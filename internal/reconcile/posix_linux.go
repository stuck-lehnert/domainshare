package reconcile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	userObject  = 0x01
	namedUser   = 0x02
	groupObject = 0x04
	namedGroup  = 0x08
	mask        = 0x10
	other       = 0x20
)

type aclEntry struct {
	tag, rights uint16
	id          int
}

func encodeACL(entries []aclEntry) []byte {
	data := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(data, 2)
	for i, entry := range entries {
		at := data[4+i*8:]
		binary.LittleEndian.PutUint16(at, entry.tag)
		binary.LittleEndian.PutUint16(at[2:], entry.rights)
		binary.LittleEndian.PutUint32(at[4:], uint32(entry.id))
	}
	return data
}

func removeACL(fd int, attr string) error {
	err := unix.Fremovexattr(fd, attr)
	if errors.Is(err, unix.ENODATA) {
		return nil
	}
	return err
}

func privateACL(fd, uid, gid, admin int, directory bool) error {
	rights, mode := uint16(6), uint32(0o600)
	if directory {
		rights, mode = 7, 0o700
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}

	entries := []aclEntry{{userObject, rights, -1}, {namedUser, rights, uid}, {groupObject, 0, -1}}
	if admin > 0 {
		entries = append(entries, aclEntry{namedGroup, rights, admin})
	}
	entries = append(entries, aclEntry{mask, rights, -1}, aclEntry{other, 0, -1})
	acl := encodeACL(entries)
	if directory {
		if err := unix.Fsetxattr(fd, "system.posix_acl_default", acl, 0); err != nil {
			return err
		}
	}
	return unix.Fsetxattr(fd, "system.posix_acl_access", acl, 0)
}

func fslogixACL(fd, group, admin int) error {
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	if err := unix.Fchown(fd, 0, group); err != nil {
		return err
	}

	groups := []aclEntry{{namedGroup, 7, group}}
	if admin > 0 && admin != group {
		if admin < group {
			groups = append([]aclEntry{{namedGroup, 7, admin}}, groups...)
		} else {
			groups = append(groups, aclEntry{namedGroup, 7, admin})
		}
	}
	entries := append([]aclEntry{{userObject, 7, -1}, {groupObject, 7, -1}}, groups...)
	entries = append(entries, aclEntry{mask, 7, -1}, aclEntry{other, 0, -1})
	acl := encodeACL(entries)

	if err := unix.Fsetxattr(fd, "system.posix_acl_default", acl, 0); err != nil {
		return err
	}
	if err := unix.Fsetxattr(fd, "system.posix_acl_access", acl, 0); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0o3770)
}

func privateShareRoot(fd int) error {
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, 0o555); err != nil {
		return err
	}
	if err := removeACL(fd, "system.posix_acl_default"); err != nil {
		return err
	}
	return removeACL(fd, "system.posix_acl_access")
}

func openShareRoot(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" || filepath.Clean(path) != path {
		return nil, errors.New("share root must be an absolute, non-root, clean path")
	}
	how := unix.OpenHow{
		Flags:   unix.O_DIRECTORY | unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &how)
	if errors.Is(err, unix.ENOENT) {
		parent, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &how)
		if err != nil {
			return nil, err
		}
		defer unix.Close(parent)

		name := filepath.Base(path)
		if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
		fd, err := unix.Openat2(parent, name, &how)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openChild checks inode type before opening it for permission mutations. A
// symlink, mount, device, socket or hard-linked regular file is never touched.
func openChild(parent *os.File, name string, requireDirectory bool) (*os.File, bool, error) {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return nil, false, errors.New("invalid entry name")
	}
	pinned, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, false, err
	}
	defer unix.Close(pinned)

	var info unix.Stat_t
	if err := unix.Fstat(pinned, &info); err != nil {
		return nil, false, err
	}
	typ := info.Mode & unix.S_IFMT
	if typ != unix.S_IFDIR && (requireDirectory || typ != unix.S_IFREG || info.Nlink != 1) {
		return nil, false, errors.ErrUnsupported
	}

	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if typ == unix.S_IFDIR {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pinned), flags, 0)
	if err != nil {
		return nil, false, fmt.Errorf("open pinned entry: %w", err)
	}
	return os.NewFile(uintptr(fd), name), typ == unix.S_IFDIR, nil
}
