// Package documents provides permission-checked access to the document catalog
// and live share tree.
package documents

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

func excludedName(name string) bool {
	return strings.EqualFold(name, "thumbs.db") || strings.HasPrefix(name, "~$")
}

func pathParts(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || part == ".trash" || excludedName(part) ||
			!utf8.ValidString(part) || strings.ContainsRune(part, 0) {
			return nil, os.ErrNotExist
		}
	}
	return parts, nil
}

const directoryFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NOFOLLOW

type stat struct {
	unix.Stat_t
	mountID uint64
}

func fdStat(fd int) (stat, error) {
	var item stat
	if err := unix.Fstat(fd, &item.Stat_t); err != nil {
		return item, err
	}
	var extended unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_DONT_SYNC, unix.STATX_MNT_ID, &extended); err == nil &&
		extended.Mask&unix.STATX_MNT_ID != 0 {
		item.mountID = extended.Mnt_id
	}
	return item, nil
}

func sameMount(item, root stat) bool {
	return item.Dev == root.Dev && (item.mountID == 0 || root.mountID == 0 || item.mountID == root.mountID)
}

func owned(mode uint32, uid uint32, owner *int, mask uint32) bool {
	return owner == nil || (*owner >= 0 && uint64(*owner) == uint64(uid) && mode&mask == mask)
}

func openDirectory(root string, parts []string, owner *int) (*os.File, stat, error) {
	fd, err := unix.Open(root, directoryFlags, 0)
	if err != nil {
		return nil, stat{}, classifyPathError(err)
	}
	rootStat, err := fdStat(fd)
	if err != nil || !owned(rootStat.Mode, rootStat.Uid, owner, 0o500) {
		unix.Close(fd)
		return nil, stat{}, os.ErrNotExist
	}

	for _, part := range parts {
		child, err := unix.Openat(fd, part, directoryFlags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, stat{}, classifyPathError(err)
		}
		item, err := fdStat(child)
		if err != nil || !sameMount(item, rootStat) || !owned(item.Mode, item.Uid, owner, 0o500) {
			unix.Close(child)
			return nil, stat{}, os.ErrNotExist
		}
		fd = child
	}
	return os.NewFile(uintptr(fd), "document-directory"), rootStat, nil
}

// openFile pins the directory chain and final inode before using its size or
// serving data. No symbolic links, special files or nested mounts are allowed.
func openFile(root, relative string, owner *int) (*os.File, stat, error) {
	parts, err := pathParts(relative)
	if err != nil || len(parts) == 0 {
		return nil, stat{}, os.ErrNotExist
	}
	directory, rootStat, err := openDirectory(root, parts[:len(parts)-1], owner)
	if err != nil {
		return nil, stat{}, err
	}
	defer directory.Close()

	fd, err := unix.Openat(int(directory.Fd()), parts[len(parts)-1],
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, stat{}, classifyPathError(err)
	}
	info, err := fdStat(fd)
	if err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || !sameMount(info, rootStat) || !owned(info.Mode, info.Uid, owner, 0o400) {
		unix.Close(fd)
		return nil, stat{}, os.ErrNotExist
	}
	return os.NewFile(uintptr(fd), parts[len(parts)-1]), info, nil
}

func classifyPathError(err error) error {
	for _, denied := range []error{unix.ELOOP, unix.ENOTDIR, unix.ENOENT, unix.EACCES, unix.EPERM, unix.ENAMETOOLONG, unix.ENXIO} {
		if errors.Is(err, denied) {
			return os.ErrNotExist
		}
	}
	return err
}

func fingerprint(info stat) string {
	return fmt.Sprintf("%d:%d:%d:%d:%d", info.Dev, info.Ino, info.Size, info.Mtim.Nano(), info.Ctim.Nano())
}
