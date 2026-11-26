package accesscontrol

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func basename(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}

func validFolderName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if !basename(name) || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 120 ||
		strings.EqualFold(name, ".trash") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return "", false
	}
	for _, r := range name {
		if r < 32 || r == 127 || strings.ContainsRune(`\/:*?"<>|`, r) {
			return "", false
		}
	}
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.ToUpper(stem)
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
		(len(stem) == 4 && stem[3] >= '1' && stem[3] <= '9' && (stem[:3] == "COM" || stem[:3] == "LPT")) {
		return "", false
	}
	return name, true
}

// openDirPath pins each component before opening its child. No pathname
// component, including the configured root's parents, may be a symlink.
func openDirPath(path string, create bool) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("directory path must be absolute")
	}
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, err
	}
	if path = filepath.Clean(path); path != "/" {
		for _, name := range strings.Split(path[1:], "/") {
			next, err := unix.Openat(fd, name, directoryFlags, 0)
			if create && errors.Is(err, unix.ENOENT) {
				if err = unix.Mkdirat(fd, name, 0o755); err == nil || errors.Is(err, unix.EEXIST) {
					next, err = unix.Openat(fd, name, directoryFlags, 0)
				}
			}
			_ = unix.Close(fd)
			if err != nil {
				return nil, &os.PathError{Op: "open managed directory", Path: path, Err: err}
			}
			fd = next
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openEntry(parent *os.File, name string, directory, create bool) (*os.File, error) {
	if !basename(name) {
		return nil, fmt.Errorf("unsafe managed folder entry %q", name)
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		flags |= unix.O_DIRECTORY
	}
	openFlags := flags
	if !directory {
		// Pin before opening for IO: ACL walks must not open devices or FIFOs.
		openFlags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd := int(parent.Fd())
	how := &unix.OpenHow{Flags: uint64(openFlags), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV}
	child, err := unix.Openat2(fd, name, how)
	if create && errors.Is(err, unix.ENOENT) {
		if err = unix.Mkdirat(fd, name, 0o755); err == nil || errors.Is(err, unix.EEXIST) {
			child, err = unix.Openat2(fd, name, how)
		}
	}
	path := filepath.Join(parent.Name(), name)
	if err != nil {
		return nil, &os.PathError{Op: "open pinned managed entry", Path: path, Err: err}
	}
	if !directory {
		defer unix.Close(child)
		var st unix.Stat_t
		if err := unix.Fstat(child, &st); err != nil {
			return nil, err
		}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
		case unix.S_IFDIR:
			flags |= unix.O_DIRECTORY
		default:
			return nil, fmt.Errorf("unsupported managed entry: %s", path)
		}

		// Resolve an intentional proc-fd reference to the pinned inode rather
		// than reopening the mutable pathname from the filesystem walker.
		child, err = unix.Open(fmt.Sprintf("/proc/self/fd/%d", child), flags&^unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, &os.PathError{Op: "reopen pinned managed entry", Path: path, Err: err}
		}
	}

	return os.NewFile(uintptr(child), path), nil
}

func inspectEntry(parent *os.File, name string) (exists bool, err error) {
	if !basename(name) {
		return false, fmt.Errorf("unsafe managed folder entry %q", name)
	}
	var st unix.Stat_t
	err = unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, fmt.Errorf("managed entry is not a real directory: %s", filepath.Join(parent.Name(), name))
	}
	return true, nil
}

func moveFolder(source *os.File, from string, dest *os.File, to string) error {
	if !basename(from) || !basename(to) {
		return errors.New("unsafe folder rename components")
	}
	pinned, err := openEntry(source, from, true, false)
	if err != nil {
		return err
	}
	defer pinned.Close()

	if err := unix.Renameat2(int(source.Fd()), from, int(dest.Fd()), to, unix.RENAME_NOREPLACE); err != nil {
		return &os.LinkError{Op: "rename without overwrite", Old: filepath.Join(source.Name(), from),
			New: filepath.Join(dest.Name(), to), Err: err}
	}
	return nil
}
