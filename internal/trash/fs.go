package trash

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	Directory   = ".trash"
	stagePrefix = ".domainshare-restore-"
	dirFlags    = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
)

func fd(file *os.File) int { return int(file.Fd()) }

func openRoot(path string) (*os.File, error) {
	value, err := unix.Open(path, dirFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(value), path), nil
}

func openDir(parent *os.File, name string) (*os.File, error) {
	f, err := unix.Openat(fd(parent), name, dirFlags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: name, Err: err}
	}
	return os.NewFile(uintptr(f), name), nil
}

func openRepository(path string) (*os.File, error) {
	root, err := openRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return openDir(root, Directory)
}

func ensureRepository(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	root, err := openRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := unix.Mkdirat(fd(root), Directory, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return &os.PathError{Op: "mkdir", Path: Directory, Err: err}
	}
	bin, err := openDir(root, Directory)
	if err != nil {
		return err
	}
	defer bin.Close()
	if err := unix.Fchown(fd(bin), 0, 0); err != nil && !(os.Geteuid() != 0 && errors.Is(err, unix.EPERM)) {
		return &os.PathError{Op: "chown", Path: Directory, Err: err}
	}
	return unix.Fchmod(fd(bin), 01733)
}

func statEntry(parent *os.File, name string) (unix.Stat_t, error) {
	var info unix.Stat_t
	err := unix.Fstatat(fd(parent), name, &info, unix.AT_SYMLINK_NOFOLLOW)
	return info, err
}

func statFile(f *os.File) (unix.Stat_t, error) {
	var info unix.Stat_t
	err := unix.Fstat(fd(f), &info)
	return info, err
}

func fileType(info unix.Stat_t) uint32 { return info.Mode & unix.S_IFMT }

func modTime(info unix.Stat_t) time.Time { return time.Unix(info.Mtim.Sec, info.Mtim.Nsec) }

func sameInode(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func sameEntry(parent *os.File, name string, wanted unix.Stat_t) bool {
	current, err := statEntry(parent, name)
	return err == nil && sameInode(current, wanted)
}

func reservedStage(name string) bool { return strings.HasPrefix(name, stagePrefix) }

// walkRepository never follows directory symlinks; visitor operations are
// relative to the already opened directory. Like os.walk, vanished or unreadable
// entries are skipped. Descending to a changed inode is also skipped.
func walkRepository(ctx context.Context, directory *os.File, relative string, visit func(*os.File, string, string, unix.Stat_t), postOrder bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := directory.Readdirnames(256)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			if relative == "" && reservedStage(name) {
				continue
			}
			info, err := statEntry(directory, name)
			if err != nil {
				continue
			}
			item := name
			if relative != "" {
				item = relative + "/" + name
			}
			if fileType(info) == unix.S_IFDIR {
				child, err := openDir(directory, name)
				if err != nil {
					continue
				}
				opened, err := statFile(child)
				if err != nil || !sameInode(info, opened) {
					_ = child.Close()
					continue
				}
				err = walkRepository(ctx, child, item, visit, postOrder)
				_ = child.Close()
				if err != nil {
					return err
				}
				if postOrder {
					visit(directory, name, item, info)
				}
				continue
			}
			visit(directory, name, item, info)
		}
		if err != nil || len(names) == 0 {
			return nil
		}
	}
}
