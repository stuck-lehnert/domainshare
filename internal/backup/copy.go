package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// copyEntry copies a live staging tree. Disappearance of a source is tolerated;
// permission/read errors and all destination errors are fatal.
func copyEntry(ctx context.Context, source, target string, exclude func(string) bool, rel string, log *runLogger) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	vanished := func(err error) bool {
		if errors.Is(err, fs.ErrNotExist) {
			log.print("Skipping vanished backup source %s", source)
			return true
		}
		return false
	}
	info, err := os.Lstat(source)
	if vanished(err) {
		return nil
	}
	if err != nil {
		return err
	}

	// Symlinks are preserved as links. Do not chmod or timestamp them: those
	// operations could mutate an external target.
	if info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(source)
		if vanished(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return os.Symlink(link, target)
	}

	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported backup file type: %s", source)
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if info.IsDir() {
		flags |= syscall.O_DIRECTORY
	}
	input, err := os.OpenFile(source, flags, 0)
	if vanished(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer input.Close()

	openedInfo, err := input.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(openedInfo, info) {
		return fmt.Errorf("backup source was replaced during staging: %s", source)
	}

	if info.IsDir() {
		entries, err := input.ReadDir(-1)
		if vanished(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := os.Mkdir(target, 0700); err != nil {
			return err
		}
		for _, entry := range entries {
			child := entry.Name()
			childRel := filepath.Join(rel, child)
			if exclude != nil && exclude(childRel) {
				continue
			}
			// Resolve children from the open parent, not from a path that may
			// have been replaced with a symlink while the tree was being read.
			childSource := fmt.Sprintf("/proc/self/fd/%d/%s", input.Fd(), child)
			if err := copyEntry(ctx, childSource, filepath.Join(target, child), exclude, childRel, log); err != nil {
				return err
			}
		}
		return applyDirectoryMetadata(target, info)
	}

	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	var metadataErr error
	if copyErr == nil {
		metadataErr = applyFileMetadata(output, info)
	}
	return errors.Join(copyErr, metadataErr, output.Close())
}

func applyDirectoryMetadata(path string, info fs.FileInfo) error {
	dir, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	return applyFileMetadata(dir, info)
}

func applyFileMetadata(file *os.File, info fs.FileInfo) error {
	mode := info.Mode().Perm() | info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
	if err := file.Chmod(mode); err != nil {
		return err
	}
	modified := syscall.NsecToTimeval(info.ModTime().UnixNano())
	return syscall.Futimes(int(file.Fd()), []syscall.Timeval{modified, modified})
}
