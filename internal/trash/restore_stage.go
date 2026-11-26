package trash

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// The private stage prevents concurrent Samba users from substituting the
// source between validation and publication. The cleanup timer skips this
// namespace so an interrupted restore cannot silently discard the file.
type restoreStage struct {
	repository *os.File
	file       *os.File
	name       string
}

func newRestoreStage(repository *os.File) (*restoreStage, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	name := stagePrefix + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(fd(repository), name, 0700); err != nil {
		return nil, err
	}
	file, err := openDir(repository, name)
	if err != nil {
		return nil, err
	}
	return &restoreStage{repository: repository, file: file, name: name}, nil
}

func (stage *restoreStage) close() {
	defer stage.file.Close()
	if _, err := statEntry(stage.file, "item"); errors.Is(err, unix.ENOENT) {
		_ = unix.Unlinkat(fd(stage.file), "origin.json", 0)
	}
	if info, err := statFile(stage.file); err == nil && sameEntry(stage.repository, stage.name, info) {
		// ENOTEMPTY means recovery is needed; preserve rather than deleting it.
		_ = unix.Unlinkat(fd(stage.repository), stage.name, unix.AT_REMOVEDIR)
	}
}

func (stage *restoreStage) rememberOrigin(entry *openEntry) error {
	value, err := unix.Openat(fd(stage.file), "origin.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(value), "origin.json")
	metadata := struct {
		Share string `json:"share"`
		Path  string `json:"trashRelativePath"`
	}{Share: entry.share, Path: entry.relative}
	encodeErr := json.NewEncoder(file).Encode(metadata)
	return errors.Join(encodeErr, file.Sync(), file.Close())
}

func (stage *restoreStage) makeParent(destination *os.File, name string, entry *openEntry) (*os.File, error) {
	const pendingParent = "parent"
	if err := unix.Mkdirat(fd(stage.file), pendingParent, 0700); err != nil {
		return nil, err
	}
	defer unix.Unlinkat(fd(stage.file), pendingParent, unix.AT_REMOVEDIR)

	pinned, err := openDir(stage.file, pendingParent)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = pinned.Close()
		}
	}()

	if entry.share != "Data" {
		if err := unix.Fchown(fd(pinned), int(entry.info.Uid), int(entry.info.Gid)); err != nil {
			return nil, err
		}
	}
	if err := unix.Fchmod(fd(pinned), 0700); err != nil {
		return nil, err
	}
	if err := unix.Renameat2(fd(stage.file), pendingParent, fd(destination), name, unix.RENAME_NOREPLACE); err != nil {
		return nil, err
	}
	keep = true
	return pinned, nil
}

func (stage *restoreStage) capture(entry *openEntry) error {
	if !sameEntry(entry.parent(), entry.leaf(), entry.info) {
		return ErrChanged
	}
	if err := stage.rememberOrigin(entry); err != nil {
		return err
	}
	if err := unix.Renameat2(fd(entry.parent()), entry.leaf(), fd(stage.file), "item", unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if !sameEntry(stage.file, "item", entry.info) {
		return stage.putBack(entry, ErrChanged)
	}
	return nil
}

func (stage *restoreStage) putBack(entry *openEntry, reason error) error {
	if err := unix.Renameat2(fd(stage.file), "item", fd(entry.parent()), entry.leaf(), unix.RENAME_NOREPLACE); err != nil {
		return errors.Join(reason, fmt.Errorf("could not return staged item to trash; kept in %s: %w", stage.name, err))
	}
	return reason
}
