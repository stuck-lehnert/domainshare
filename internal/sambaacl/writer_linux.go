package sambaacl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Writer calls the installed Bookworm helper with already-open files. Its
// caller owns both descriptors, must keep them open through each call, and
// must open the database in a trusted state directory without symlink following.
// The helper path is a trusted absolute installation path, not request input.
type Writer struct {
	HelperPath string
	Database   *os.File
}

type preparedWrite struct {
	blob []byte
	kind string
	mode os.FileMode
}

func (w Writer) prepare(ctx context.Context, target *os.File, d Descriptor) (preparedWrite, error) {
	if err := ctx.Err(); err != nil {
		return preparedWrite{}, err
	}
	if target == nil || w.Database == nil {
		return preparedWrite{}, errors.New("Samba ACL writer requires pinned target and database descriptors")
	}

	blob, err := d.Pack()
	if err != nil {
		return preparedWrite{}, err
	}
	file, err := target.Stat()
	if err != nil {
		return preparedWrite{}, fmt.Errorf("inspect managed data descriptor: %w", err)
	}
	if (d.directory && !file.IsDir()) || (!d.directory && !file.Mode().IsRegular()) {
		return preparedWrite{}, errors.New("unsupported managed data entry or descriptor type mismatch")
	}

	db, err := w.Database.Stat()
	if err != nil {
		return preparedWrite{}, fmt.Errorf("inspect Samba xattr database descriptor: %w", err)
	}
	stat, ok := db.Sys().(*syscall.Stat_t)
	if !ok || !db.Mode().IsRegular() || stat.Nlink != 1 || int(stat.Uid) != os.Geteuid() || os.SameFile(file, db) {
		return preparedWrite{}, errors.New("invalid Samba xattr database descriptor")
	}

	if !filepath.IsAbs(w.HelperPath) {
		return preparedWrite{}, errors.New("Samba ACL helper requires an absolute installation path")
	}
	helper, err := os.Stat(w.HelperPath)
	if err != nil {
		return preparedWrite{}, fmt.Errorf("inspect Samba ACL helper: %w", err)
	}
	if !helper.Mode().IsRegular() || helper.Mode().Perm()&0o111 == 0 {
		return preparedWrite{}, errors.New("Samba ACL helper must be an executable regular file")
	}

	if d.directory {
		return preparedWrite{blob: blob, kind: "directory", mode: 0o777}, nil
	}
	return preparedWrite{blob: blob, kind: "file", mode: 0o666}, nil
}

// SetACLFD sets root ownership, then the Windows ACL, then the legacy local mode
// on the supplied pinned inode. These steps are not transactional. Never publish
// a file or save its ACL success signature when any step returns an error.
func (w Writer) SetACLFD(ctx context.Context, target *os.File, d Descriptor) error {
	write, err := w.prepare(ctx, target, d)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := target.Chown(0, 0); err != nil {
		return fmt.Errorf("set root ownership on managed data descriptor: %w", err)
	}
	if err := w.store(target, write); err != nil {
		return err
	}
	if err := target.Chmod(write.mode); err != nil {
		return fmt.Errorf("set managed data mode after writing Samba ACL: %w", err)
	}
	return nil
}

func (w Writer) store(target *os.File, write preparedWrite) error {
	// Once starting the helper, wait for its actual result. A request cancel
	// must not kill the process while Samba is updating a locked TDB record.
	cmd := exec.Command(w.HelperPath, write.kind)
	cmd.ExtraFiles = []*os.File{target, w.Database} // inherited fds 3 and 4
	cmd.Stdin = bytes.NewReader(write.blob)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if message := strings.TrimSpace(string(output)); message != "" {
			return fmt.Errorf("Samba ACL helper: %w: %s", err, message)
		}
		return fmt.Errorf("Samba ACL helper: %w", err)
	}
	return nil
}
