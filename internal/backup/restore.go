package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Restore extracts a trusted DomainShare backup into a new directory that it
// creates with mode 0700. Use ArchiveKey to turn a recovery phrase into a
// password; legacy archives take the original password. A failed extraction
// can leave partial files in the new directory for inspection.
func Restore(ctx context.Context, archive, output, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	archive, err := filepath.Abs(archive)
	if err != nil {
		return err
	}
	info, err := os.Stat(archive)
	if err != nil {
		return fmt.Errorf("open backup archive: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("backup archive is not a regular file")
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(output); err == nil {
		return errors.New("the recovery output must be a new directory")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return fmt.Errorf("create recovery directory: %w", err)
	}

	// Keep the password off argv, environment, error messages and logs. Use a
	// real newline for the password prompt, including for legacy 7z builds.
	cmd := exec.CommandContext(ctx, "7z", "x", "-aos", "-o"+output, "--", archive)
	cmd.Stdin = strings.NewReader(password + "\n")
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	result := runCaptured(cmd)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if result.err != nil {
		return errors.New("recovery failed; check the password, archive and available disk space")
	}
	return nil
}
