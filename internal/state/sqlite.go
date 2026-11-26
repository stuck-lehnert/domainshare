// Package state opens DomainShare's existing on-disk SQLite databases.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"syscall"

	_ "modernc.org/sqlite" // Provides FTS5 without a dependency on the host SQLite build.
)

// OpenPrivate opens a secret-bearing database in a trusted directory.
// SQLite opens its own handles, including WAL sidecars, so the directory
// must prevent another user from replacing those paths after validation.
func OpenPrivate(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" {
		return nil, errors.New("database path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(filepath.Dir(absolute), false); err != nil {
		return nil, err
	}

	// Do not open the inode of an existing database separately. Closing an
	// unrelated descriptor can release SQLite's POSIX record locks in this process.
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if createErr == nil {
			if err := file.Close(); err != nil {
				return nil, err
			}
		} else if !errors.Is(createErr, os.ErrExist) {
			return nil, createErr
		}
		info, err = os.Lstat(absolute)
	}
	if err != nil {
		return nil, err
	}
	if !privateDatabaseFile(info) {
		return nil, errors.New("private database must be an unshared regular file owned by the service")
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		return nil, err
	}

	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		sidecar := absolute + suffix
		info, err := os.Lstat(sidecar)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !privateDatabaseFile(info) || info.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("unsafe private database sidecar: %s", filepath.Base(sidecar))
		}

		// The Python state store could create read-only-for-others sidecars.
		// Keep their contents (especially uncheckpointed WAL transactions) and
		// tighten permissions under the already validated parent directory.
		if info.Mode().Perm() != 0o600 {
			if err := os.Chmod(sidecar, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("restrict private database sidecar %s: %w", filepath.Base(sidecar), err)
			}
		}
	}
	return Open(ctx, absolute, false)
}

func privateDatabaseFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1
}

func ensurePrivateDirectory(path string, ancestor bool) error {
	parent := filepath.Dir(path)
	if parent != path {
		if err := ensurePrivateDirectory(parent, true); err != nil {
			return err
		}
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	trustedOwner := ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
	stickyAncestor := ancestor && info.Mode()&os.ModeSticky != 0
	if !info.IsDir() || !trustedOwner || (info.Mode().Perm()&0o022 != 0 && !stickyAncestor) {
		return fmt.Errorf("unsafe directory for private database: %s", path)
	}
	return nil
}

// Open applies the same WAL and foreign-key conventions as the existing services.
func Open(ctx context.Context, path string, readOnly bool) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	options := url.Values{"_pragma": {"busy_timeout(30000)", "foreign_keys(1)"}}
	if readOnly {
		options.Set("mode", "ro")
	} else {
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return nil, err
		}
		options.Add("_pragma", "synchronous(NORMAL)")
	}

	uri := url.URL{Scheme: "file", Path: abs, RawQuery: options.Encode()}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	if !readOnly {
		var journal string
		err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal)
		if err != nil || journal != "wal" {
			db.Close()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("SQLite did not enable WAL: %q", journal)
		}
	}
	return db, nil
}
