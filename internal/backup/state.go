package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"modernc.org/sqlite"
)

const pendingDirectory = "backup-pending"

func within(root, path string) (string, bool) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, absolute)
	return rel, err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func stageState(ctx context.Context, path string, options Options, log *runLogger) (string, string, error) {
	root, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}

	database := options.StateDBPath
	if database == "" {
		database = filepath.Join(root, "shares.db")
	}
	databaseRel, ok := within(root, database)
	if !ok || databaseRel == "." {
		return "", "", errors.New("STATE_DB_PATH must be located below STATE_ROOT")
	}

	document := options.DocumentDir
	if document == "" {
		document = filepath.Join(root, "documents")
	}
	excluded := map[string]bool{pendingDirectory: true}
	if documentRel, underRoot := within(root, document); underRoot && documentRel != "." {
		excluded[documentRel] = true
	}
	for _, db := range []string{databaseRel, "configuration.db", "agent-tokens.db"} {
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			excluded[db+suffix] = true
		}
	}

	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", err
	}
	temp, err := os.MkdirTemp("", "backup-state-")
	if err != nil {
		return "", "", err
	}

	staged := filepath.Join(temp, "state")
	err = copyEntry(ctx, resolved, staged, func(name string) bool { return excluded[name] }, "", log)
	if err == nil {
		err = snapshotDB(ctx, filepath.Join(resolved, databaseRel), staged, databaseRel)
	}
	if err == nil && databaseRel != "configuration.db" {
		err = snapshotDB(ctx, filepath.Join(resolved, "configuration.db"), staged, "configuration.db")
	}
	if err != nil {
		_ = os.RemoveAll(temp)
		return "", "", err
	}
	return temp, staged, nil
}

func sqliteURI(path, query string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query}).String()
}

func snapshotDB(ctx context.Context, source, stagedRoot, relative string) error {
	info, err := os.Stat(source)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("state database is not a regular file: %s", source)
	}

	// The private staging tree contains original symlinks. Refuse to write a
	// snapshot through any of them, especially one pointing back to live state.
	stagedParent := stagedRoot
	for _, component := range strings.Split(filepath.Dir(relative), string(filepath.Separator)) {
		if component == "." {
			continue
		}
		stagedParent = filepath.Join(stagedParent, component)
		if err := os.Mkdir(stagedParent, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if info, err := os.Lstat(stagedParent); err != nil || !info.IsDir() {
			return fmt.Errorf("unsafe staged database parent: %s", stagedParent)
		}
	}

	destination := filepath.Join(stagedParent, filepath.Base(relative))
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	live, err := sql.Open("sqlite", sqliteURI(source, "mode=ro&_pragma=busy_timeout%2830000%29"))
	if err != nil {
		return err
	}
	defer live.Close()

	if err := snapshotPages(ctx, live, destination); err != nil {
		return fmt.Errorf("snapshot SQLite database %s: %w", filepath.Base(source), err)
	}

	// The snapshot is a closed, standalone database; immutable avoids creating
	// WAL/SHM files during the check if its journal mode is WAL.
	snapshot, err := sql.Open("sqlite", sqliteURI(destination, "mode=ro&immutable=1"))
	if err != nil {
		return err
	}
	defer snapshot.Close()

	var check string
	if err := snapshot.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("SQLite %s snapshot failed its integrity check", filepath.Base(source))
	}
	return nil
}

func snapshotPages(ctx context.Context, db *sql.DB, destination string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Raw(func(driverConn any) (err error) {
		online, ok := driverConn.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return errors.New("SQLite driver does not support online snapshots")
		}
		backup, err := online.NewBackup(sqliteURI(destination, ""))
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, backup.Finish()) }()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			more, err := backup.Step(256)
			if err != nil || !more {
				return err
			}
		}
	})
}
