package documents

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/directory"
)

func (index indexer) inventory(ctx context.Context) (map[string]indexSource, error) {
	tx, err := index.Policy.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	sources := make(map[string]indexSource)
	shares, err := tx.QueryContext(ctx, `SELECT objectGUID,shareName,path FROM shares WHERE isActive=1`)
	if err != nil {
		return nil, err
	}
	defer shares.Close()
	for shares.Next() {
		var id, label, path string
		if err := shares.Scan(&id, &label, &path); err != nil {
			return nil, err
		}
		root, safe := directChild(index.DataRoot, path)
		if !safe {
			continue
		}
		dir, _, err := openDirectory(root, nil, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		dir.Close()
		id = "data:" + id
		sources[id] = indexSource{id: id, kind: "data", label: label, root: root}
	}
	if err := shares.Err(); err != nil {
		return nil, err
	}

	users, err := tx.QueryContext(ctx, `SELECT sam,sid FROM access_users`)
	if err != nil {
		return nil, err
	}
	defer users.Close()
	identities := make(map[string]string)
	for users.Next() {
		var sam, sid string
		if err := users.Scan(&sam, &sid); err != nil {
			return nil, err
		}
		if !directory.IsExcludedUser(sam) {
			key := foldCase.String(sam)
			if current, exists := identities[key]; exists && current != sid {
				identities[key] = ""
			} else {
				identities[key] = sid
			}
		}
	}
	if err := users.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	root, err := filepath.Abs(index.PrivateRoot)
	if err != nil {
		return nil, err
	}
	private, rootStat, err := openDirectory(root, nil, nil)
	if errors.Is(err, os.ErrNotExist) {
		return sources, nil
	}
	if err != nil {
		return nil, err
	}
	defer private.Close()
	entries, err := private.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	conflicts := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		key := foldCase.String(name)
		sid := identities[key]
		if sid == "" || !entry.IsDir() || conflicts[key] {
			continue
		}
		if _, err := pathParts(name); err != nil {
			continue
		}
		dir, _, err := openDirectory(root, []string{name}, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		info, err := fdStat(int(dir.Fd()))
		dir.Close()
		if err != nil || !sameMount(info, rootStat) {
			continue
		}
		id := "private:" + key
		if _, exists := sources[id]; exists {
			delete(sources, id)
			conflicts[key] = true
			continue
		}
		sources[id] = indexSource{id: id, kind: "private", label: "Private", root: filepath.Join(root, name), sid: sid}
	}
	return sources, nil
}

func (index indexer) refreshSources(ctx context.Context) (map[string]indexSource, []string, error) {
	current, err := index.inventory(ctx)
	if err != nil {
		return nil, nil, err
	}
	var changes []string
	err = immediate(ctx, index.db, func(conn *sql.Conn) error {
		paused, err := workerPaused(ctx, conn)
		if err != nil {
			return err
		}
		if paused {
			return errIndexPaused
		}
		rows, err := conn.QueryContext(ctx, `SELECT id,kind,label,root,owner_sid FROM document_sources`)
		if err != nil {
			return err
		}
		defer rows.Close()
		old := make(map[string]indexSource)
		for rows.Next() {
			var source indexSource
			if err := rows.Scan(&source.id, &source.kind, &source.label, &source.root, &source.sid); err != nil {
				return err
			}
			old[source.id] = source
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for id := range old {
			if _, exists := current[id]; !exists {
				if _, err := conn.ExecContext(ctx, `DELETE FROM document_sources WHERE id=?`, id); err != nil {
					return err
				}
			}
		}
		for id, source := range current {
			previous, exists := old[id]
			if previous == source {
				continue
			}
			if exists && (previous.root != source.root || previous.sid != source.sid || previous.kind != source.kind) {
				if _, err := conn.ExecContext(ctx, `DELETE FROM documents WHERE source_id=?`, id); err != nil {
					return err
				}
			}
			if _, err := conn.ExecContext(ctx, `INSERT INTO document_sources(id,kind,label,root,owner_sid) VALUES(?,?,?,?,?)
				ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,label=excluded.label,root=excluded.root,owner_sid=excluded.owner_sid`,
				id, source.kind, source.label, source.root, source.sid); err != nil {
				return err
			}
			changes = append(changes, id)
		}
		return nil
	})
	return current, changes, err
}

type indexStatements interface {
	rowQueryer
	sqlExecer
}

func discoverFile(ctx context.Context, db indexStatements, source indexSource, relative string, seen int64) error {
	file, info, err := openFile(source.root, relative, nil)
	if errors.Is(err, os.ErrNotExist) {
		_, err := db.ExecContext(ctx, `DELETE FROM documents WHERE source_id=? AND path=?`, source.id, relative)
		return err
	}
	if err != nil {
		return err
	}
	file.Close()

	stamp := fingerprint(info)
	var existing string
	err = db.QueryRowContext(ctx, `SELECT fingerprint FROM documents WHERE source_id=? AND path=?`, source.id, relative).Scan(&existing)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if existing == stamp {
		if seen != 0 {
			_, err = db.ExecContext(ctx, `UPDATE documents SET seen=? WHERE source_id=? AND path=? AND fingerprint=?`,
				seen, source.id, relative, stamp)
		}
		return err
	}

	name := filepath.Base(relative)
	extension := filepath.Ext(name)
	// Python splitext treats names like .pdf and ....jpg as extensionless.
	if stem := strings.TrimSuffix(name, extension); strings.Trim(stem, ".") == "" {
		extension = ""
	}
	extension = strings.ToLower(extension)
	state := "name-only"
	if contentType(extension) || imageType(extension) {
		state = "pending"
	}
	var rawID [16]byte
	rand.Read(rawID[:])
	rawID[6] = rawID[6]&0x0f | 0x40
	rawID[8] = rawID[8]&0x3f | 0x80
	_, err = db.ExecContext(ctx, `INSERT INTO documents(id,source_id,path,name,extension,size,modified,fingerprint,seen,state)
		VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id,path) DO UPDATE SET name=excluded.name,extension=excluded.extension,
		size=excluded.size,modified=excluded.modified,fingerprint=excluded.fingerprint,seen=excluded.seen,
		body='',state=excluded.state,preview='',pages=0,attempts=0,retry_at=0,indexed_at=0`,
		hex.EncodeToString(rawID[:]), source.id, relative, name, extension, info.Size,
		float64(info.Mtim.Sec)+float64(info.Mtim.Nsec)/1e9, stamp, seen, state)
	return err
}

func (index indexer) scanSource(ctx context.Context, source indexSource, watcher *indexWatcher, check func() error) error {
	seen := time.Now().UnixNano()
	var scan func([]string) error
	scan = func(parts []string) error {
		if err := check(); err != nil {
			return err
		}
		if len(parts) > 256 {
			return errors.New("document directory nesting exceeds limit")
		}
		dir, rootStat, err := openDirectory(source.root, parts, nil)
		if err != nil {
			return err
		}
		defer dir.Close()

		prefix := strings.Join(parts, "/")
		if watcher != nil {
			watcher.add(dir, watchPath{source: source.id, relative: prefix})
		}
		for {
			entries, err := dir.ReadDir(100)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if len(entries) == 0 && errors.Is(err, io.EOF) {
				return nil
			}
			if err := check(); err != nil {
				return err
			}

			var subdirs []string
			if transactionErr := immediate(ctx, index.db, func(conn *sql.Conn) error {
				for _, entry := range entries {
					name := entry.Name()
					if _, err := pathParts(name); err != nil || entry.Type()&os.ModeSymlink != 0 {
						continue
					}
					if entry.IsDir() {
						subdirs = append(subdirs, name)
						continue
					}
					if entry.Type().IsRegular() {
						if err := discoverFile(ctx, conn, source, appendPath(prefix, name), seen); err != nil {
							return err
						}
					}
				}
				return nil
			}); transactionErr != nil {
				return transactionErr
			}
			for _, name := range subdirs {
				// An invalid/symlink/mounted child is outside this catalog. An
				// I/O failure in a legitimate subtree instead aborts pruning.
				child, err := openDirectoryChild(dir, name, rootStat)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				child.Close()
				if err := scan(append(parts, name)); err != nil {
					return err
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
		}
	}
	if err := scan(nil); err != nil {
		return err
	}

	return immediate(ctx, index.db, func(conn *sql.Conn) error {
		paused, err := workerPaused(ctx, conn)
		if err != nil {
			return err
		}
		if paused {
			return errIndexPaused
		}
		_, err = conn.ExecContext(ctx, `DELETE FROM documents WHERE source_id=? AND seen<>?`, source.id, seen)
		return err
	})
}

func appendPath(relative, name string) string {
	if relative == "" {
		return name
	}
	return relative + "/" + name
}
