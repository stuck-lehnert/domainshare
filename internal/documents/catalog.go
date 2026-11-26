package documents

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/state"
	"golang.org/x/text/cases"
	"modernc.org/sqlite"
)

const (
	catalogVersion  = 3
	maxText         = 2 * 1024 * 1024
	visibleName     = `lower(name) <> 'thumbs.db' AND name NOT GLOB '~$*'`
	visibleDocument = `lower(d.name) <> 'thumbs.db' AND d.name NOT GLOB '~$*'`
	contentTypes    = `'.docx','.odp','.odt','.pdf','.pptx'`
	imageTypes      = `'.bmp','.jpeg','.jpg','.png','.tif','.tiff','.webp'`
)

var foldCase = cases.Fold()

func contentType(s string) bool {
	switch s {
	case ".pdf", ".docx", ".odp", ".odt", ".pptx":
		return true
	}
	return false
}

func imageType(s string) bool {
	switch s {
	case ".bmp", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp":
		return true
	}
	return false
}

func searchKey(s, prefix string) string { return prefix + hex.EncodeToString([]byte(s)) }

func nameTerms(name string) string {
	chars := []rune(foldCase.String(name))
	terms := make(map[string]struct{})
	for n := 1; n <= 3; n++ {
		for i := 0; i+n <= len(chars); i++ {
			terms[searchKey(string(chars[i:i+n]), "g")] = struct{}{}
		}
	}

	return strings.Join(sortedKeys(terms), " ")
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func init() {
	// Register on every pooled connection, including writers to a v3 database
	// created by Python. The name-index triggers depend on this function.
	if err := sqlite.RegisterDeterministicScalarFunction("document_name_terms", 1,
		func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			name, ok := args[0].(string)
			if !ok {
				return nil, errors.New("document name is not text")
			}
			return nameTerms(name), nil
		}); err != nil {
		panic(err)
	}
}

// OpenCatalog opens the existing persistent search catalog, initializing or
// migrating it before any reader or worker can use it.
func OpenCatalog(ctx context.Context, root string) (*sql.DB, error) {
	if root == "" {
		return nil, errors.New("document state root is empty")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	dir, _, err := openDirectory(root, nil, nil)
	if err != nil {
		return nil, err
	}
	err = dir.Chmod(0o700)
	dir.Close()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(root, "search.db")
	for _, ending := range []string{"", "-wal", "-shm", "-journal"} {
		info, err := os.Lstat(path + ending)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("unsafe document catalog file: %s", path+ending)
		}
	}

	db, err := state.Open(ctx, path, false)
	if err != nil {
		return nil, err
	}
	if err := ensureCatalog(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func immediate(ctx context.Context, db *sql.DB, fn func(*sql.Conn) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	if err := fn(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func ensureCatalog(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version >= catalogVersion {
		return nil
	}

	return immediate(ctx, db, func(conn *sql.Conn) error {
		if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if version >= catalogVersion { // Another process completed migration.
			return nil
		}
		if _, err := conn.ExecContext(ctx, baseCatalogDDL); err != nil {
			return err
		}

		const dropDerived = `
DROP TRIGGER IF EXISTS document_insert;
DROP TRIGGER IF EXISTS document_update;
DROP TRIGGER IF EXISTS document_delete;
DROP TRIGGER IF EXISTS document_name_insert;
DROP TRIGGER IF EXISTS document_name_update;
DROP TRIGGER IF EXISTS document_name_delete;
DROP TRIGGER IF EXISTS document_count_insert;
DROP TRIGGER IF EXISTS document_count_update;
DROP TRIGGER IF EXISTS document_count_delete;
DROP TABLE IF EXISTS document_fts;
DROP TABLE IF EXISTS document_names_fts;
DROP TABLE IF EXISTS document_counts;
DROP VIEW IF EXISTS document_search_content;`
		if _, err := conn.ExecContext(ctx, dropDerived); err != nil {
			return err
		}
		if version < 1 {
			_, err := conn.ExecContext(ctx, `UPDATE documents SET body='',pages=0,attempts=0,retry_at=0,
				state=CASE WHEN extension IN (`+imageTypes+`) AND preview='' THEN 'pending' ELSE 'name-only' END
				WHERE extension NOT IN (`+contentTypes+`)`)
			if err != nil {
				return err
			}
		}
		if version < 2 {
			if _, err := conn.ExecContext(ctx, `DELETE FROM documents WHERE NOT (`+visibleName+`)`); err != nil {
				return err
			}
		}
		if _, err := conn.ExecContext(ctx, searchCatalogDDL); err != nil {
			return err
		}

		_, err := conn.ExecContext(ctx, `
INSERT OR IGNORE INTO document_worker(id) VALUES(1);
INSERT INTO document_fts(document_fts) VALUES('rebuild');
INSERT INTO document_fts(document_fts,rank) VALUES('rank','bm25(6,2,1,0,0)');
INSERT INTO document_names_fts(rowid,terms,source_key,type_key)
 SELECT rowid,document_name_terms(name),'s'||lower(hex(source_id)),'t'||lower(hex(extension))
 FROM documents WHERE `+visibleName+`;
INSERT INTO document_counts SELECT source_id,extension,state,count(*)
 FROM documents WHERE `+visibleName+` GROUP BY source_id,extension,state;
PRAGMA user_version=3;`)
		return err
	})
}

type Document struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Path       string  `json:"path"`
	SourceID   string  `json:"sourceId"`
	Source     string  `json:"source"`
	Kind       string  `json:"kind"`
	Extension  string  `json:"extension"`
	Size       int64   `json:"size"`
	Modified   float64 `json:"modified"`
	State      string  `json:"state"`
	Pages      int     `json:"pages"`
	HasPreview bool    `json:"hasPreview"`
	Version    string  `json:"version"`
	Snippet    string  `json:"snippet"`
	Attempts   int     `json:"attempts"`
}

type DocumentDetail struct {
	Document
	Text string `json:"text"`
}

const documentColumns = `d.rowid,d.id,d.source_id,d.path,d.name,d.extension,d.size,d.modified,d.fingerprint,d.state,d.preview,d.pages,d.attempts`

type catalogRow struct {
	Document
	rowID        int64
	fingerprint  string
	preview      string
	body         string
	rank         float64
	streamOffset int64
}

func (row *catalogRow) columns() []any {
	return []any{&row.rowID, &row.ID, &row.SourceID, &row.Path, &row.Name, &row.Extension, &row.Size,
		&row.Modified, &row.fingerprint, &row.State, &row.preview, &row.Pages, &row.Attempts}
}

func (row catalogRow) public(source Source) Document {
	result := row.Document
	result.Source, result.Kind = source.Label, source.Kind
	result.Extension = strings.TrimLeft(result.Extension, ".")
	result.HasPreview = row.preview != ""
	sum := sha256.Sum256([]byte(row.fingerprint))
	result.Version = hex.EncodeToString(sum[:8])
	return result
}

func (row catalogRow) openCurrent(source Source) (*os.File, error) {
	if excludedName(row.Name) {
		return nil, os.ErrNotExist
	}
	file, info, err := openFile(source.root, row.Path, source.owner)
	if err != nil {
		return nil, os.ErrNotExist
	}
	if fingerprint(info) != row.fingerprint {
		file.Close()
		return nil, os.ErrNotExist
	}
	return file, nil
}

func (service Service) currentDocument(ctx context.Context, identity directory.Identity, id string, withBody bool) (catalogRow, Source, *os.File, error) {
	tx, err := service.Catalog.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return catalogRow{}, Source{}, nil, err
	}
	defer tx.Rollback()
	sources, err := service.allowedSourcesInCatalog(ctx, identity, false, tx)
	if err != nil {
		return catalogRow{}, Source{}, nil, err
	}

	var row catalogRow
	columns, targets := documentColumns, row.columns()
	if withBody {
		columns += `,CASE WHEN d.extension IN (` + contentTypes + `) THEN d.body ELSE '' END`
		targets = append(targets, &row.body)
	}
	err = tx.QueryRowContext(ctx, `SELECT `+columns+` FROM documents d WHERE d.id=?`, id).Scan(targets...)
	if errors.Is(err, sql.ErrNoRows) {
		return catalogRow{}, Source{}, nil, os.ErrNotExist
	}
	if err != nil {
		return catalogRow{}, Source{}, nil, err
	}
	source, ok := sources[row.SourceID]
	if !ok {
		return catalogRow{}, Source{}, nil, os.ErrNotExist
	}

	file, err := row.openCurrent(source)
	return row, source, file, err
}

func (service Service) Detail(ctx context.Context, identity directory.Identity, id string) (DocumentDetail, error) {
	row, source, file, err := service.currentDocument(ctx, identity, id, true)
	if err != nil {
		return DocumentDetail{}, err
	}
	defer file.Close()
	return DocumentDetail{Document: row.public(source), Text: row.body}, nil
}

// Download returns the already-validated, pinned original. The caller closes it.
func (service Service) Download(ctx context.Context, identity directory.Identity, id string) (*os.File, Document, error) {
	row, source, file, err := service.currentDocument(ctx, identity, id, false)
	return file, row.public(source), err
}

var previewName = regexp.MustCompile(`^[a-f0-9]{32}\.jpg$`)

func (service Service) Preview(ctx context.Context, identity directory.Identity, id, stateRoot string) (*os.File, error) {
	row, _, original, err := service.currentDocument(ctx, identity, id, false)
	if err != nil {
		return nil, err
	}
	defer original.Close()
	if !previewName.MatchString(row.preview) {
		return nil, os.ErrNotExist
	}
	file, _, err := openFile(filepath.Join(stateRoot, "previews"), row.preview, nil)
	return file, err
}

func unixTime() float64 { return float64(time.Now().UnixNano()) / 1e9 }
