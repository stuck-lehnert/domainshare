// Package config opens the same configuration.db used by DomainShare's Python backend.
package config

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stuck-lehnert/domainshare/internal/state"
)

const DefaultRoot = "/state"

var ErrConflict = errors.New("configuration revision changed")

//go:embed schema.json
var schemaJSON []byte

type field struct {
	Key     string          `json:"key"`
	Label   string          `json:"label"`
	Kind    string          `json:"kind"`
	Section string          `json:"section"`
	Default json.RawMessage `json:"default"`
	Minimum int             `json:"minimum"`
	Maximum int             `json:"maximum"`
	Choices []string        `json:"choices"`
}

var schema = loadSchema()

func loadSchema() (result struct {
	Fields        []field  `json:"fields"`
	PrivateFields []string `json:"privateFields"`
}) {
	if err := json.Unmarshal(schemaJSON, &result); err != nil {
		panic("invalid embedded configuration schema: " + err.Error())
	}
	return result
}

type Values map[string]any

func decodeValues(data []byte) (Values, error) {
	values := make(Values)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&values); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, errors.New("configuration settings must be a JSON object")
	}
	return values, nil
}

func (values Values) String(key string) string {
	value, _ := values[key].(string)
	return value
}

func (values Values) Bool(key string) bool {
	value, _ := values[key].(bool)
	return value
}

func (values Values) Int(key string) int {
	switch value := values[key].(type) {
	case json.Number:
		number, _ := strconv.Atoi(value.String())
		return number
	case int:
		return value
	default:
		return 0
	}
}

type Snapshot struct {
	Revision        int64
	Phase           string
	ServiceRevision int64
	Values          Values
}

type Store struct {
	root string
	db   *sql.DB
}

func Open(ctx context.Context, root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("configuration root is empty")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(absolute, "configuration.db")
	db, err := state.OpenPrivate(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("open private configuration database: %w", err)
	}
	store := &Store{root: absolute, db: db}
	if err := store.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Root() string { return store.root }

func (store *Store) Close() error { return store.db.Close() }

func (store *Store) initialize(ctx context.Context) error {
	// Match the schema in app/configuration.py, including the positional INSERT
	// contract for pending backup keys, while both backends share the database.
	const statements = `
CREATE TABLE IF NOT EXISTS configuration (
    id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, phase TEXT NOT NULL,
    service_revision INTEGER NOT NULL, settings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_backup_keys (
    nonce TEXT PRIMARY KEY, owner TEXT NOT NULL, expires REAL NOT NULL, revision INTEGER NOT NULL,
    password TEXT NOT NULL, key_id TEXT NOT NULL, format TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scheduled_backups (slot TEXT PRIMARY KEY);
`
	defaults := map[string]json.RawMessage{}
	for _, item := range schema.Fields {
		defaults[item.Key] = item.Default
	}
	secret := make([]byte, 48)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	encoded, err := json.Marshal(base64.RawURLEncoding.EncodeToString(secret))
	if err != nil {
		return err
	}
	defaults["WEB_JWT_SECRET"] = encoded
	settings, err := json.Marshal(defaults)
	if err != nil {
		return err
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, statements); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT OR IGNORE INTO configuration VALUES(1,0,'unconfigured',0,?)", string(settings),
	); err != nil {
		return err
	}

	if err := migrateSessionLifetime(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateSessionLifetime(ctx context.Context, tx *sql.Tx) error {
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version >= 1 {
		return nil
	}

	// Old configurations did not distinguish the eight-hour default from an
	// explicit eight-hour setting. Migrate that value once, leaving the key
	// and any other custom duration intact. Switch to the next revision only
	// for edited configurations; revision zero still permits legacy import.
	if _, err := tx.ExecContext(ctx, `
UPDATE configuration
SET settings=json_set(settings, '$.WEB_JWT_TTL_SECONDS', 345600),
    revision=CASE WHEN revision=0 AND phase='unconfigured' THEN 0 ELSE revision+1 END
WHERE id=1 AND json_extract(settings, '$.WEB_JWT_TTL_SECONDS')=28800`); err != nil {
		return err
	}

	_, err := tx.ExecContext(ctx, "PRAGMA user_version=1")
	return err
}

func (store *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	var snapshot Snapshot
	var settings []byte
	err := store.db.QueryRowContext(ctx,
		"SELECT revision,phase,service_revision,settings FROM configuration WHERE id=1",
	).Scan(&snapshot.Revision, &snapshot.Phase, &snapshot.ServiceRevision, &settings)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Values, err = decodeValues(settings)
	return snapshot, err
}

// AdvanceToGroups does not override a concurrent setup submission.
func (store *Store) AdvanceToGroups(ctx context.Context, revision int64) error {
	result, err := store.db.ExecContext(ctx, `
UPDATE configuration SET phase='groups', revision=revision+1
WHERE id=1 AND phase='joining' AND revision=?`, revision)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err == nil && changed != 1 {
		return ErrConflict
	}
	return err
}

func (store *Store) ClaimBackupSlot(ctx context.Context, slot string) (bool, error) {
	result, err := store.db.ExecContext(ctx, "INSERT OR IGNORE INTO scheduled_backups VALUES(?)", slot)
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	return inserted == 1, err
}
