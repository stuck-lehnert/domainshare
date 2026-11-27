// Package agenttoken manages read-only API credentials scoped to AD account SIDs.
package agenttoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stuck-lehnert/domainshare/internal/state"
)

const DatabaseName = "agent-tokens.db"

// NoExpiry opts out of expiry. The same sentinel is stored in expires_at,
// allowing older releases to reject these tokens without a schema change.
const NoExpiry = -1

// Store the all-user scope explicitly. Empty or null scopes never grant access.
// The reserved key is not an AD SID, so older releases deny these tokens.
const allUsersScope = `{"*":"*"}`

var (
	ErrInvalid = errors.New("invalid or expired agent token")
	ErrID      = errors.New("Ungültige Token-ID")
	validRaw   = regexp.MustCompile(`^dsat_[A-Za-z0-9_-]{43}$`)
	validID    = regexp.MustCompile(`^[a-f0-9]{24}$`)
	validSID   = regexp.MustCompile(`^S-1-(?:[0-9]+-)*[0-9]+$`)
)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

type Token struct {
	ID       string
	AllUsers bool
	Accounts map[string]string // SID to display name; display names are never authoritative.
}

type Issued struct {
	ID        string `json:"id"`
	Raw       string `json:"token"`
	ExpiresAt *int64 `json:"expiresAt"`
}

type Record struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	AllUsers  bool     `json:"allUsers"`
	Usernames []string `json:"usernames"`
	CreatedBy string   `json:"createdBy"`
	CreatedAt int64    `json:"createdAt"`
	ExpiresAt *int64   `json:"expiresAt"`
}

func Open(ctx context.Context, root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("agent token state root is empty")
	}
	db, err := state.OpenPrivate(ctx, filepath.Join(root, DatabaseName))
	if err != nil {
		return nil, err
	}

	const schema = `CREATE TABLE IF NOT EXISTS agent_tokens (
		id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE,
		label TEXT NOT NULL, accounts TEXT NOT NULL, created_by TEXT NOT NULL,
		created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
	)`
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, now: time.Now}, nil
}

func (store *Store) Close() error { return store.db.Close() }

func digest(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// Issue creates a restricted token. The caller must have checked the
// administrator's identity and resolved the allowed users directly in AD.
func (store *Store) Issue(ctx context.Context, label string, accounts map[string]string, days int, actor string) (Issued, error) {
	if len(accounts) < 1 || len(accounts) > 10 {
		return Issued{}, errors.New("Ein bis zehn AD-Benutzernamen sind erforderlich")
	}
	for sid, name := range accounts {
		if !validSID.MatchString(sid) || name == "" {
			return Issued{}, errors.New("Ungültiger AD-Benutzer")
		}
	}

	scope, err := json.Marshal(accounts)
	if err != nil {
		return Issued{}, err
	}
	return store.issue(ctx, label, string(scope), days, actor)
}

// IssueForAllUsers grants delegation without a fixed SID list. Each request
// must still resolve a current eligible AD account and enforce its permissions.
func (store *Store) IssueForAllUsers(ctx context.Context, label string, days int, actor string) (Issued, error) {
	return store.issue(ctx, label, allUsersScope, days, actor)
}

// issue persists only the hash of the generated bearer credential.
func (store *Store) issue(ctx context.Context, label, scope string, days int, actor string) (Issued, error) {
	label = strings.TrimSpace(label)
	if label == "" || utf8.RuneCountInString(label) > 100 {
		return Issued{}, errors.New("Eine Bezeichnung mit 1 bis 100 Zeichen ist erforderlich")
	}
	if days != NoExpiry && (days < 1 || days > 365) {
		return Issued{}, errors.New("Die Laufzeit muss zwischen 1 und 365 Tagen liegen oder leer bleiben")
	}

	var random [44]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Issued{}, err
	}
	identifier := hex.EncodeToString(random[:12])
	raw := "dsat_" + base64.RawURLEncoding.EncodeToString(random[12:])

	now := store.now().Unix()
	expires := int64(NoExpiry)
	if days != NoExpiry {
		expires = now + int64(days)*86400
	}

	_, err := store.db.ExecContext(ctx, `INSERT INTO agent_tokens VALUES(?,?,?,?,?,?,?)`,
		identifier, digest(raw), label, scope, actor, now, expires)
	if err != nil {
		return Issued{}, err
	}
	return Issued{ID: identifier, Raw: raw, ExpiresAt: expiryTimestamp(expires)}, nil
}

func expiryTimestamp(expires int64) *int64 {
	if expires == NoExpiry {
		return nil
	}
	return &expires
}

func (store *Store) Authenticate(ctx context.Context, raw string) (Token, error) {
	if !validRaw.MatchString(raw) {
		return Token{}, ErrInvalid
	}
	var token Token
	var scope []byte
	err := store.db.QueryRowContext(ctx, `SELECT id,accounts FROM agent_tokens
		WHERE digest=? AND (expires_at=? OR expires_at>?)`, digest(raw), NoExpiry, store.now().Unix()).Scan(&token.ID, &scope)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrInvalid
	}
	if err != nil {
		return Token{}, err
	}
	if string(scope) == allUsersScope {
		token.AllUsers = true
		return token, nil
	}

	if err := json.Unmarshal(scope, &token.Accounts); err != nil {
		return Token{}, err
	}
	return token, nil
}

func (store *Store) Inventory(ctx context.Context) ([]Record, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,label,accounts,created_by,created_at,expires_at
		FROM agent_tokens ORDER BY created_at DESC,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Record, 0)
	for rows.Next() {
		var item Record
		var scope string
		var expires int64
		if err := rows.Scan(&item.ID, &item.Label, &scope, &item.CreatedBy, &item.CreatedAt, &expires); err != nil {
			return nil, err
		}
		item.ExpiresAt = expiryTimestamp(expires)

		if scope == allUsersScope {
			item.AllUsers = true
			item.Usernames = []string{}
		} else {
			item.Usernames, err = namesInStoredOrder(scope)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Existing inventories preserve the order of names in the stored JSON object.
func namesInStoredOrder(scope string) ([]string, error) {
	decoder := json.NewDecoder(strings.NewReader(scope))
	if start, err := decoder.Token(); err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid stored token scope")
	}
	names := make([]string, 0)
	for decoder.More() {
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		var name string
		if err := decoder.Decode(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	return names, nil
}

func (store *Store) Revoke(ctx context.Context, id string) (bool, error) {
	if !validID.MatchString(id) {
		return false, ErrID
	}
	result, err := store.db.ExecContext(ctx, "DELETE FROM agent_tokens WHERE id=?", id)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}
