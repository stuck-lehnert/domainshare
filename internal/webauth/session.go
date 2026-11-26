// Package webauth implements the browser session protocol independently of agent tokens.
package webauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/directory"
)

const (
	CookieName = "domainshare_session"
	issuer     = "domainshare-web"
	audience   = "ad-users"
)

var (
	ErrSession = errors.New("invalid or expired web session")
	sidPattern = regexp.MustCompile(`^S-1-(?:[0-9]+-)*[0-9]+$`)
	encoding   = base64.RawURLEncoding.Strict()
)

type Resolver func(context.Context, string) (directory.Identity, error)

type Manager struct {
	db      *sql.DB
	secret  []byte
	ttl     time.Duration
	recheck time.Duration
	resolve Resolver
	now     func() time.Time
}

type Session struct {
	directory.Identity
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti"`
}

func New(ctx context.Context, db *sql.DB, secret string, ttl, recheck time.Duration, resolve Resolver) (*Manager, error) {
	if len(secret) < 32 {
		return nil, errors.New("WEB_JWT_SECRET must contain at least 32 bytes")
	}
	if db == nil || ttl < 5*time.Minute || ttl > 7*24*time.Hour || recheck < 5*time.Second || recheck > 5*time.Minute || resolve == nil {
		return nil, errors.New("invalid web session configuration")
	}

	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS web_sessions (
		id TEXT PRIMARY KEY, sid TEXT NOT NULL, expires INTEGER NOT NULL,
		username TEXT NOT NULL, uid INTEGER, role TEXT NOT NULL, checked REAL NOT NULL);
		CREATE INDEX IF NOT EXISTS web_sessions_expiry ON web_sessions(expires);`)
	if err != nil {
		return nil, err
	}
	return &Manager{db: db, secret: []byte(secret), ttl: ttl, recheck: recheck, resolve: resolve, now: time.Now}, nil
}

func validIdentity(id directory.Identity) bool {
	return sidPattern.MatchString(id.SID) && id.Username != "" && !directory.IsExcludedUser(id.Username) &&
		(id.UID == nil || *id.UID >= 0) && (id.Role == "user" || id.Admin())
}

func (manager *Manager) Issue(ctx context.Context, id directory.Identity) (string, Session, error) {
	if !validIdentity(id) {
		return "", Session{}, ErrSession
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", Session{}, err
	}

	now := manager.now()
	session := Session{
		Identity: id, Issuer: issuer, Audience: audience, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(manager.ttl).Unix(), ID: encoding.EncodeToString(random[:]),
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return "", Session{}, err
	}
	signingInput := encoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + encoding.EncodeToString(payload)
	token := signingInput + "." + encoding.EncodeToString(manager.sign(signingInput))

	tx, err := manager.db.BeginTx(ctx, nil)
	if err != nil {
		return "", Session{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires<=?`, session.IssuedAt); err != nil {
		return "", Session{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO web_sessions(id,sid,expires,username,uid,role,checked) VALUES(?,?,?,?,?,?,?)`,
		key(session.ID), id.SID, session.ExpiresAt, id.Username, id.UID, id.Role, session.IssuedAt)
	if err != nil {
		return "", Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", Session{}, err
	}

	return token, session, nil
}

func (manager *Manager) sign(value string) []byte {
	mac := hmac.New(sha256.New, manager.secret)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

func key(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func decode(segment string) ([]byte, error) {
	decoded, err := encoding.DecodeString(segment)
	if err != nil || encoding.EncodeToString(decoded) != segment {
		return nil, ErrSession
	}
	return decoded, nil
}

func (manager *Manager) parse(token string, now time.Time) (Session, error) {
	if len(token) > 8192 || strings.Count(token, ".") != 2 {
		return Session{}, ErrSession
	}

	parts := strings.Split(token, ".")
	signature, err := decode(parts[2])
	if err != nil || !hmac.Equal(signature, manager.sign(parts[0]+"."+parts[1])) {
		return Session{}, ErrSession
	}

	var header map[string]string
	rawHeader, err := decode(parts[0])
	if err != nil || json.Unmarshal(rawHeader, &header) != nil || len(header) != 2 ||
		header["alg"] != "HS256" || header["typ"] != "JWT" {
		return Session{}, ErrSession
	}

	var session Session
	payload, err := decode(parts[1])
	if err != nil || json.Unmarshal(payload, &session) != nil || !validIdentity(session.Identity) ||
		session.Issuer != issuer || session.Audience != audience || session.ID == "" || len(session.ID) > 128 ||
		session.ExpiresAt <= now.Unix() || session.IssuedAt > now.Unix()+60 {
		return Session{}, ErrSession
	}
	return session, nil
}

func (manager *Manager) current(ctx context.Context, session Session, now float64) (directory.Identity, float64, error) {
	var id directory.Identity
	var checked float64
	err := manager.db.QueryRowContext(ctx, `SELECT sid,username,uid,role,checked FROM web_sessions
		WHERE id=? AND sid=? AND expires=? AND expires>?`, key(session.ID), session.SID, session.ExpiresAt, now).
		Scan(&id.SID, &id.Username, &id.UID, &id.Role, &checked)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !validIdentity(id)) {
		return directory.Identity{}, 0, ErrSession
	}
	return id, checked, err
}

func seconds(now time.Time) float64 {
	return float64(now.Unix()) + float64(now.Nanosecond())/1e9
}

// Verify reads live session state even if identity refresh is disabled. Only
// session housekeeping routes may disable the directory lookup.
func (manager *Manager) Verify(ctx context.Context, token string, refresh bool) (Session, error) {
	timeNow := manager.now()
	session, err := manager.parse(token, timeNow)
	if err != nil {
		return Session{}, err
	}

	now := seconds(timeNow)
	id, checked, err := manager.current(ctx, session, now)
	if err != nil {
		return Session{}, err
	}

	if refresh && now-checked >= manager.recheck.Seconds() {
		revalidated, err := manager.resolve(ctx, session.SID)
		if err != nil || revalidated.SID != session.SID || !validIdentity(revalidated) {
			return Session{}, ErrSession
		}

		// Never resurrect a logged-out session or overwrite a more recent refresh.
		_, err = manager.db.ExecContext(ctx, `UPDATE web_sessions SET username=?,uid=?,role=?,checked=?
			WHERE id=? AND sid=? AND expires=? AND checked=?`, revalidated.Username, revalidated.UID,
			revalidated.Role, now, key(session.ID), session.SID, session.ExpiresAt, checked)
		if err != nil {
			return Session{}, err
		}

		verifiedAt := seconds(manager.now())
		id, checked, err = manager.current(ctx, session, verifiedAt)
		if err != nil {
			return Session{}, err
		}
		if verifiedAt-checked >= manager.recheck.Seconds() {
			return Session{}, ErrSession
		}
	}

	session.Identity = id
	return session, nil
}

func (manager *Manager) CSRF(session Session) string {
	return encoding.EncodeToString(manager.sign("csrf:" + session.ID))
}

func (manager *Manager) Revoke(ctx context.Context, session Session) error {
	_, err := manager.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id=?`, key(session.ID))
	return err
}

func (manager *Manager) RecheckAll(ctx context.Context) error {
	// Distinct negative values invalidate in-flight lookups even if the
	// session was already marked for revalidation at their start.
	_, err := manager.db.ExecContext(ctx, `UPDATE web_sessions SET checked=min(checked - 1, 0)`)
	return err
}
