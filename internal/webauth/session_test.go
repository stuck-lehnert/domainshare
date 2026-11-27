package webauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stuck-lehnert/domainshare/internal/config"
	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/state"
)

const testSecret = "local-fixture-for-domainshare-web-sessions"

func sampleIdentity() directory.Identity {
	uid := 10001
	return directory.Identity{Username: `AD\Änne`, SID: "S-1-5-21-10-20-30-1234", UID: &uid, Role: "domain-admin"}
}

func newManager(t *testing.T, resolve Resolver) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shares.db")
	db, err := state.OpenPrivate(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	manager, err := New(t.Context(), db, testSecret, 8*time.Hour, time.Minute, resolve)
	if err != nil {
		t.Fatal(err)
	}
	return manager, path
}

func TestRefreshRevocationAndExpiry(t *testing.T) {
	id := sampleIdentity()
	now := time.Unix(1_790_000_000, 0)
	var directoryErr error
	var lookups int
	manager, _ := newManager(t, func(_ context.Context, sid string) (directory.Identity, error) {
		lookups++
		if sid != id.SID {
			t.Fatalf("resolved wrong SID: %q", sid)
		}
		return id, directoryErr
	})
	manager.now = func() time.Time { return now }

	token, session, err := manager.Issue(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := manager.Verify(t.Context(), token, true)
	if err != nil || !verified.Admin() || lookups != 0 {
		t.Fatalf("fresh session: %+v %v lookups=%d", verified, err, lookups)
	}
	if _, err := manager.Verify(t.Context(), token+"=", true); !errors.Is(err, ErrSession) {
		t.Fatalf("noncanonical token: %v", err)
	}

	id.Role = "user"
	now = now.Add(time.Minute)
	verified, err = manager.Verify(t.Context(), token, true)
	if err != nil || verified.Admin() || lookups != 1 {
		t.Fatalf("stale privileges: %+v %v lookups=%d", verified, err, lookups)
	}

	directoryErr = errors.New("directory offline")
	if err := manager.RecheckAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(t.Context(), token, true); !errors.Is(err, ErrSession) {
		t.Fatalf("offline directory is not fail-closed: %v", err)
	}

	directoryErr = nil
	restarted := *manager
	if err := restarted.Revoke(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(t.Context(), token, false); !errors.Is(err, ErrSession) {
		t.Fatalf("revoked session: %v", err)
	}

	token, session, err = manager.Issue(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	now = time.Unix(session.ExpiresAt, 0)
	if _, err := manager.Verify(t.Context(), token, true); !errors.Is(err, ErrSession) {
		t.Fatalf("expired session: %v", err)
	}
}

func TestRevokeDuringRefresh(t *testing.T) {
	id := sampleIdentity()
	var manager *Manager
	var session Session
	manager, _ = newManager(t, func(ctx context.Context, _ string) (directory.Identity, error) {
		return id, manager.Revoke(ctx, session)
	})
	token, session, err := manager.Issue(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RecheckAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Verify(t.Context(), token, true); !errors.Is(err, ErrSession) {
		t.Fatalf("refresh resurrected session: %v", err)
	}
}

func TestFourDaySessionSurvivesRestart(t *testing.T) {
	const lifetime = 4 * 24 * time.Hour

	ctx, root := t.Context(), t.TempDir()
	start := time.Unix(1_790_000_000, 0)
	now := start
	id := sampleIdentity()
	resolve := func(context.Context, string) (directory.Identity, error) { return id, nil }

	// A new management process reads the key from configuration.db and opens
	// the policy database anew. Keep no live connection or manager between runs.
	startManager := func(run func(*Manager)) {
		t.Helper()
		store, err := config.Open(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()

		snapshot, err := store.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		db, err := state.OpenPrivate(ctx, filepath.Join(root, "shares.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		ttl := time.Duration(snapshot.Values.Int("WEB_JWT_TTL_SECONDS")) * time.Second
		secret := snapshot.Values.String("WEB_JWT_SECRET")
		manager, err := New(ctx, db, secret, ttl, time.Minute, resolve)
		if err != nil {
			t.Fatal(err)
		}
		manager.now = func() time.Time { return now }
		run(manager)
	}

	var token, loggedOut, legacyToken string
	startManager(func(manager *Manager) {
		var err error
		var session Session
		token, session, err = manager.Issue(ctx, id)
		if err != nil || session.ExpiresAt-session.IssuedAt != int64(lifetime/time.Second) {
			t.Fatalf("new session did not get four days: expiry=%d, issued=%d, err=%v", session.ExpiresAt, session.IssuedAt, err)
		}

		loggedOut, session, err = manager.Issue(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Revoke(ctx, session); err != nil {
			t.Fatal(err)
		}

		// The new default must not extend a JWT issued with the previous TTL.
		previous := *manager
		previous.ttl = 8 * time.Hour
		legacyToken, _, err = previous.Issue(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
	})

	startManager(func(manager *Manager) {
		now = start.Add(7 * time.Hour)
		if _, err := manager.Verify(ctx, legacyToken, true); err != nil {
			t.Fatalf("still-valid eight-hour session rejected after restart: %v", err)
		}

		now = start.Add(lifetime - time.Second)
		if session, err := manager.Verify(ctx, token, true); err != nil || session.SID != id.SID {
			t.Fatalf("unexpired session rejected after restart: %v", err)
		}
		if _, err := manager.Verify(ctx, loggedOut, true); !errors.Is(err, ErrSession) {
			t.Fatalf("logged-out session accepted after restart: %v", err)
		}
		if _, err := manager.Verify(ctx, legacyToken, true); !errors.Is(err, ErrSession) {
			t.Fatalf("eight-hour session retained beyond its original expiration: %v", err)
		}

		now = start.Add(lifetime)
		if _, err := manager.Verify(ctx, token, true); !errors.Is(err, ErrSession) {
			t.Fatalf("session accepted at or after four-day expiration: %v", err)
		}
	})
}

func TestOriginAndCSRF(t *testing.T) {
	manager, _ := newManager(t, func(context.Context, string) (directory.Identity, error) { return sampleIdentity(), nil })
	origins, err := NewOrigins("https://files.ad.test, https://setup.ad.test:9443")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		origin, fetch, auth string
		valid               bool
	}{
		{origin: "https://FILES.AD.TEST:443", valid: true},
		{origin: "https://setup.ad.test:9443", valid: true},
		{origin: "https://setup.ad.test"},
		{origin: "https://files.ad.test/"},
		{origin: "https://files.ad.test?"},
		{origin: "https://files.ad.test#"},
		{origin: "https://attacker.test"},
		{origin: "https://files.ad.test", fetch: "cross-site"},
		{origin: "https://files.ad.test", fetch: "same-site"},
		{auth: "Bearer xyz", valid: true},
		{auth: "Bearer "},
		{},
	} {
		request := httptest.NewRequest("POST", "https://attacker.test/api/admin", nil)
		if tc.origin != "" {
			request.Header.Set("Origin", tc.origin)
		}
		request.Header.Set("Sec-Fetch-Site", tc.fetch)
		request.Header.Set("Authorization", tc.auth)
		session := Session{ID: "test-id"}
		request.Header.Set("X-CSRF-Token", manager.CSRF(session))
		if manager.CheckCSRF(origins, request, session) != tc.valid {
			t.Fatalf("unexpected origin/CSRF result: %+v", tc)
		}
		request.Header.Add("X-CSRF-Token", manager.CSRF(session))
		if manager.CheckCSRF(origins, request, session) {
			t.Fatal("accepted duplicate CSRF header")
		}
	}
}

func TestPythonSessionCompatibility(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python reference unavailable")
	}
	id := sampleIdentity()
	manager, path := newManager(t, func(context.Context, string) (directory.Identity, error) { return id, nil })
	token, issued, err := manager.Issue(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	const script = `
import json, sys
from app.web_security import Sessions
from app.web_ui import TokenManager

path, secret = sys.argv[1:]
reference = TokenManager(secret, 28800, Sessions(path))
payload = reference.verify(sys.stdin.read())
token, _ = reference.issue(payload['sub'], payload['sid'], payload['role'], payload['uid'])
print(json.dumps({'token': token, 'csrf': reference.csrf(payload)}))
`
	command := exec.CommandContext(t.Context(), python, "-c", script, path, testSecret)
	command.Dir = "../.."
	command.Stdin = strings.NewReader(token)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("reference session: %v: %s", err, output)
	}
	var reference struct{ Token, CSRF string }
	if err := json.Unmarshal(output, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.CSRF != manager.CSRF(issued) {
		t.Fatal("CSRF differs from Python")
	}
	verified, err := manager.Verify(t.Context(), reference.Token, true)
	if err != nil || verified.SID != id.SID || verified.Username != id.Username || !verified.Admin() {
		t.Fatalf("reference JWT and session row: %+v %v", verified, err)
	}
}
