package agenttoken

import (
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestTokenExpiryAndRevocationAcrossReopen(t *testing.T) {
	root := t.TempDir()
	ctx := t.Context()
	store, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	accounts := map[string]string{"S-1-5-21-1000": "sam"}
	issued, err := store.Issue(ctx, "automation", accounts, 1, "DEMO\\administrator")
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	var hash string
	err = store.db.QueryRowContext(ctx, "SELECT digest FROM agent_tokens WHERE id=?", issued.ID).Scan(&hash)
	store.Close()
	if err != nil || hash != digest(issued.Raw) || hash == issued.Raw {
		t.Fatal("did not store only the token digest")
	}

	store, err = Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	value, err := store.Authenticate(ctx, issued.Raw)
	if err != nil || value.ID != issued.ID || value.AllUsers || !reflect.DeepEqual(accounts, value.Accounts) {
		t.Fatal("token could not be used with its original SID scope")
	}
	if issued.ExpiresAt == nil {
		t.Fatal("finite token was issued without an expiry")
	}
	store.now = func() time.Time { return time.Unix(*issued.ExpiresAt, 0) }
	if _, err := store.Authenticate(ctx, issued.Raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token accepted at expiry: %v", err)
	}
	store.now = time.Now
	if removed, err := store.Revoke(ctx, issued.ID); err != nil || !removed {
		t.Fatalf("revoke: %v, %v", removed, err)
	}
	if _, err := store.Authenticate(ctx, issued.Raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked token accepted: %v", err)
	}
}

func TestNonExpiringTokenSurvivesTimeAndRemainsRevocable(t *testing.T) {
	for _, allUsers := range []bool{false, true} {
		name := "restricted"
		if allUsers {
			name = "all users"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			root := t.TempDir()
			store, err := Open(ctx, root)
			if err != nil {
				t.Fatal(err)
			}

			var issued Issued
			if allUsers {
				issued, err = store.IssueForAllUsers(ctx, name, NoExpiry, "admin")
			} else {
				issued, err = store.Issue(ctx, name, map[string]string{"S-1-5-21-1000": "sam"}, NoExpiry, "admin")
			}
			store.Close()
			if err != nil || issued.ExpiresAt != nil {
				t.Fatalf("could not issue a token without expiry: %v", err)
			}

			store, err = Open(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			future := time.Now().AddDate(100, 0, 0)
			store.now = func() time.Time { return future }

			token, err := store.Authenticate(ctx, issued.Raw)
			if err != nil || token.ID != issued.ID || token.AllUsers != allUsers {
				t.Fatalf("non-expiring token did not retain its scope in the future: %v", err)
			}
			rows, err := store.Inventory(ctx)
			if err != nil || len(rows) != 1 || rows[0].ExpiresAt != nil {
				t.Fatalf("inventory should have no expiry for this token: %v, %v", rows, err)
			}

			if revoked, err := store.Revoke(ctx, issued.ID); err != nil || !revoked {
				t.Fatalf("could not revoke the non-expiring token: %v", err)
			}
			if _, err := store.Authenticate(ctx, issued.Raw); !errors.Is(err, ErrInvalid) {
				t.Fatalf("revoked non-expiring token was accepted: %v", err)
			}
		})
	}
}

func TestAllUserScopeIsExplicitAndPersistent(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	store, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Issue(ctx, "empty", nil, 1, "admin"); err == nil {
		t.Fatal("an empty restricted scope accidentally issued a token")
	}
	issued, err := store.IssueForAllUsers(ctx, "all users", 1, "admin")
	store.Close()
	if err != nil {
		t.Fatal(err)
	}

	store, err = Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	token, err := store.Authenticate(ctx, issued.Raw)
	if err != nil || token.ID != issued.ID || !token.AllUsers || len(token.Accounts) != 0 {
		t.Fatalf("all-user scope after reopen: %+v, %v", token, err)
	}
	rows, err := store.Inventory(ctx)
	if err != nil || len(rows) != 1 || !rows[0].AllUsers || rows[0].Usernames == nil || len(rows[0].Usernames) != 0 {
		t.Fatalf("inventory did not identify the all-user scope: %v, %v", rows, err)
	}

	for _, scope := range []string{`{}`, `null`, `{"*":"anything else"}`} {
		if _, err := store.db.ExecContext(ctx, `UPDATE agent_tokens SET accounts=? WHERE id=?`, scope, issued.ID); err != nil {
			t.Fatal(err)
		}
		token, err := store.Authenticate(ctx, issued.Raw)
		if err == nil && token.AllUsers {
			t.Fatalf("invalid stored scope %s was treated as all users", scope)
		}
	}
}

func TestReadsExistingPythonTokens(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python reference backend not installed")
	}
	root := t.TempDir()
	command := exec.CommandContext(t.Context(), python, "-c", `
import json, sys
from app.agent_api import TokenStore
store = TokenStore(sys.argv[1])
print(json.dumps(store.issue('legacy', {'S-1-5-21-1002': 'bravo', 'S-1-5-21-1001': 'alpha'}, 2, 'DEMO\\admin')))
`, root)
	command.Dir = "../.."
	data, err := command.Output()
	if err != nil {
		t.Fatal("Python test fixture failed:", err)
	}
	var issued Issued
	if err := json.Unmarshal(data, &issued); err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token, err := store.Authenticate(t.Context(), issued.Raw)
	if err != nil || token.ID != issued.ID || token.Accounts["S-1-5-21-1002"] != "bravo" {
		t.Fatal("existing SID scope was not preserved")
	}
	rows, err := store.Inventory(t.Context())
	if err != nil || len(rows) != 1 || !reflect.DeepEqual(rows[0].Usernames, []string{"bravo", "alpha"}) {
		t.Fatalf("existing inventory order differs: %v, %v", rows, err)
	}
}
