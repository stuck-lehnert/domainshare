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
	if err != nil || value.ID != issued.ID || !reflect.DeepEqual(accounts, value.Accounts) {
		t.Fatal("token could not be used with its original SID scope")
	}
	store.now = func() time.Time { return time.Unix(issued.ExpiresAt, 0) }
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
