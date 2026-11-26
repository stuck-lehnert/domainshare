package config

import (
	"encoding/json"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/backup"
)

func TestPublicConfigurationRedactionAndParity(t *testing.T) {
	ctx := t.Context()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	snap.Values["BACKUP_DESTINATION"] = "webdavs://hidden-user:hidden-password@backup.ad.test:8443/domainshare?secret-token=hidden-query#hidden-fragment"
	snap.Values["JOIN_PASSWORD"] = "hidden-join-password"
	snap.Values["BACKUP_ARCHIVE_PASSWORD"] = "hidden-legacy-key"
	if err := store.update(ctx, snap.Revision, snap.Phase, snap.Values, 0); err != nil {
		t.Fatal(err)
	}

	public, err := store.Public(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if !public.Encryption.Legacy || strings.Contains(string(encoded), "hidden-") || !strings.Contains(string(encoded), `"summary":"webdavs://backup.ad.test:8443/domainshare"`) {
		t.Fatal("public view failed to redact settings or describe the legacy key")
	}
	for _, private := range schema.PrivateFields {
		if strings.Contains(string(encoded), `"key":"`+private+`"`) {
			t.Fatalf("private setting present in public schema: %s", private)
		}
	}

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python reference unavailable")
	}
	const script = `
import json, sys
from app.configuration import Store
print(json.dumps(Store(sys.argv[1]).public()))
`
	command := exec.CommandContext(ctx, python, "-c", script, store.Root())
	command.Dir = "../.."
	reference, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("public reference failed: %v: %s", err, reference)
	}
	var goValue, pythonValue any
	if err := json.Unmarshal(encoded, &goValue); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reference, &pythonValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(goValue, pythonValue) {
		t.Fatal("public schema differs from the Python reference")
	}
}

func TestPendingBackupKeyIsBoundToOwnerAndRevision(t *testing.T) {
	ctx := t.Context()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const owner = "AD\\admin"
	key, err := store.GenerateKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if key.Phrase == "" || key.Format != backup.KeyFormat || len(key.KeyID) != 24 {
		t.Fatal("invalid pending backup-key metadata")
	}
	if err := store.ActivateKey(ctx, "AD\\other", key.Nonce, true, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending key accepted for wrong account: %v", err)
	}
	if err := store.ActivateKey(ctx, owner, key.Nonce, false, false); err == nil {
		t.Fatal("activated without recovery phrase confirmation")
	}
	if err := store.ActivateKey(ctx, owner, key.Nonce, true, false); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateKey(ctx, owner, key.Nonce, true, true); !errors.Is(err, ErrConflict) {
		t.Fatal("activation nonce was reusable")
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	password, err := backup.ArchiveKey(key.Phrase)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Values.String("BACKUP_ARCHIVE_PASSWORD") != password || snap.Values.String("BACKUP_NAMESPACE") != "keys/"+key.KeyID ||
		!snap.Values.Bool("BACKUP_ENCRYPTION_ENABLED") || snap.ServiceRevision != 0 || snap.Revision != 1 {
		t.Fatal("active key differs from recovery phrase or wrong revisions changed")
	}
	rotated, err := store.GenerateKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateKey(ctx, owner, rotated.Nonce, true, false); err == nil {
		t.Fatal("rotated an existing key without confirming the need for old credentials")
	}
	if err := store.update(ctx, snap.Revision, snap.Phase, snap.Values, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateKey(ctx, owner, rotated.Nonce, true, true); !errors.Is(err, ErrConflict) {
		t.Fatalf("activated stale key after settings revision changed: %v", err)
	}
}
