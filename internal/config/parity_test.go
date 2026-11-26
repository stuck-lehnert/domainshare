package config

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func pythonOracle(t *testing.T, script string, args ...string) []byte {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python reference backend is not installed")
	}
	command := exec.CommandContext(t.Context(), python, append([]string{"-c", script}, args...)...)
	command.Dir = "../.."
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("Python oracle: %v\n%s", err, exit.Stderr)
		}
		t.Fatal(err)
	}
	return output
}

func TestPythonDatabaseAndEnvironment(t *testing.T) {
	root := t.TempDir()
	output := pythonOracle(t, `
from app.configuration import Store
import json, sys
store = Store(sys.argv[1])
assert store.import_legacy({
    'REALM': 'EXAMPLE.TEST', 'WORKGROUP': 'EXAMPLE', 'DOMAIN': 'example.test',
    'DOMAIN_USERS_SID': 'S-1-5-21-1-513', 'DOMAIN_ADMINS_SID': 'S-1-5-21-1-512',
    'JOIN_PASSWORD': " $literal ' password ", 'BACKUP_ARCHIVE_PASSWORD': 'legacy-password',
    'TLS_CA_PROVISIONER_PASSWORD': 'test ca password', 'WEB_BIND_PORT': '9443',
})
print(json.dumps(store.environment(materialize=True)))
`, root)
	var want map[string]string
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatal(err)
	}
	store, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	snapshot, err := store.Snapshot(t.Context())
	if err != nil || snapshot.Phase != "configured" || snapshot.Revision != 1 || snapshot.ServiceRevision != 1 {
		t.Fatalf("read prior configuration: phase=%q revision=%d serviceRevision=%d err=%v", snapshot.Phase, snapshot.Revision, snapshot.ServiceRevision, err)
	}
	got, err := store.Environment(snapshot, true)
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("environment differs for %s", key)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected environment variable %s", key)
		}
	}

	if err := store.Save(t.Context(), Values{"BACKUP_START_HOUR": "4"}, snapshot.Revision, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(t.Context(), Values{"BACKUP_START_HOUR": "5"}, snapshot.Revision, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}
	claimed, err := store.ClaimBackupSlot(t.Context(), "2026-11-26T04")
	if err != nil || !claimed {
		t.Fatalf("claim existing database slot: %v, %v", claimed, err)
	}
	pythonOracle(t, `
from app.configuration import Store
import sys
store = Store(sys.argv[1])
snap = store.snapshot()
assert (snap['phase'], snap['revision'], snap['service_revision']) == ('configured', 2, 1)
assert snap['values']['BACKUP_START_HOUR'] == 4
with store.connect() as conn:
    assert conn.execute('INSERT OR IGNORE INTO scheduled_backups VALUES(?)', ('2026-11-26T04',)).rowcount == 0
`, root)
}

func TestGoDatabaseReadableByPython(t *testing.T) {
	root := t.TempDir()
	store, err := Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	info, err := os.Stat(filepath.Join(root, "configuration.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("configuration permissions: %o", info.Mode().Perm())
	}
	pythonOracle(t, `
from app.configuration import FIELDS, Store
import sys
store = Store(sys.argv[1])
snap = store.snapshot()
assert snap['phase'] == 'unconfigured' and snap['revision'] == 0
assert len(snap['values']['WEB_JWT_SECRET']) == 64
assert {k: v['default'] for k,v in FIELDS.items()} == {k:v for k,v in snap['values'].items() if k != 'WEB_JWT_SECRET'}
assert store.generate_key('test-owner')['nonce']
`, root)
	var revision int
	if err := store.db.QueryRowContext(t.Context(), "SELECT revision FROM pending_backup_keys WHERE owner=?", "test-owner").Scan(&revision); err != nil || revision != 0 {
		t.Fatalf("Python pending key in Go DB: revision=%d, err=%v", revision, err)
	}
}

func TestLegacyParsingDoesNotExpandShell(t *testing.T) {
	source := "REALM='EXAMPLE.TEST' # ignored\n" +
		"export JOIN_PASSWORD=' abc  $UNCHANGED # = '\n" +
		`BACKUP_ARCHIVE_PASSWORD="a\$b \"quoted\""` + "\n" +
		"UNKNOWN='unclosed quote\n"
	got, err := ParseLegacy(source)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	output := pythonOracle(t, `from app.configuration import parse_legacy; import json,sys; print(json.dumps(parse_legacy(sys.argv[1])))`, source)
	if err := json.Unmarshal(output, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatal("legacy shell parser differs from the Python oracle")
	}
}

func TestSaveRevisionAndGroupTransitions(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.Save(ctx, Values{"WEB_TLS_MODE": "files"}, 0, true); err == nil {
		t.Fatal("accepted files TLS without a certificate pair")
	}
	if err := store.Save(ctx, Values{"BACKUP_DESTINATION": "sftp://backup.example.test/data"}, 0, true); err == nil {
		t.Fatal("accepted encrypted backup without a confirmed key")
	}
	if err := store.Save(ctx, Values{"DOMAIN_USERS_SID": "S-1-5-21-1-513"}, 0, true); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ctx, Values{"DOMAIN_USERS_SID": "S-1-5-21-1-513"}, 1, true); err != nil {
		t.Fatal(err)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil || snap.Revision != 1 || snap.ServiceRevision != 0 {
		t.Fatalf("group and no-op updates: revision=%d serviceRevision=%d err=%v", snap.Revision, snap.ServiceRevision, err)
	}
	if err := store.AdvanceToGroups(ctx, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("advanced from incorrect phase: %v", err)
	}
}
