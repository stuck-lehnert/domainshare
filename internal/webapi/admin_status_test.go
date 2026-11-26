package webapi

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/backup"
	"github.com/stuck-lehnert/domainshare/internal/state"
)

func TestBackupStatusDistinguishesRunningFromInterrupted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "backup-status.json")
	content := `{"state":"running","percent":52,"workerPid":123,"updatedAt":"2026-01-01T01:00:00+00:00"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	lock, err := backup.AcquireLock(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if status := readBackupStatus(root, path); status["state"] != "running" || status["processRunning"] != true {
		t.Fatalf("running worker status: %#v", status)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}

	status := readBackupStatus(root, path)
	if status["state"] != "failed" || status["processRunning"] != false || status["interrupted"] != true {
		t.Fatalf("interrupted worker status: %#v", status)
	}
	persisted, err := os.ReadFile(path)
	if err != nil || string(persisted) != content {
		t.Fatalf("status read changed worker state: %s, %v", persisted, err)
	}
}

func TestUsageCacheRemainsReadableAcrossBackends(t *testing.T) {
	root := t.TempDir()
	db, err := state.Open(t.Context(), filepath.Join(root, "state.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scanner := UsageScanner{
		DB: db, Data: filepath.Join(root, "data"), Private: filepath.Join(root, "private"),
		FSLogix: filepath.Join(root, "fslogix"),
	}
	if err := scanner.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	legacy := `{"scannedAt":"2025-01-01T00:00:00+00:00","users":[{"name":"MSOL_hidden"},{"name":"Alice","privateBytes":4,"totalBytes":4}],"groups":[]}`
	if _, err := db.Exec(`INSERT INTO web_cache VALUES('usage',?,'2025-01-01T00:00:00+00:00')`, legacy); err != nil {
		t.Fatal(err)
	}
	if got := scanner.snapshot(t.Context()); len(got.Users) != 1 || got.Users[0].Name != "Alice" || got.ScannedAt == nil {
		t.Fatalf("existing cache: %#v", got)
	}
	if err := scanner.scan(t.Context()); err == nil {
		t.Fatal("missing scan roots did not fail")
	}
	if got := scanner.snapshot(t.Context()); len(got.Users) != 1 || got.Users[0].Private != 4 {
		t.Fatalf("scan failure replaced cache: %#v", got)
	}

	for _, item := range []struct{ path, content string }{
		{"data/Finance/report.txt", "12345"},
		{"data/.trash/skipped.txt", "123456789"},
		{"private/Alice/test.txt", "123"},
		{"private/krbtgt/dummy.txt", "12"},
	} {
		path := filepath.Join(root, item.path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(item.content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(scanner.FSLogix, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(scanner.Private, filepath.Join(scanner.Data, "Finance", "not-a-share")); err != nil {
		t.Fatal(err)
	}
	if err := scanner.scan(t.Context()); err != nil {
		t.Fatal(err)
	}

	report := scanner.snapshot(t.Context())
	if !reflect.DeepEqual(report.Groups, []usageGroup{{Name: "Finance", Bytes: 5}}) ||
		!reflect.DeepEqual(report.Users, []usageUser{{Name: "Alice", Private: 3, Total: 3}}) ||
		report.Totals != (usageTotals{Data: 5, Private: 5}) {
		t.Fatalf("usage report: %#v", report)
	}
}
