package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const zeroEntropyPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
const pythonArchiveKey = "65025e5d7e34d4fb25ea8447390634e239e6c2af78eb2620b3fc0c89af7eb5a3"

func TestRecoveryKeyCompatibility(t *testing.T) {
	if phraseFromEntropy(make([]byte, 32)) != zeroEntropyPhrase {
		t.Fatal("BIP39 256-bit entropy test vector differs")
	}
	phrase := strings.ReplaceAll("\t"+strings.ToUpper(zeroEntropyPhrase)+"\n", " ", "\u3000")
	password, err := ArchiveKey(phrase)
	if err != nil || password != pythonArchiveKey {
		t.Fatalf("derived password does not match original Python vector: %v", err)
	}
	if _, err := ArchiveKey(strings.TrimSuffix(zeroEntropyPhrase, "art") + "abandon"); err == nil {
		t.Fatal("phrase with invalid checksum accepted")
	}
	key, err := GenerateKey()
	if err != nil || len(key.KeyID) != 24 || key.Format != KeyFormat || len(strings.Fields(key.Phrase)) != 24 {
		t.Fatalf("generated an invalid key: %v", err)
	}
	encoded, err := json.Marshal(key)
	if err != nil || bytes.Contains(encoded, []byte(key.Phrase)) || bytes.Contains(encoded, []byte(key.Password)) {
		t.Fatal("key JSON contains secret material")
	}
}

func TestJournalMatchesPythonAndIgnoresPassword(t *testing.T) {
	d, err := parseDestination("sftp://D%C3%A4:test@Host:8022/old/%F0%9F%98%80/", "")
	if err != nil {
		t.Fatal(err)
	}
	const expected = "db0f317ef3c32ed95bac7afec4d345595c24e2bc27913d14c4357b54d9b7d199"
	if name := filepath.Base(journalPath("/state", d)); name != expected {
		t.Fatalf("journal ID = %s; want Python ID %s", name, expected)
	}
	if strings.Contains(d.redacted, ":test@") {
		t.Fatalf("destination password leaked into %q", d.redacted)
	}
	rotated, err := parseDestination("sftp://D%C3%A4:rotated@Host:8022/old/%F0%9F%98%80/", "")
	if err != nil || journalPath("/state", rotated) != journalPath("/state", d) {
		t.Fatalf("password change affected journal identity: %v", err)
	}
	plain, err := parseDestination("sftp://D%C3%A4:rotated@Host:8022/old/%F0%9F%98%80/", "plain")
	if err != nil || journalPath("/state", plain) == journalPath("/state", d) {
		t.Fatalf("namespace is not isolated: %v", err)
	}
}

func TestRetentionUnion(t *testing.T) {
	names := []string{"20250804T020000Z", "20250803T020000Z", "20250801T020000Z", "20250101T020000Z", "20240101T020000Z", "garbage", "20250231T020000Z"}
	got := RetainedSnapshots(names, RetentionPolicy{Daily: 2, Weekly: 1, Monthly: 1, Yearly: 1})
	want := map[string]bool{"20250804T020000Z": true, "20250803T020000Z": true, "20250801T020000Z": true, "20250101T020000Z": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("retained = %v; want %v", got, want)
	}
}

type cleanupBackend struct {
	backend
	complete  bool
	markerErr error
	deleted   []string
}

func (*cleanupBackend) directories(context.Context) ([]string, error) {
	return []string{"20250804T020000Z", "20250803T020000Z"}, nil
}

func (b *cleanupBackend) hasMarker(context.Context, string) (bool, error) {
	return b.complete, b.markerErr
}

func (b *cleanupBackend) deleteSnapshot(_ context.Context, name string) error {
	b.deleted = append(b.deleted, name)
	return nil
}

func TestCleanupPreservesSnapshotIfMarkerCannotBeChecked(t *testing.T) {
	log := newLogger(Options{Stdout: io.Discard, Stderr: io.Discard})
	journal := filepath.Join(t.TempDir(), "journal")
	const snapshot = "20250804T020000Z"
	writeFixture(t, journal, snapshot+"\n")
	b := &cleanupBackend{markerErr: errors.New("cannot verify remote marker")}

	if err := cleanupPending(context.Background(), b, journal, log); !errors.Is(err, b.markerErr) {
		t.Fatalf("cleanup did not report marker error: %v", err)
	}
	assertContents(t, journal, snapshot+"\n")
	if len(b.deleted) != 0 {
		t.Fatalf("cleanup attempted unsafe deletion: %v", b.deleted)
	}

	b.markerErr = nil
	b.complete = true
	if err := cleanupPending(context.Background(), b, journal, log); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, fs.ErrNotExist) || len(b.deleted) != 0 {
		t.Fatalf("completed snapshot should be kept and journal cleared: %v, %v", b.deleted, err)
	}
}

func TestSnapshotIncludesLiveWALWithoutSidecars(t *testing.T) {
	ctx := context.Background()
	state := t.TempDir()
	source := filepath.Join(state, "shares.db")
	for _, name := range []string{"shares.db", "configuration.db"} {
		db, err := sql.Open("sqlite", filepath.Join(state, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE saved(key TEXT); INSERT INTO saved VALUES ('from WAL');"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(state, name+"-wal")); err != nil {
			t.Fatalf("fixture lacks a live WAL: %v", err)
		}
	}
	for _, name := range []string{"ordinary", "documents/cache", "backup-pending/journal", "agent-tokens.db", "agent-tokens.db-wal"} {
		writeFixture(t, filepath.Join(state, name), "fixture")
	}
	log := newLogger(Options{Stdout: io.Discard, Stderr: io.Discard})
	temp, stage, err := stageState(ctx, state, Options{StateDBPath: source}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(temp)
	for _, name := range []string{"shares.db", "configuration.db"} {
		db, err := sql.Open("sqlite", sqliteURI(filepath.Join(stage, name), "mode=ro&immutable=1"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var got string
		if err := db.QueryRow("SELECT key FROM saved").Scan(&got); err != nil || got != "from WAL" {
			t.Fatalf("snapshot of %s does not contain live WAL data: %q, %v", name, got, err)
		}
	}
	for _, name := range []string{"documents", "backup-pending", "agent-tokens.db", "agent-tokens.db-wal", "shares.db-wal", "shares.db-shm", "configuration.db-wal", "configuration.db-shm"} {
		if _, err := os.Stat(filepath.Join(stage, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("excluded path %q unexpectedly exists: %v", name, err)
		}
	}
	assertContents(t, filepath.Join(stage, "ordinary"), "fixture")
}

func TestArchiveCompatibilityAndRestore(t *testing.T) {
	requireCommand(t, "7z")
	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "Group A")
	archive := filepath.Join(root, "Group A.7z")
	writeFixture(t, filepath.Join(source, "first.txt"), "Group data")
	writeFixture(t, filepath.Join(source, "second.txt"), "Group archive data")
	writeFixture(t, filepath.Join(source, "~$ignored.docx"), "Office lock")
	writeFixture(t, filepath.Join(source, ".trash", "hidden.txt"), "Retained trash")
	log := newLogger(Options{Stdout: io.Discard, Stderr: io.Discard})
	created, err := makeArchive(ctx, source, archive, pythonArchiveKey, log)
	if err != nil || !created {
		t.Fatalf("creating archive: %t %v", created, err)
	}
	listing := exec.CommandContext(ctx, "7z", "l", "-slt", "--", archive)
	listing.Stdin = strings.NewReader(pythonArchiveKey + "\n")
	data, err := listing.CombinedOutput()
	if err != nil || !bytes.Contains(data, []byte("Solid = -")) || !bytes.Contains(data, []byte("Encrypted = +")) {
		t.Fatalf("not an encrypted non-solid archive: %v\n%s", err, data)
	}
	wrong := filepath.Join(root, "wrong")
	if err := Restore(ctx, archive, wrong, "incorrect"); err == nil {
		t.Fatal("incorrect password was accepted; archive headers must be encrypted")
	}
	output := filepath.Join(root, "recovery")
	if err := Restore(ctx, archive, output, pythonArchiveKey); err != nil {
		t.Fatal(err)
	}
	assertContents(t, filepath.Join(output, "Group A", "first.txt"), "Group data")
	for _, name := range []string{"~$ignored.docx", ".trash"} {
		if _, err := os.Stat(filepath.Join(output, "Group A", name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("recovery contains excluded path %q: %v", name, err)
		}
	}
	if err := Restore(ctx, archive, output, pythonArchiveKey); err == nil {
		t.Fatal("restored into an existing directory")
	}
	// Legacy worker's exact creation flags, including its raw password and
	// source argument, must remain readable.
	legacy := filepath.Join(root, "legacy.7z")
	command := exec.CommandContext(ctx, "7z", "a", "-t7z", "-m0=lzma2", "-mx=5", "-mmt=on", "-ms=off", "-mhe=on", "-p", "-snl", "-xr!.trash", "-xr!~$*", "-y", legacy, "--", "Group A")
	command.Dir = root
	command.Stdin = strings.NewReader("legacy key\n")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("make legacy fixture: %v %s", err, output)
	}
	if err := Restore(ctx, legacy, filepath.Join(root, "legacy-recovery"), "legacy key"); err != nil {
		t.Fatal(err)
	}
	assertContents(t, filepath.Join(root, "legacy-recovery", "Group A", "first.txt"), "Group data")
}

func TestMissingArchiveWarningsAreStrict(t *testing.T) {
	if !onlyMissingWarnings("\nWARNING: errno=2: No such file or directory\none.txt\nWARNING: No such file or directory\ntwo.txt\n") {
		t.Error("did not tolerate a sequence of missing-file warnings")
	}
	for _, warning := range []string{"", "WARNING: No such file or directory", "WARNING: Permission denied\none.txt", "WARNING: No such file or directory\none.txt\nWARNING: Permission denied\ntwo.txt"} {
		if onlyMissingWarnings(warning) {
			t.Errorf("accepted unsafe warning %q", warning)
		}
	}
}

func TestProgressRecordAndLimit(t *testing.T) {
	var console bytes.Buffer
	log := newLogger(Options{Stdout: &console, Stderr: io.Discard})
	status := newStatus("", "rsync://redacted", "manual", log)
	p := &transferProgress{source: Source{t.TempDir(), "data/private"}, total: 20 << 20, sourceSize: 20 << 20, interval: time.Second, status: status, log: log}
	p.resetAttempt()
	output := &progressOutput{name: "rclone", observe: p.observe}
	for i := range 13 {
		_, _ = output.Write([]byte("\x1b[2K* report-" + string(rune('A'+i)) + ".txt: 50% /1 MiB, 5 MiB/s\r\n"))
	}
	p.report(time.Now(), true)
	active := status.data["activeFiles"].([]fileProgress)
	if len(active) != 12 || active[0].Path != "report-M.txt" || active[0].Transferred != 512<<10 {
		t.Fatalf("unexpected active file progress: %v", active)
	}
	if !strings.Contains(console.String(), "Total upload progress") {
		t.Fatalf("progress logs missing: %s", console.String())
	}
}

func requireCommand(t *testing.T, program string) {
	t.Helper()
	if _, err := exec.LookPath(program); err != nil {
		t.Skipf("%s not installed", program)
	}
}

func writeFixture(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertContents(t *testing.T, path, text string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != text {
		t.Fatalf("%s: got %q, %v; want %q", path, data, err, text)
	}
}
