package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunRsyncEncryptedAndCleanup(t *testing.T) {
	requireCommand(t, "rsync")
	requireCommand(t, "7z")
	destination, remote := localRsync(t)
	state := t.TempDir()
	source := filepath.Join(t.TempDir(), "private")
	writeFixture(t, filepath.Join(source, "example.txt"), "real payload")
	writeFixture(t, filepath.Join(source, ".trash", "old"), "trash")
	writeFixture(t, filepath.Join(source, "~$office.txt"), "lock")
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Destination: destination, StateRoot: state,
		Sources: []Source{{source, "data/private"}}, Retention: RetentionPolicy{Daily: 1},
		Encrypted: true, Password: key.Password, KeyID: key.KeyID, KeyFormat: key.Format, Namespace: "keys/" + key.KeyID,
		ProgressInterval: time.Millisecond, ArchiveTemp: t.TempDir(), Trigger: "web",
		StatusPath: filepath.Join(state, "status.json"), LogPath: filepath.Join(state, "backup.log"),
		Stdout: io.Discard, Stderr: io.Discard,
	}
	d, err := parseDestination(destination, options.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	journal := journalPath(state, d)
	root := filepath.Join(remote, options.Namespace, "snapshots")
	const partial = "20250102T000000Z"
	const completed = "20250101T000000Z"
	const untracked = "20250103T000000Z"
	writeFixture(t, journal, partial+"\n")
	writeFixture(t, filepath.Join(root, partial, "partial.txt"), "interrupted")
	writeFixture(t, filepath.Join(root, completed, ".backup_complete"), "prior successful backup")
	writeFixture(t, filepath.Join(root, untracked, "other.txt"), "not tracked by the journal")
	writeFixture(t, filepath.Join(remote, "snapshots", completed, ".backup_complete"), "old key generation")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Run(ctx, options); err != nil {
		log, _ := os.ReadFile(options.LogPath)
		t.Fatalf("backup failed: %v\n%s", err, log)
	}
	for _, name := range []string{journal, filepath.Join(root, partial), filepath.Join(root, completed)} {
		if _, err := os.Stat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("expected %s to be gone: %v", name, err)
		}
	}
	assertContents(t, filepath.Join(root, untracked, "other.txt"), "not tracked by the journal")
	assertContents(t, filepath.Join(remote, "snapshots", completed, ".backup_complete"), "old key generation")

	var status struct {
		State       string `json:"state"`
		Snapshot    string `json:"snapshot"`
		WorkerPID   *int   `json:"workerPid"`
		Percent     int    `json:"percent"`
		Trigger     string `json:"trigger"`
		Transferred int    `json:"transferredBytes"`
	}
	statusData, err := os.ReadFile(options.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(statusData, &status); err != nil {
		t.Fatal(err)
	}
	if status.State != "completed" || status.WorkerPID != nil || status.Percent != 100 || status.Trigger != "web" || status.Transferred <= 0 || !validSnapshot(status.Snapshot) {
		t.Fatalf("unexpected status: %s", statusData)
	}
	archiveRoot := filepath.Join(root, status.Snapshot, "encrypted")
	if _, err := os.Stat(filepath.Join(root, status.Snapshot, ".backup_complete")); err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Format    string
		KeyID     string
		Encrypted bool
		Archives  []string
	}
	data, err := os.ReadFile(filepath.Join(archiveRoot, "backup-format.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &metadata); err != nil || !metadata.Encrypted || metadata.KeyID != key.KeyID || metadata.Format != KeyFormat || len(metadata.Archives) != 1 || metadata.Archives[0] != "data-private.7z" {
		t.Fatalf("unexpected backup format: %s, %v", data, err)
	}
	password, err := ArchiveKey(key.Phrase)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "recovery")
	if err := Restore(ctx, filepath.Join(archiveRoot, metadata.Archives[0]), output, password); err != nil {
		t.Fatal(err)
	}
	assertContents(t, filepath.Join(output, "private", "example.txt"), "real payload")
	logData, err := os.ReadFile(options.LogPath)
	if err != nil || !strings.Contains(string(logData), "Total upload progress") || !strings.Contains(string(logData), "Removing incomplete snapshot") || strings.Contains(string(logData), password) {
		t.Fatalf("unexpected log: %v\n%s", err, logData)
	}
}

func TestRunHonorsExistingLock(t *testing.T) {
	state := t.TempDir()
	file, err := os.Create(LockPath(state))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	options := Options{Destination: "not even a valid URL", StateRoot: state, StatusPath: filepath.Join(state, "status"), Stdout: io.Discard}
	if err := Run(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(options.StatusPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("locked backup touched status file: %v", err)
	}
}

func TestRunAuthenticatedWebDAV(t *testing.T) {
	requireCommand(t, "rclone")
	addr := reserveLoopback(t)
	remote := t.TempDir()
	password := "not a production pass:@!"
	cmd := exec.Command("rclone", "serve", "webdav", remote, "--addr", addr, "--user", "backup-user", "--pass", password)
	startLocalDaemon(t, cmd, addr)

	src := filepath.Join(t.TempDir(), "private")
	writeFixture(t, filepath.Join(src, "example.txt"), "WebDAV payload")
	writeFixture(t, filepath.Join(src, ".trash/hidden.txt"), "Retained trash")
	writeFixture(t, filepath.Join(src, "~$ignored.docx"), "Office lock")
	state := t.TempDir()
	destination := (&url.URL{Scheme: "http", Host: addr, User: url.UserPassword("backup-user", password)}).String()
	options := Options{Destination: destination, StateRoot: state, Namespace: "plain", Sources: []Source{{src, "data/private"}},
		Retention: RetentionPolicy{Daily: 1}, StatusPath: filepath.Join(state, "status.json"), Stdout: io.Discard, Stderr: io.Discard}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := Run(ctx, options); err != nil {
		t.Fatal(err)
	}
	snapshotsRoot := filepath.Join(remote, "plain", "snapshots")
	entries, err := os.ReadDir(snapshotsRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one WebDAV snapshot: %v, %v", entries, err)
	}
	backupRoot := filepath.Join(snapshotsRoot, entries[0].Name())
	assertContents(t, filepath.Join(backupRoot, "data/private/example.txt"), "WebDAV payload")
	for _, name := range []string{".trash", "~$ignored.docx"} {
		if _, err := os.Stat(filepath.Join(backupRoot, "data/private", name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("excluded %s was uploaded: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(backupRoot, ".backup_complete")); err != nil {
		t.Fatal(err)
	}
	status, err := os.ReadFile(options.StatusPath)
	if err != nil || strings.Contains(string(status), password) || !strings.Contains(string(status), "backup-user:***@") {
		t.Fatalf("unexpected status redaction: %v, %s", err, status)
	}
}

func localRsync(t *testing.T) (string, string) {
	t.Helper()
	addr := reserveLoopback(t)
	_, port, _ := net.SplitHostPort(addr)
	dir := t.TempDir()
	remote := filepath.Join(dir, "remote")
	if err := os.Mkdir(remote, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "rsyncd.conf")
	identity := ""
	if os.Getuid() == 0 {
		identity = fmt.Sprintf("uid = %d\ngid = %d\n", os.Getuid(), os.Getgid())
	}
	writeFixture(t, config, fmt.Sprintf("use chroot = false\n%s[backup]\npath = %s\nread only = false\n", identity, remote))
	cmd := exec.Command("rsync", "--daemon", "--no-detach", "--address=127.0.0.1", "--port="+port, "--config="+config)
	startLocalDaemon(t, cmd, addr)
	return "rsync://" + addr + "/backup", remote
}

func reserveLoopback(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	defer l.Close()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))
}

func startLocalDaemon(t *testing.T, cmd *exec.Cmd, addr string) {
	t.Helper()
	log, err := os.Create(filepath.Join(t.TempDir(), "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for range 100 {
		conn, err := net.DialTimeout("tcp", addr, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, _ := os.ReadFile(log.Name())
	t.Fatalf("local test daemon did not listen: %s", data)
}
