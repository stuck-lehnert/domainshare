package trash

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var testTime = time.Date(2025, 8, 10, 12, 0, 0, 123, time.UTC)

func testService(t *testing.T) *Service {
	t.Helper()
	root := t.TempDir()
	s, err := New(Options{
		DataRoot: filepath.Join(root, "data"), PrivateRoot: filepath.Join(root, "private"),
		FSLogixRoot: filepath.Join(root, "profiles"), Now: func() time.Time { return testTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureRoots(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func deposit(t *testing.T, s *Service, share, relative, value string, mtime time.Time) (string, string) {
	t.Helper()
	path := filepath.Join(s.rootFor(share), Directory, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	id, err := EncodeItemID(share, relative)
	if err != nil {
		t.Fatal(err)
	}
	return path, id
}

func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected absent path %q: %v", path, err)
	}
}

func contents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if string(data) != want || err != nil {
		t.Fatalf("read %q: %q, %v; want %q", path, data, err, want)
	}
}

func TestListDownloadAndRestoreVersionedFile(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	origin, id := deposit(t, s, "Private", "alice/alice/Copy #2 of Straße.xlsx", "spreadsheet", testTime.Add(-time.Hour))
	desiredID := base64.RawURLEncoding.EncodeToString([]byte("Private\x00alice/alice/Copy #2 of Straße.xlsx"))
	if id != desiredID {
		t.Fatalf("ID: %q, want %q", id, desiredID)
	}
	_, _ = deposit(t, s, "Data", "alice/Group/old.xlsx", "expired", testTime.Add(-8*24*time.Hour))
	_, _ = deposit(t, s, "FSLogix", "alice/another.vhd", "unrelated", testTime)
	result, err := s.List(ctx, ListOptions{Share: "private", Path: " STRASSE "})
	if err != nil || result.Matched != 1 || len(result.Items) != 1 {
		t.Fatalf("list = %+v; %v", result, err)
	}
	item := result.Items[0]
	if item.Path != "alice/Straße.xlsx" || item.DeletedBy != "alice" || item.Size != 11 ||
		item.DeletedAt != "2025-08-10T11:00:00+00:00" || item.ExpiresAt != "2025-08-17T11:00:00+00:00" {
		t.Fatalf("unexpected item: %+v", item)
	}
	paged, err := s.List(ctx, ListOptions{Limit: 1})
	if err != nil || len(paged.Items) != 1 || paged.Items[0].Share != "FSLogix" || paged.Matched != 2 || !paged.Truncated {
		t.Fatalf("unexpected result ordering or page metadata: %+v, %v", paged, err)
	}
	f, item, err := s.OpenDownload(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil || string(data) != "spreadsheet" || item.Name != "Straße.xlsx" {
		t.Fatalf("download: %q, %+v, %v", data, item, err)
	}
	restored, err := s.Restore(ctx, id, nil)
	if err != nil || restored != (RestoreResult{true, "Private", "alice/Straße.xlsx"}) {
		t.Fatalf("restore: %+v, %v", restored, err)
	}
	destination := filepath.Join(s.rootFor("Private"), "alice", "Straße.xlsx")
	contents(t, destination, "spreadsheet")
	if after, err := os.Stat(destination); err != nil || !os.SameFile(info, after) {
		t.Fatalf("restore did not preserve the inode: %v", err)
	}
	absent(t, origin)
	absent(t, filepath.Join(s.rootFor("Private"), Directory, "alice"))
}

func TestDataRestoreFailsClosedAndRollsBack(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	origin, id := deposit(t, s, "Data", "alice/Finance/Existing/new/deep/report.txt", "deleted", testTime)
	parent := filepath.Join(s.rootFor("Data"), "Finance", "Existing")
	destination := filepath.Join(parent, "new", "deep", "report.txt")
	if _, err := s.Restore(ctx, id, nil); !errors.Is(err, ErrDataACLRequired) {
		t.Fatalf("Data restore without ACL = %v", err)
	}
	called := 0
	denied := errors.New("acl denied")
	failedACL := func(_ context.Context, target DataRestoreTarget) error {
		called++
		if target.RelativePath != "Finance/Existing/new/deep/report.txt" || len(target.Directories) != 4 {
			t.Fatalf("unexpected ACL target: %+v", target)
		}
		data, err := io.ReadAll(target.Source)
		if err != nil || string(data) != "deleted" {
			t.Fatalf("source descriptor: %s %v", data, err)
		}
		newDirectory, err := target.Directories[2].Stat()
		if err != nil || newDirectory.Mode().Perm() != 0700 {
			t.Fatalf("new Data parent is not private before ACL preparation: %v, %v", newDirectory, err)
		}
		absent(t, destination)
		return denied
	}
	if _, err := s.Restore(ctx, id, failedACL); !errors.Is(err, fs.ErrNotExist) || called != 0 {
		t.Fatalf("Data restore created an unmanaged group or ran its callback: %v", err)
	}
	absent(t, filepath.Join(s.rootFor("Data"), "Finance"))
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(ctx, id, failedACL); !errors.Is(err, denied) || called != 1 {
		t.Fatalf("Data restore propagated unexpected result: %v, called %d", err, called)
	}
	contents(t, origin, "deleted")
	absent(t, filepath.Join(parent, "new"))
	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("existing destination ancestor was removed: %v", err)
	}
	_, err := s.Restore(ctx, id, func(_ context.Context, target DataRestoreTarget) error {
		absent(t, destination)
		return target.Source.Chmod(0640)
	})
	if err != nil {
		t.Fatal(err)
	}
	contents(t, destination, "deleted")
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("ACL-prepared inode was not published: %v %v", info, err)
	}
}

func TestRestoreDoesNotReplaceConcurrentFile(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	origin, id := deposit(t, s, "Data", "alice/Finance/new/report.txt", "deleted", testTime)
	group := filepath.Join(s.rootFor("Data"), "Finance")
	if err := os.Mkdir(group, 0700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(group, "new", "report.txt")
	_, err := s.Restore(ctx, id, func(_ context.Context, _ DataRestoreTarget) error {
		return os.WriteFile(destination, []byte("current"), 0600)
	})
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("concurrent destination was not reported as conflict: %v", err)
	}
	contents(t, destination, "current")
	contents(t, origin, "deleted")
}

func TestRollbackConflictPreservesStagedInode(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	origin, id := deposit(t, s, "Data", "alice/Finance/report.txt", "original", testTime)
	group := filepath.Join(s.rootFor("Data"), "Finance")
	if err := os.Mkdir(group, 0700); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("ACL backend failed")
	_, err := s.Restore(ctx, id, func(_ context.Context, _ DataRestoreTarget) error {
		deposit(t, s, "Data", "alice/Finance/report.txt", "new recycle item", testTime)
		return denied
	})
	if !errors.Is(err, denied) || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("rollback conflict was not reported: %v", err)
	}
	absent(t, filepath.Join(group, "report.txt"))
	contents(t, origin, "new recycle item")
	bin := filepath.Join(s.rootFor("Data"), Directory)
	entries, err := os.ReadDir(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if reservedStage(entry.Name()) {
			stage := filepath.Join(bin, entry.Name())
			contents(t, filepath.Join(stage, "item"), "original")
			contents(t, filepath.Join(stage, "origin.json"), "{\"share\":\"Data\",\"trashRelativePath\":\"alice/Finance/report.txt\"}\n")
			if _, err := s.Cleanup(ctx, testTime.Add(8*24*time.Hour)); err != nil {
				t.Fatal(err)
			}
			contents(t, filepath.Join(stage, "item"), "original")
			return
		}
	}
	t.Fatal("failed rollback discarded the original inode")
}

func TestCleanupExpiryAndSymlinks(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	old, oldID := deposit(t, s, "FSLogix", "alice/old.vhd", "old", testTime.Add(-8*24*time.Hour))
	recent, _ := deposit(t, s, "FSLogix", "alice/recent.vhd", "recent", testTime.Add(-7*24*time.Hour))
	lock, lockID := deposit(t, s, "Data", "alice/Finance/Copy #3 of ~$lock", "lock", testTime)
	temporary, _ := deposit(t, s, "Data", "alice/Finance/Copy #٢ of TRANSIENT.TMP", "temp", testTime)
	outside := t.TempDir()
	protected := filepath.Join(outside, "protected")
	if err := os.WriteFile(protected, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	stale := testTime.Add(-8 * 24 * time.Hour)
	link := filepath.Join(filepath.Dir(old), "linked-dir")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	times := []unix.Timespec{unix.NsecToTimespec(stale.UnixNano()), unix.NsecToTimespec(stale.UnixNano())}
	if err := unix.UtimesNanoAt(unix.AT_FDCWD, link, times, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{oldID, lockID} {
		if file, _, err := s.OpenDownload(ctx, id); !errors.Is(err, fs.ErrNotExist) || file != nil {
			t.Fatalf("download opened an expired or excluded item: %v", err)
		}
	}
	result, err := s.Cleanup(ctx, testTime)
	if err != nil || result != (CleanupResult{4, 11}) {
		t.Fatalf("cleanup = %+v, %v", result, err)
	}
	for _, path := range []string{old, lock, temporary, link} {
		absent(t, path)
	}
	contents(t, recent, "recent")
	contents(t, protected, "untouched")
	status, err := json.Marshal(result)
	if err != nil || string(status) != `{"removed":4,"removedBytes":11}` {
		t.Fatalf("cleanup JSON: %s, %v", status, err)
	}
}

func TestRejectsEscapesAndDirectorySymlinks(t *testing.T) {
	s := testService(t)
	ctx := context.Background()
	for _, relative := range []string{"../outside", "alice//broken", "alice/../escape", "/absolute", `\absolute`} {
		raw := base64.RawURLEncoding.EncodeToString([]byte("Data\x00" + relative))
		if _, _, err := DecodeItemID(raw); err == nil {
			t.Errorf("decoded invalid path %q", relative)
		}
	}
	origin, id := deposit(t, s, "Private", "alice/linked/report.txt", "deleted", testTime)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(s.rootFor("Private"), "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(ctx, id, nil); err == nil {
		t.Fatal("restore followed destination symlink")
	}
	contents(t, origin, "deleted")
	absent(t, filepath.Join(outside, "report.txt"))
	fileLink := filepath.Join(filepath.Dir(origin), "link.txt")
	if err := os.Symlink(origin, fileLink); err != nil {
		t.Fatal(err)
	}
	linkID, _ := EncodeItemID("Private", "alice/linked/link.txt")
	var invalid InvalidError
	if _, _, err := s.OpenDownload(ctx, linkID); !errors.As(err, &invalid) {
		t.Fatalf("download did not reject file symlink: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(s.rootFor("Private"), Directory))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stagePrefix) {
			t.Fatalf("failed restores left an unexplained stage: %s", entry.Name())
		}
	}
}
