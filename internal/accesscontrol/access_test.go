package accesscontrol

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/sambaacl"
	"github.com/stuck-lehnert/domainshare/internal/trash"
	_ "modernc.org/sqlite"
)

const (
	testID = "11111111-2222-4333-8444-555555555555"
	admin  = "S-1-5-21-1-2-3-512"
	alice  = "S-1-5-21-1-2-3-1000"
	bob    = "S-1-5-21-1-2-3-1001"
	system = "S-1-5-21-1-2-3-1002"
)

type aclCall struct {
	file os.FileInfo
	name string
	sddl string
}

type fakeACL struct {
	calls []aclCall
	fail  func(string) bool
}

func (a *fakeACL) SetACLFD(_ context.Context, file *os.File, d sambaacl.Descriptor) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	a.calls = append(a.calls, aclCall{file: info, name: file.Name(), sddl: d.SDDL()})
	if a.fail != nil && a.fail(file.Name()) {
		return errors.New("synthetic ACL failure")
	}
	return nil
}

func testService(t *testing.T) (*Service, *fakeACL) {
	t.Helper()
	tmp := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(tmp, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	acl := &fakeACL{}
	service, err := New(db, Config{
		GroupRoot: filepath.Join(tmp, "groups", "data"), ArchiveRoot: filepath.Join(tmp, "groups", "archive"),
		LockPath: filepath.Join(tmp, "reconcile.lock"), AdminSID: admin, ACLWriter: acl,
		CloseDataConnections: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, acl
}

func execTest(t *testing.T, s *Service, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func ensure(t *testing.T, s *Service) {
	t.Helper()
	if err := s.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func seedFolder(t *testing.T, s *Service, name, path string) {
	t.Helper()
	stem := "FS_" + name
	execTest(t, s, `INSERT INTO shares VALUES(?,?,?,?,?,?,1,'')`, testID, stem, name, path, timestamp(), timestamp())
}

func writeFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaUpgradeKeepsDirectZeroAndMaximumGroupGrant(t *testing.T) {
	s, _ := testService(t)
	ensure(t, s)
	seedFolder(t, s, "Finance", filepath.Join(s.cfg.GroupRoot, "Finance"))
	execTest(t, s, `DROP TABLE folder_permissions;
		CREATE TABLE folder_permissions(folderId TEXT, kind TEXT CHECK(kind IN ('user','group')), principalId TEXT, level INTEGER);
		CREATE TABLE access_groups(id TEXT PRIMARY KEY);
		CREATE TABLE access_members(groupId TEXT, userSid TEXT);
		INSERT INTO access_groups VALUES ('low'),('high');`)
	execTest(t, s, `INSERT INTO folder_permissions VALUES(?,'user',?,0),(?,'group','low',1),(?,'group','high',3)`, testID, alice, testID, testID)
	execTest(t, s, `INSERT INTO access_members VALUES('low',?),('high',?),('low',?),('high',?)`, alice, alice, bob, bob)
	ensure(t, s)
	ensure(t, s)
	levels, err := s.EffectiveLevels(t.Context(), testID)
	if err != nil || !reflect.DeepEqual(levels, map[string]int{alice: 0, bob: 3}) {
		t.Fatalf("flattened permissions: %v, %v", levels, err)
	}
	var audits int
	if err := s.db.QueryRow("SELECT count(*) FROM access_changes WHERE action='migrate-individual-permissions'").Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("migration history: %d %v", audits, err)
	}
}

func TestLegacyImportNestedPrimaryAndLayoutIsOneTime(t *testing.T) {
	s, _ := testService(t)
	ensure(t, s)
	legacy := filepath.Join(filepath.Dir(s.cfg.GroupRoot), testID)
	writeFixture(t, filepath.Join(legacy, "old.txt"))
	writeFixture(t, filepath.Join(s.cfg.GroupRoot, "Finance", "untracked.txt"))
	seedFolder(t, s, "Finance", legacy)
	reads := 0
	s.cfg.ReadDirectory = func(_ context.Context, groups bool) (map[string]Principal, map[string]Principal, error) {
		reads++
		if !groups {
			t.Fatal("legacy snapshot requires nested group resolution")
		}
		return map[string]Principal{
			alice:  {SAM: "Alice", Name: "Alice", DN: "alice", PrimaryRID: 111},
			bob:    {SAM: "Bob", Name: "Bob", DN: "bob", PrimaryRID: 222},
			system: {SAM: "MSOL_hidden", DN: "system", PrimaryRID: 111},
		}, map[string]Principal{
			"finance": {SID: "S-1-5-21-1-2-3-111", SAM: "fs_finance", DN: "finance", Members: []string{"nested", "system"}},
			"nested":  {SID: "S-1-5-21-1-2-3-222", SAM: "nested", DN: "nested", Members: []string{"finance"}},
		}, nil
	}
	for range 2 {
		if err := s.WithMutation(t.Context(), func(m *Mutation) error { return m.Migrate(t.Context()) }); err != nil {
			t.Fatal(err)
		}
	}
	assertExists(t, filepath.Join(s.cfg.GroupRoot, "Finance_11111111", "old.txt"))
	assertExists(t, filepath.Join(s.cfg.GroupRoot, "Finance", "untracked.txt"))
	levels, err := s.EffectiveLevels(t.Context(), testID)
	if err != nil || reads != 1 || !reflect.DeepEqual(levels, map[string]int{alice: 3, bob: 3}) {
		t.Fatalf("legacy snapshot: %v, %v, reads=%d", levels, err, reads)
	}
	report, err := s.Report(t.Context())
	if err != nil || len(report.Groups) != 2 || report.Groups[0].UserCount != 0 || report.Groups[1].UserCount != 2 {
		t.Fatalf("managed report: %+v, %v", report, err)
	}
}

func TestLegacyLayoutJournalResumesAfterRename(t *testing.T) {
	s, _ := testService(t)
	ensure(t, s)
	source := filepath.Join(filepath.Dir(s.cfg.GroupRoot), testID)
	dest := filepath.Join(s.cfg.GroupRoot, "Finance")
	writeFixture(t, filepath.Join(dest, "preserved.txt"))
	seedFolder(t, s, "Finance", source)
	// Legacy JSON shape, as if Python died after rename but before SQLite commit.
	details, err := json.Marshal(layoutMove{FolderID: testID, Source: source, Destination: dest, Name: "Finance"})
	if err != nil {
		t.Fatal(err)
	}
	execTest(t, s, "INSERT INTO access_settings VALUES('managed','1'),('pendingFolderLayout',?)", string(details))
	if err := s.WithMutation(t.Context(), func(m *Mutation) error { return m.Migrate(t.Context()) }); err != nil {
		t.Fatal(err)
	}
	row, err := findFolder(t.Context(), s.db, testID)
	if err != nil || row.Path != dest {
		t.Fatalf("layout was not resumed: %+v, %v", row, err)
	}
	assertExists(t, filepath.Join(dest, "preserved.txt"))
	_, pending, err := readSetting(t.Context(), s.db, "pendingFolderLayout")
	if err != nil || pending {
		t.Fatalf("layout marker still pending: %v, %v", pending, err)
	}
}

func TestAdminLifecyclePinnedACLsAndCloseMarker(t *testing.T) {
	s, acl := testService(t)
	users := map[string]Principal{alice: {SAM: "Alice", Name: "Alice"}, system: {SAM: "krbtgt"}}
	apply := func(body map[string]any) (Snapshot, error) { return s.ApplyChange(t.Context(), body, "admin", users) }
	snapshot, err := apply(map[string]any{"action": "create-folder", "name": "Finance"})
	if err != nil || !snapshot.Initialized || len(snapshot.Folders) != 1 {
		t.Fatalf("create-folder: %+v, %v", snapshot, err)
	}
	id := snapshot.Folders[0].ID
	file := filepath.Join(s.cfg.GroupRoot, "Finance", "sub", "invoice.txt")
	writeFixture(t, file)
	rules := func(sid string, level json.Number) map[string]any {
		return map[string]any{"action": "set-permissions", "id": id, "permissions": []any{
			map[string]any{"kind": "user", "principalId": sid, "level": level},
		}}
	}
	for _, body := range []map[string]any{rules(system, "1"), rules(alice, "1.0")} {
		var invalid Invalid
		if _, err := apply(body); !errors.As(err, &invalid) {
			t.Fatalf("invalid permission accepted: %v", err)
		}
	}
	acl.calls = nil
	if _, err := apply(rules(alice, "3")); err != nil {
		t.Fatal(err)
	}
	if len(acl.calls) != 4 || !strings.Contains(acl.calls[1].sddl, "(A;;0x001201ff;;;"+alice+")") ||
		!strings.Contains(acl.calls[3].sddl, "(A;;0x001301ff;;;"+alice+")") {
		t.Fatalf("unexpected top-level/child ACLs: %+v", acl.calls)
	}
	s.cfg.CloseDataConnections = func(context.Context) error { return errors.New("synthetic disconnect failure") }
	if _, err := apply(map[string]any{"action": "archive-folder", "id": id}); err == nil {
		t.Fatal("failed SMB disconnect reported success")
	}
	assertExists(t, filepath.Join(s.cfg.ArchiveRoot, "Finance", "sub", "invoice.txt"))
	_, pending, err := readSetting(t.Context(), s.db, disconnectKey)
	if err != nil || !pending {
		t.Fatalf("disconnect was not left pending: %v %v", pending, err)
	}
	s.cfg.CloseDataConnections = func(context.Context) error { return nil }
	if _, err := apply(map[string]any{"action": "restore-folder", "id": id}); err != nil {
		t.Fatal(err)
	}
	assertExists(t, file)
}

func TestInterruptedMoveRepairRetriesAndLockIsShared(t *testing.T) {
	s, acl := testService(t)
	ensure(t, s)
	from := filepath.Join(s.cfg.GroupRoot, "Finance")
	to := filepath.Join(s.cfg.ArchiveRoot, "Finance")
	writeFixture(t, filepath.Join(to, "fixture.txt"))
	if err := os.MkdirAll(s.cfg.GroupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	seedFolder(t, s, "Finance", from)
	intent, _ := json.Marshal(repairIntent{Move: []string{from, to}})
	execTest(t, s, `INSERT INTO access_settings VALUES('managed','1'),('pendingRepair',?)`, string(intent))
	acl.fail = func(string) bool { return true }
	recover := func(m *Mutation) error {
		var conflict Conflict
		if err := s.WithMutation(t.Context(), func(*Mutation) error { return nil }); !errors.As(err, &conflict) {
			t.Fatalf("shared lock could be acquired twice: %v", err)
		}
		return m.RecoverPending(t.Context())
	}
	if err := s.WithMutation(t.Context(), recover); err == nil {
		t.Fatal("expected failing ACL repair")
	}
	assertExists(t, filepath.Join(from, "fixture.txt"))
	_, pending, err := readSetting(t.Context(), s.db, repairKey)
	if err != nil || !pending {
		t.Fatalf("repair marker was lost: %v %v", pending, err)
	}
	acl.fail = nil
	if err := s.WithMutation(t.Context(), recover); err != nil {
		t.Fatal(err)
	}
	_, pending, err = readSetting(t.Context(), s.db, repairKey)
	if err != nil || pending {
		t.Fatalf("repair marker was not cleared: %v %v", pending, err)
	}
}

func TestRestoreOnlyUsesValidatedBorrowedInodes(t *testing.T) {
	s, acl := testService(t)
	ensure(t, s)
	top := filepath.Join(s.cfg.GroupRoot, "Finance")
	sub := filepath.Join(top, "sub")
	file := filepath.Join(filepath.Dir(s.cfg.GroupRoot), "trashed")
	writeFixture(t, filepath.Join(sub, "existing"))
	writeFixture(t, file)
	seedFolder(t, s, "Finance", top)
	execTest(t, s, `INSERT INTO folder_permissions VALUES(?,'user',?,3)`, testID, alice)
	open := func(path string) *os.File {
		fd, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fd.Close() })
		return fd
	}
	fdTop, fdSub, fdFile := open(top), open(sub), open(file)
	target := trash.DataRestoreTarget{RelativePath: "Finance/sub/restored", Source: fdFile, Directories: []*os.File{fdTop, fdSub}}
	if err := s.WithMutation(t.Context(), func(m *Mutation) error { return m.PrepareDataRestore(t.Context(), target) }); err != nil {
		t.Fatal(err)
	}
	info, err := fdFile.Stat()
	if err != nil || len(acl.calls) != 3 || !os.SameFile(info, acl.calls[2].file) {
		t.Fatalf("restore ACL did not use pinned source: %+v, %v", acl.calls, err)
	}
	if err := os.Rename(sub, sub+".renamed"); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(sub, "decoy"))
	acl.calls = nil
	if err := s.WithMutation(t.Context(), func(m *Mutation) error { return m.PrepareDataRestore(t.Context(), target) }); err == nil || len(acl.calls) != 0 {
		t.Fatalf("replaced restore directory was not rejected: %v, %+v", err, acl.calls)
	}
}

func TestACLWalkRejectsSymlinkAndKeepsRetryMarker(t *testing.T) {
	s, acl := testService(t)
	ensure(t, s)
	folder := filepath.Join(s.cfg.GroupRoot, "Finance")
	outside := filepath.Join(filepath.Dir(s.cfg.GroupRoot), "unmanaged-file")
	writeFixture(t, outside)
	writeFixture(t, filepath.Join(folder, "ordinary-file"))
	link := filepath.Join(folder, "linked-file")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	seedFolder(t, s, "Finance", folder)

	if err := s.WithMutation(t.Context(), func(m *Mutation) error { return m.SyncPermissions(t.Context(), true) }); err == nil {
		t.Fatal("ACL rewrite followed unsafe entry")
	}
	for _, call := range acl.calls {
		if call.name == link || call.name == outside {
			t.Fatalf("unexpected ACL write to unmanaged symlink target: %+v", call)
		}
	}
	_, pending, err := readSetting(t.Context(), s.db, repairKey)
	if err != nil || !pending {
		t.Fatalf("failed sync must retain recovery journal: %v, %v", pending, err)
	}
	row, err := findFolder(t.Context(), s.db, testID)
	if err != nil || row.Signature != "" {
		t.Fatalf("failed sync published a signature: %+v, %v", row, err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := s.WithMutation(t.Context(), func(m *Mutation) error { return m.RecoverPending(t.Context()) }); err != nil {
		t.Fatal(err)
	}
	row, err = findFolder(t.Context(), s.db, testID)
	if err != nil || row.Signature == "" {
		t.Fatalf("successful recovery did not publish signature: %+v, %v", row, err)
	}
}
