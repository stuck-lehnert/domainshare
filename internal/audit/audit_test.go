package audit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

func initTestStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()
	store, err := NewStore(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func checkCount(t *testing.T, got int, err error, want int) {
	t.Helper()
	if err != nil || got != want {
		t.Fatalf("got (%d, %v), want (%d, nil)", got, err, want)
	}
}

func mustAppend(t *testing.T, s *Store, events []Event, want int) {
	t.Helper()
	appended, err := s.AppendBatch(t.Context(), events, nil, nil)
	checkCount(t, appended, err, want)
}

func mustSQL(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The golden responses were captured from app.audit_store.query_activity
// after feeding app.audit_collector the same Samba log lines.
func TestPythonActivityFixture(t *testing.T) {
	t.Setenv("AUDIT_SKIP_USER_SUFFIXES", "_svc,_ServiceAcc")
	db, path := openTestDB(t)
	store := initTestStore(t, db)
	observed, err := time.Parse(time.RFC3339Nano, "2026-07-31T12:36:30.123+00:00")
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for _, line := range strings.Split(string(mustRead(t, "testdata/samba.log")), "\n") {
		if event, ok := ParseLine(line, "samba.log", observed); ok {
			events = append(events, event)
		}
	}
	if len(events) != 7 || events[0].Operation != "pread" || events[6].Path != "a file.txt|another file.txt" {
		t.Fatalf("unexpected Samba parser output: %+v", events)
	}
	mustAppend(t, store, events, 5)

	var cases []struct {
		Stream   string
		Params   map[string]string
		Response Activity
	}
	if err := json.Unmarshal(mustRead(t, "testdata/activity.json"), &cases); err != nil {
		t.Fatal(err)
	}
	// Prove that reading path pages does not depend on a working FTS table.
	mustSQL(t, db, "DROP TRIGGER audit_paths_insert; DROP TABLE audit_paths_fts")
	for _, fixture := range cases {
		params := make(url.Values)
		for key, value := range fixture.Params {
			params.Set(key, value)
		}
		t.Run(fixture.Stream+"/"+params.Encode(), func(t *testing.T) {
			actual, err := store.QueryActivity(t.Context(), observed, observed, params, fixture.Stream)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, fixture.Response) {
				want, _ := json.Marshal(fixture.Response)
				got, _ := json.Marshal(actual)
				t.Fatalf("expected %s\n     got %s", want, got)
			}
		})
	}

	summary, err := store.Summary(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Days != 1 || summary.Bytes == 0 || summary.Oldest == nil || summary.Newest == nil ||
		*summary.Oldest != "2026-07-31" || *summary.Newest != *summary.Oldest || !summary.Indexing.Ready {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestPythonFingerprintCompatibility(t *testing.T) {
	db, _ := openTestDB(t)
	store := initTestStore(t, db)
	lines := strings.Split(string(mustRead(t, "testdata/samba.log")), "\n")
	event, ok := ParseLine(lines[0], "samba.log", time.Now())
	if !ok {
		t.Fatal("could not parse fixture event")
	}
	const pythonFingerprint = "712479d6d1e4f9a3e6518d067babbc59"
	fp := fingerprint(event, event.Timestamp)
	if actual := hex.EncodeToString(fp[:]); actual != pythonFingerprint {
		t.Fatalf("fingerprint = %s, want Python's %s", actual, pythonFingerprint)
	}

	at, err := eventTime(event.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	// A recent Python-compatible persisted key suppresses a Go append.
	storedKey, _ := hex.DecodeString(pythonFingerprint)
	mustSQL(t, db, "INSERT INTO audit_event_dedup VALUES (?, ?, 42)", storedKey, at.Unix())
	t.Setenv("AUDIT_DEDUP_WINDOW_SECONDS", "3153600000")
	mustAppend(t, store, []Event{event}, 0)
	// Time representations and successes are normalized; failures remain separate.
	event.Timestamp, event.Result = "2026-07-31T13:34:56.987+01:00", "ok"
	mustAppend(t, store, []Event{event}, 0)
	event.Success, event.Result = false, "Permission denied"
	mustAppend(t, store, []Event{event, event}, 1)
	event.Result = "No such file"
	mustAppend(t, store, []Event{event}, 1)
}

func TestUpgradeAndChunkedBackfill(t *testing.T) {
	db, _ := openTestDB(t)
	store := initTestStore(t, db)
	now := time.Now().UTC().Truncate(time.Second)
	t.Setenv("AUDIT_DEDUP_WINDOW_SECONDS", "172800")
	stamp := now.Format(secondLayout)

	legacy := `INSERT INTO audit_events (occurred_at, occurred_second, ingested_at, user, account, client_ip,
		client, share, action, result, success, path, source) VALUES (?, ?, ?, 'DEV\Alice', 'alice', '192.0.2.5',
		'PC01', ?, 'write', 'OK', 1, ?, 'log.pc01')`
	mustSQL(t, db, legacy, stamp, now.Unix(), stamp, "FSLogix", "profile.vhdx")
	mustSQL(t, db, legacy, stamp, now.Unix(), stamp, "FSLogix", "profile.vhdx")
	mustSQL(t, db, legacy, stamp, now.Unix(), stamp, "Data", "document")
	mustSQL(t, db, `CREATE TABLE audit_read_dedup (fingerprint BLOB PRIMARY KEY);
		CREATE INDEX audit_events_time ON audit_events (occurred_second);
		ALTER TABLE audit_events DROP COLUMN path_id;
		ALTER TABLE audit_rollup_state DROP COLUMN policy_version;
		INSERT INTO audit_daily_totals VALUES (0, 'obsolete', 999);
		INSERT INTO audit_daily_counts VALUES (0, 'obsolete', 'old', 'Data', 'read', 'OK', 1, 999);`)
	store = initTestStore(t, db)

	page, err := store.QueryActivity(t.Context(), now, now, nil, StreamFSLogix)
	if err != nil || page.Indexing.Ready || page.Indexing.TotalEvents != 3 || len(page.Facets.Users) != 0 || len(page.Events) != 2 {
		t.Fatalf("unexpected pending backfill state: %+v, %v", page, err)
	}

	count, err := store.BackfillRollups(t.Context(), 1)
	checkCount(t, count, err, 1)
	live := Event{Timestamp: stamp, IngestedAt: stamp, User: "Carol", Share: "Data", Path: "document", Action: "write", Result: "OK", Success: true}
	mustAppend(t, store, []Event{live, live}, 2) // ordinary writes are not deduplicated
	count, err = store.BackfillRollups(t.Context(), 1)
	checkCount(t, count, err, 1)
	count, err = store.BackfillRollups(t.Context(), 1)
	checkCount(t, count, err, 1)
	count, err = store.BackfillRollups(t.Context(), 1)
	checkCount(t, count, err, 0)

	for stream, want := range map[string]int64{StreamMain: 3, StreamFSLogix: 1} {
		activity, err := store.QueryActivity(t.Context(), now, now, nil, stream)
		if err != nil || !activity.Indexing.Ready || activity.Matched == nil || *activity.Matched != want || int64(len(activity.Events)) != want {
			t.Fatalf("%s: %+v, %v", stream, activity, err)
		}
	}
	var paths, pathEvents, policyVersion int
	err = db.QueryRow(`SELECT (SELECT count(*) FROM audit_paths_fts WHERE audit_paths_fts MATCH 'profile'),
		(SELECT count(*) FROM audit_path_events), policy_version FROM audit_rollup_state`).Scan(&paths, &pathEvents, &policyVersion)
	if err != nil || paths != 1 || pathEvents != 4 || policyVersion != 5 {
		t.Fatalf("path and policy indexes: %d %d %d %v", paths, pathEvents, policyVersion, err)
	}
}

func writeLog(t *testing.T, path, content string, appendMode bool) {
	t.Helper()
	if !appendMode {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorPartialLineRotationAndTruncation(t *testing.T) {
	db, _ := openTestDB(t)
	store := initTestStore(t, db)
	dir := t.TempDir()
	active := filepath.Join(dir, "log.pc01")
	rotated := active + ".old"
	line := func(path string) string { return "2026/07/31 12:34:56|alice|192.0.2.5|PC01|Data|pwrite|OK|" + path }
	first := line("first") + "\r\n"
	writeLog(t, active, first+line("second"), false)
	collector := &Collector{Store: store, SourceGlob: filepath.Join(dir, "log.*")}
	count, err := collector.CollectOnce(t.Context())
	checkCount(t, count, err, 1)
	state, err := store.SourceEntries(t.Context())
	if err != nil || state[active].Offset != int64(len(first)) {
		t.Fatalf("partial line offset: %v %v", state, err)
	}
	writeLog(t, active, "\n", true)
	if err := os.Rename(active, rotated); err != nil {
		t.Fatal(err)
	}
	writeLog(t, active, line("new active file")+"\n", false)
	// Even with an older mtime, the new inode follows the known rotated one.
	old := time.Unix(100000, 0)
	if err := os.Chtimes(active, old, old); err != nil {
		t.Fatal(err)
	}
	count, err = collector.CollectOnce(t.Context())
	checkCount(t, count, err, 2)
	state, err = store.SourceEntries(t.Context())
	if err != nil || state[rotated].Offset != int64(len(first)+len(line("second"))+1) {
		t.Fatalf("rotated offset: %v %v", state, err)
	}
	count, err = collector.CollectOnce(t.Context())
	checkCount(t, count, err, 0)

	if err := os.Remove(rotated); err != nil {
		t.Fatal(err)
	}
	writeLog(t, active, line("fourth")+"\n", false)
	count, err = collector.CollectOnce(t.Context())
	checkCount(t, count, err, 1)
	state, err = store.SourceEntries(t.Context())
	if err != nil || len(state) != 1 {
		t.Fatalf("stale source not removed: %v %v", state, err)
	}
	day := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	page, err := store.QueryActivity(t.Context(), day, day, nil, StreamMain)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, event := range page.Events {
		paths = append(paths, event.Path)
	}
	if !reflect.DeepEqual(paths, []string{"fourth", "new active file", "second", "first"}) || page.Events[2].Source != "log.pc01.old" {
		t.Fatalf("unexpected rotated/truncated events %+v", page.Events)
	}
}

func TestFailedAppendDoesNotAdvanceOffsets(t *testing.T) {
	db, _ := openTestDB(t)
	store := initTestStore(t, db)
	ctx := t.Context()
	updates := map[string]Source{"log.pc01": {Inode: 1, Offset: 200}}
	seen := map[string]bool{"log.pc01": true}
	event := Event{Timestamp: "2026-07-31T12:34:56Z", Action: "write", Path: "example"}
	invalid := event
	invalid.Action = "not supported"
	if count, err := store.AppendBatch(ctx, []Event{event, invalid}, updates, seen); err == nil || count != 0 {
		t.Fatalf("bad action append: %d %v", count, err)
	}
	state, err := store.SourceEntries(ctx)
	if err != nil || len(state) != 0 {
		t.Fatalf("offsets survived failed batch: %v %v", state, err)
	}
	var events, paths int
	if err := db.QueryRow("SELECT (SELECT count(*) FROM audit_events), (SELECT count(*) FROM audit_paths)").Scan(&events, &paths); err != nil || events != 0 || paths != 0 {
		t.Fatalf("failed batch partially committed: events=%d, paths=%d, err=%v", events, paths, err)
	}
	count, err := store.AppendBatch(ctx, []Event{event}, updates, seen)
	checkCount(t, count, err, 1)
}

func TestReopenSharedWALDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	uri := &url.URL{Scheme: "file", Path: path}
	uri.RawQuery = url.Values{"_pragma": {"busy_timeout(30000)", "journal_mode(WAL)", "foreign_keys(ON)"}}.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := initTestStore(t, db)
	mustSQL(t, db, "CREATE TABLE unrelated (data TEXT); INSERT INTO unrelated VALUES ('keep me');")

	now := time.Now().UTC()
	stamp := now.Format(secondLayout)
	event := Event{Timestamp: stamp, IngestedAt: stamp, Action: "read", Path: "notes", Share: "Data"}
	updates := map[string]Source{"log.pc01": {Inode: 10, Offset: 42}}
	seen := map[string]bool{"log.pc01": true}
	count, err := store.AppendBatch(t.Context(), []Event{event}, updates, seen)
	checkCount(t, count, err, 1)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	store = initTestStore(t, reopened)
	state, err := store.SourceEntries(t.Context())
	if err != nil || !reflect.DeepEqual(state, updates) {
		t.Fatalf("reopened sources: %v, %v", state, err)
	}
	activity, err := store.QueryActivity(t.Context(), now, now, nil, StreamMain)
	if err != nil || !activity.Indexing.Ready || activity.Matched == nil || *activity.Matched != 1 {
		t.Fatalf("reopened activity: %+v, %v", activity, err)
	}
	count, err = store.AppendBatch(t.Context(), []Event{event}, updates, seen)
	checkCount(t, count, err, 0)

	var data string
	if err := reopened.QueryRow("SELECT data FROM unrelated").Scan(&data); err != nil || data != "keep me" {
		t.Fatalf("unrelated table: %q, %v", data, err)
	}
}

func TestQueryValidation(t *testing.T) {
	db, _ := openTestDB(t)
	store := initTestStore(t, db)
	t.Setenv("AUDIT_QUERY_MAX_DAYS", "2")
	for _, params := range []url.Values{
		{"from": {"2026-07-32"}},
		{"from": {"2026-07-29"}, "to": {"2026-07-31"}},
		{"cursor": {"invalid"}},
		{"limit": {"invalid"}},
	} {
		var invalid *InvalidQuery
		if _, err := store.Query(t.Context(), params, StreamMain); !errors.As(err, &invalid) {
			t.Errorf("%v: got %v, want InvalidQuery", params, err)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	collector := &Collector{Store: store, SourceGlob: filepath.Join(t.TempDir(), "log.*")}
	if err := collector.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitLegacyCleanupDoesNotRemoveUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"2026-07-31.jsonl", "2026-07-30.jsonl.gz", "collector-state.json", "collector-state.json.tmp", "unrelated.jsonl"} {
		writeLog(t, filepath.Join(dir, name), "fixture", false)
	}
	count, err := DropLegacyAuditFiles(dir)
	checkCount(t, count, err, 4)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "unrelated.jsonl" {
		t.Fatalf("unexpected legacy directory: %v %v", entries, err)
	}
}
