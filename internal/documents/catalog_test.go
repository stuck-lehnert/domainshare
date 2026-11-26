package documents

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/state"
)

type documentFixture struct {
	Service
	root, catalogRoot, policyPath string
	identity                      directory.Identity
}

func makeDocumentFixture(t *testing.T) documentFixture {
	t.Helper()
	root := t.TempDir()
	fixture := documentFixture{root: root, catalogRoot: filepath.Join(root, "catalog"), policyPath: filepath.Join(root, "shares.db")}
	fixture.DataRoot, fixture.PrivateRoot = filepath.Join(root, "data"), filepath.Join(root, "private")
	for _, name := range []string{"data/Granted", "data/Denied", "private/alice", "private/bob", "catalog"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	policy, err := state.Open(t.Context(), fixture.policyPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { policy.Close() })
	fixture.Policy = policy
	if _, err := policy.Exec(`CREATE TABLE shares(objectGUID TEXT PRIMARY KEY,shareName TEXT,path TEXT,isActive INTEGER);
		CREATE TABLE access_users(sid TEXT PRIMARY KEY,sam TEXT);
		CREATE TABLE folder_permissions(folderId TEXT,kind TEXT,principalId TEXT,level INTEGER);
		INSERT INTO access_users VALUES('SID-Al','alice'),('SID-Bo','bob');
		INSERT INTO folder_permissions VALUES('id-a','user','SID-Al',1);`); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Exec(`INSERT INTO shares VALUES('id-a','Granted',?,1),('id-b','Denied',?,1)`,
		filepath.Join(fixture.DataRoot, "Granted"), filepath.Join(fixture.DataRoot, "Denied")); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	fixture.identity = directory.Identity{Username: "alice", SID: "SID-Al", Role: "user", UID: &uid}
	return fixture
}

func (fixture *documentFixture) openCatalog(t *testing.T) {
	t.Helper()
	catalog, err := OpenCatalog(t.Context(), fixture.catalogRoot)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Catalog = catalog
	t.Cleanup(func() { catalog.Close() })
}

func putDocumentFile(t *testing.T, root, name, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

const pythonCatalogFixture = `
import json, os, sys
from app import documents, document_search, state_db

root, search, policy, version = sys.argv[1:]
documents.SEARCH_ROOT = search
documents.SEARCH_DB = os.path.join(search, 'search.db')
documents.directory.GROUP_ROOT = os.path.join(root, 'data')
documents.directory.PRIVATE_ROOT = os.path.join(root, 'private')
documents.directory.open_db = lambda: state_db.connect_state_db(policy)
conn = documents.connect()
if version == '2':
    # Legacy schema and content index, before migration to v3 search rollups.
    document_search.ensure_schema = lambda *args: None
documents.ensure_schema(conn)

preview = '0123456789abcdef0123456789abcdef.jpg'
os.mkdir(os.path.join(search, 'previews'), 0o700)
with open(os.path.join(search, 'previews', preview), 'wb') as f:
    f.write(b'\xff\xd8JPG')
for source, kind, label, relative, owner in [
    ('data:id-a', 'data', 'Granted', 'data/Granted', ''),
    ('data:id-b', 'data', 'Denied', 'data/Denied', ''),
    ('private:alice', 'private', 'Private', 'private/alice', 'SID-Al'),
    ('private:bob', 'private', 'Private', 'private/bob', 'SID-Bo'),
]:
    conn.execute('INSERT INTO document_sources VALUES(?,?,?,?,?)', (source,kind,label,os.path.join(root,relative),owner))

documents_by_source = [
    ('data:id-a', 'Überblick-Bericht😊.pdf', 'Frühe Straße Entwurf', 'ready', preview, 2, 0o600),
    ('data:id-a', 'Überblick-Plan.pdf', 'Frühe Planung Fünf', 'ocr', '', 1, 0o600),
    ('data:id-a', '100%_real.txt', "Frühe shouldn't be indexed", 'name-only', '', 0, 0o600),
    ('data:id-b', 'Secret.pdf', 'Frühe SECRET', 'ready', '', 1, 0o600),
    ('private:alice', 'Frühe.odt', 'Frühe Straße privat', 'pending', '', 0, 0o600),
    ('private:alice', 'owner-denied.xyz', 'INACCESSIBLE', 'pending', '', 0, 0o200),
    ('private:bob', 'Confidential.pdf', 'Frühe CONFIDENTIAL', 'ready', '', 1, 0o600),
]
for i, (source, name, body, state, thumbnail, pages, mode) in enumerate(documents_by_source, 1):
    folder = conn.execute('SELECT root FROM document_sources WHERE id=?', (source,)).fetchone()[0]
    path = os.path.join(folder, name)
    with open(path, 'w', encoding='utf8') as f:
        f.write(name)
    os.chmod(path, mode)
    # Deliberately tie timestamps so ordering/cursor tests also exercise IDs.
    os.utime(path, ns=(1600000000000000000,1600000000000000000 + 1000000000 * (i % 2)))
    info = os.stat(path)
    conn.execute('INSERT INTO documents(id,source_id,path,name,extension,size,modified,fingerprint,body,state,preview,pages) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
        (f'{i:032x}', source,name,name,os.path.splitext(name)[1],info.st_size,info.st_mtime,documents.fingerprint(info),body,state,thumbnail,pages))
conn.commit()

if version == '2':
    conn.close()
    raise SystemExit

identity = {'sub': 'alice', 'sid': 'SID-Al', 'role': 'user', 'uid': os.getuid()}
queries = [
    {'limit': '1'},
    {'scope': 'content', 'q': 'fruhe', 'sort': 'relevance', 'limit': '1'},
    {'scope': 'content', 'q': 'FRÜHE', 'sort': 'oldest'},
    {'scope': 'name', 'q': 'Überblick', 'sort': 'name', 'limit': '1'},
    {'scope': 'name', 'q': 'überblick'},
    {'scope': 'name', 'q': '%_', 'source': 'data:id-a'},
    {'scope': 'name', 'q': '😊'},
    {'q': '–', 'sort': 'relevance', 'type': 'PDF'},
    {'q': '_', 'scope': 'all'},
    {'source': 'data:id-b'},
    {'type': '.PDF', 'sort': 'oldest', 'offset': '1'},
]
expectations = []
for query in queries:
    result = documents.search(conn, identity, {key: [value] for key,value in query.items()})
    expectations.append({'query': query, 'result': result})
    if result['nextCursor']:
        query = dict(query, cursor=result['nextCursor'])
        result = documents.search(conn, identity, {key: [value] for key,value in query.items()})
        expectations.append({'query': query, 'result': result})
print(json.dumps({'queries': expectations,
    'detail': documents.detail(conn, identity, f'{1:032x}'),
    'worker': documents.worker_snapshot(conn),
    'terms': [document_search.name_terms(s) for s in ['Straße', 'Κόσμος', 'über', 'İstanbul', '😊', 'Cafe\u0301']],
}))
conn.close()
`

func runPythonCatalogFixture(t *testing.T, fixture documentFixture, version string) []byte {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("Python is only used for the legacy reference comparison")
	}
	if _, err := os.Stat("../../app/documents.py"); err != nil {
		t.Skip("legacy Python reference is not in this checkout")
	}
	cmd := exec.CommandContext(t.Context(), "python3", "-c", pythonCatalogFixture,
		fixture.root, fixture.catalogRoot, fixture.policyPath, version)
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "TMPDIR=/tmp")
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generate Python v%s fixture: %v\n%s", version, err, data)
	}
	return data
}

func TestPythonV3CatalogSearchAndWorkerParity(t *testing.T) {
	fixture := makeDocumentFixture(t)
	data := runPythonCatalogFixture(t, fixture, "3")
	fixture.openCatalog(t)
	var baseline struct {
		Queries []struct {
			Query  map[string]string
			Result SearchResult
		}
		Detail DocumentDetail
		Worker WorkerStatus
		Terms  []string
	}
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatalf("decode reference: %v", err)
	}
	for i, name := range []string{"Straße", "Κόσμος", "über", "İstanbul", "😊", "Cafe\u0301"} {
		if got := nameTerms(name); got != baseline.Terms[i] {
			t.Errorf("casefold trigrams for %q\ngot %q\nwant %q", name, got, baseline.Terms[i])
		}
	}
	for _, sample := range baseline.Queries {
		params := make(url.Values)
		for key, value := range sample.Query {
			params.Set(key, value)
		}
		got, err := fixture.Search(t.Context(), fixture.identity, params)
		if err != nil {
			t.Errorf("query %v: %v", params, err)
			continue
		}
		// Internal source root and owner are never serialized to clients.
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(sample.Result)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("query %v\ngot  %s\nwant %s", params, gotJSON, wantJSON)
		}
	}
	id := baseline.Detail.ID
	detail, err := fixture.Detail(t.Context(), fixture.identity, id)
	if err != nil || detail != baseline.Detail {
		t.Fatalf("detail %+v, %v; want %+v", detail, err, baseline.Detail)
	}
	worker, err := WorkerSnapshot(t.Context(), fixture.Catalog)
	if err != nil || !reflect.DeepEqual(worker, baseline.Worker) {
		t.Fatalf("worker %+v, %v; want %+v", worker, err, baseline.Worker)
	}
	file, metadata, err := fixture.Download(t.Context(), fixture.identity, id)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(content) != detail.Name || metadata != detail.Document {
		t.Fatalf("download: %q, %+v, %v", content, metadata, err)
	}
	file, err = fixture.Preview(t.Context(), fixture.identity, id, fixture.catalogRoot)
	if err != nil {
		t.Fatal(err)
	}
	content, err = io.ReadAll(file)
	file.Close()
	if err != nil || string(content) != "\xff\xd8JPG" {
		t.Fatalf("preview: %q, %v", content, err)
	}
	assertPythonCatalogWritable(t, fixture)
}

func TestPythonV2CatalogMigratesPreservingQueueAndFiles(t *testing.T) {
	fixture := makeDocumentFixture(t)
	runPythonCatalogFixture(t, fixture, "2")
	fixture.openCatalog(t)
	var version int
	if err := fixture.Catalog.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != catalogVersion {
		t.Fatalf("catalog version = %v, %v", version, err)
	}
	result, err := fixture.Search(t.Context(), fixture.identity, url.Values{"scope": {"content"}, "q": {"fruhe"}})
	if err != nil || len(result.Items) != 3 || result.Pending != 2 {
		t.Fatalf("migrated catalog results %+v, %v", result, err)
	}
	if detail, err := fixture.Detail(t.Context(), fixture.identity, strings.Repeat("0", 31)+"1"); err != nil || !detail.HasPreview || detail.Pages != 2 {
		t.Fatalf("migrated detail %+v, %v", detail, err)
	}
	assertPythonCatalogWritable(t, fixture)
}

func assertPythonCatalogWritable(t *testing.T, fixture documentFixture) {
	t.Helper()
	// This exercises the Go registered scalar function in Python-created
	// triggers and in the native migration, not just FTS reads.
	if _, err := fixture.Catalog.Exec(`UPDATE documents SET body='Neue Suchbegriffe',name=name WHERE id=?`, strings.Repeat("0", 31)+"1"); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.Search(t.Context(), fixture.identity, url.Values{"scope": {"content"}, "q": {"Suchbegriff"}})
	if err != nil || len(result.Items) != 1 || result.Items[0].ID != strings.Repeat("0", 31)+"1" {
		t.Fatalf("Go updated FTS/index/rollups: %+v, %v", result, err)
	}
}

func TestNativeCatalogStalenessRevocationAndInvalidCursors(t *testing.T) {
	fixture := makeDocumentFixture(t)
	fixture.openCatalog(t)
	ctx := t.Context()
	root := filepath.Join(fixture.DataRoot, "Granted")
	source := indexSource{id: "data:id-a", kind: "data", label: "Granted", root: root}
	if _, err := fixture.Catalog.Exec(`INSERT INTO document_sources VALUES(?,?,?,?,?)`, source.id, source.kind, source.label, source.root, source.sid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Äpfel.txt", "Öl.txt"} {
		putDocumentFile(t, root, name, name, 0o600)
		if err := discoverFile(ctx, fixture.Catalog, source, name, 1); err != nil {
			t.Fatal(err)
		}
	}
	result, err := fixture.Search(ctx, fixture.identity, url.Values{"limit": {"1"}, "sort": {"name"}})
	if err != nil || len(result.Items) != 1 || result.NextCursor == nil || result.Total != 2 {
		t.Fatalf("initial page %+v, %v", result, err)
	}
	first := result.Items[0]
	for _, query := range []url.Values{
		{"cursor": {"invalid"}}, {"offset": {"1001"}}, {"limit": {"x"}},
		{"cursor": {*result.NextCursor}, "sort": {"name"}, "source": {"data:id-a"}},
	} {
		if _, err := fixture.Search(ctx, fixture.identity, query); !errors.Is(err, ErrInvalidSearch) {
			t.Fatalf("invalid query %v returned %v", query, err)
		}
	}
	result, err = fixture.Search(ctx, fixture.identity, url.Values{"cursor": {*result.NextCursor}, "sort": {"name"}})
	if err != nil || len(result.Items) != 1 || result.Items[0].ID == first.ID {
		t.Fatalf("second page %+v, %v", result, err)
	}
	putDocumentFile(t, root, first.Name, "Changed content", 0o600)
	if _, err := fixture.Detail(ctx, fixture.identity, first.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale document detail: %v", err)
	}
	result, err = fixture.Search(ctx, fixture.identity, url.Values{"scope": {"name"}, "q": {first.Name}})
	if err != nil || len(result.Items) != 0 {
		t.Fatalf("stale document appeared: %+v, %v", result, err)
	}
	if err := discoverFile(ctx, fixture.Catalog, source, first.Name, 2); err != nil {
		t.Fatal(err)
	}
	if detail, err := fixture.Detail(ctx, fixture.identity, first.ID); err != nil || detail.Version == first.Version {
		t.Fatalf("rediscovery must retain id and update version: %+v, %v", detail, err)
	}
	if _, err := fixture.Policy.Exec(`UPDATE folder_permissions SET level=0`); err != nil {
		t.Fatal(err)
	}
	if file, _, err := fixture.Download(ctx, fixture.identity, first.ID); !errors.Is(err, os.ErrNotExist) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("download after revocation: %v", err)
	}
	result, err = fixture.Search(ctx, fixture.identity, nil)
	if err != nil || len(result.Sources) != 0 || len(result.Items) != 0 || result.Total != 0 || len(result.Types) != 0 {
		t.Fatalf("revoked document metadata: %+v, %v", result, err)
	}
}
