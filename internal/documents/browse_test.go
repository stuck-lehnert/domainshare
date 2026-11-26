package documents

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stuck-lehnert/domainshare/internal/directory"
	"github.com/stuck-lehnert/domainshare/internal/state"
	"golang.org/x/sys/unix"
)

const (
	alice = "S-1-5-21-1001"
	bob   = "S-1-5-21-1002"
)

func fixture(t *testing.T) Service {
	t.Helper()
	root := t.TempDir()
	policy, err := state.Open(t.Context(), filepath.Join(root, "shares.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { policy.Close() })
	catalog, err := state.Open(t.Context(), filepath.Join(root, "search.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { catalog.Close() })

	svc := Service{Policy: policy, Catalog: catalog, DataRoot: filepath.Join(root, "data"), PrivateRoot: filepath.Join(root, "private")}
	for _, path := range []string{"data/Granted", "data/Restricted", "data/Archived", "private/first", "private/second"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := policy.Exec(`CREATE TABLE shares(objectGUID TEXT PRIMARY KEY,shareName TEXT,path TEXT,isActive INTEGER);
		CREATE TABLE access_users(sid TEXT PRIMARY KEY,sam TEXT);
		CREATE TABLE folder_permissions(folderId TEXT,kind TEXT,principalId TEXT,level INTEGER);`); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"Granted", "Restricted", "Archived"} {
		if _, err := policy.Exec(`INSERT INTO shares VALUES(?,?,?,?)`, name, name, filepath.Join(svc.DataRoot, name), i < 2); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := policy.Exec(`INSERT INTO folder_permissions VALUES('Granted','user',?,1),('Restricted','user',?,0)`, alice, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Exec(`CREATE TABLE document_sources (id TEXT,kind TEXT,label TEXT,root TEXT,owner_sid TEXT);
		INSERT INTO document_sources VALUES('private:first','private','Private',?,?),('private:second','private','Private',?,?)`,
		filepath.Join(svc.PrivateRoot, "first"), alice, filepath.Join(svc.PrivateRoot, "second"), bob); err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestShareRulesAreCheckedOnEveryBrowseAndDownload(t *testing.T) {
	svc := fixture(t)
	uid := os.Getuid()
	id := directory.Identity{Username: `EXAMPLE\Alice`, SID: alice, UID: &uid, Role: "user"}
	ctx := t.Context()
	listing, err := svc.BrowseSources(ctx, id)
	if err != nil || len(listing) != 2 || listing[0].ID != "data:Granted" || listing[1].ID != "private:first" {
		t.Fatalf("ordinary sources: %+v, %v", listing, err)
	}
	admin := id
	admin.Role = "domain-admin"
	listing, err = svc.BrowseSources(ctx, admin)
	if err != nil || len(listing) != 3 || listing[1].ID != "data:Restricted" || listing[2].ID != "private:first" {
		t.Fatalf("admin sources: %+v, %v", listing, err)
	}
	if err := os.WriteFile(filepath.Join(svc.DataRoot, "Granted", "allowed.txt"), []byte("allowed"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := svc.DownloadPath(ctx, id, "data:Granted", "allowed.txt")
	if err != nil {
		t.Fatal(err)
	}
	text, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(text) != "allowed" {
		t.Fatalf("download: %q, %v", text, err)
	}
	if _, err := svc.Policy.ExecContext(ctx, `UPDATE folder_permissions SET level=0 WHERE folderId='Granted' AND principalId=?`, alice); err != nil {
		t.Fatal(err)
	}
	if denied, err := svc.DownloadPath(ctx, id, "data:Granted", "allowed.txt"); !errors.Is(err, os.ErrNotExist) {
		if denied != nil {
			denied.Close()
		}
		t.Fatalf("revoked access: %v", err)
	}
}

func TestBrowsePaginationAndUnsafeEntries(t *testing.T) {
	svc := fixture(t)
	root := filepath.Join(svc.DataRoot, "Granted")
	for _, name := range []string{"zeta", "beta", "alpha", "~$office", "Thumbs.db"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("alpha", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".trash"), 0o700); err != nil {
		t.Fatal(err)
	}
	id := directory.Identity{Username: "Alice", SID: alice, Role: "user"}
	page, err := svc.BrowseDirectory(t.Context(), id, "data:Granted", "", "", 2)
	if err != nil || len(page.Items) != 2 || page.Items[0].Name != "alpha" || page.NextAfter == nil || *page.NextAfter != "beta" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	next, err := svc.BrowseDirectory(t.Context(), id, "data:Granted", "", *page.NextAfter, 2)
	if err != nil || len(next.Items) != 1 || next.Items[0].Name != "zeta" || next.NextAfter != nil || next.Items[0].Modified < 1_000_000_000 {
		t.Fatalf("second page: %+v %v", next, err)
	}
	for _, path := range []string{"../Restricted", "link", "pipe", "Thumbs.db", "~$office", ".trash"} {
		file, err := svc.DownloadPath(t.Context(), id, "data:Granted", path)
		if file != nil {
			file.Close()
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected blocked path %q: %v", path, err)
		}
	}
}
