package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenPrivateRejectsWritableParentAndSymlinks(t *testing.T) {
	root := t.TempDir()
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if database, err := OpenPrivate(t.Context(), filepath.Join(writable, "secrets.db")); err == nil {
		database.Close()
		t.Fatal("accepted a replaceable database path")
	}

	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("leave this file alone"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "secrets.db")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if database, err := OpenPrivate(t.Context(), path); err == nil {
		database.Close()
		t.Fatal("accepted a symlink as a private database")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+"-wal"); err != nil {
		t.Fatal(err)
	}
	if database, err := OpenPrivate(t.Context(), path); err == nil {
		database.Close()
		t.Fatal("accepted a symlink as a database sidecar")
	}
}

func TestOpenFTSAndReadOnlyWAL(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "shares ? fragment # %.db")
	writer, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	if _, err := writer.ExecContext(ctx, `
CREATE VIRTUAL TABLE documents USING fts5(content, tokenize='unicode61');
INSERT INTO documents VALUES('Frühe Dokumente');
CREATE TABLE parent (id INTEGER PRIMARY KEY);
CREATE TABLE child (id INTEGER REFERENCES parent(id));`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO child VALUES(1)"); err == nil {
		t.Fatal("foreign keys not enabled")
	}

	reader, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	var text string
	if err := reader.QueryRowContext(ctx, "SELECT content FROM documents WHERE documents MATCH ?", "fruhe").Scan(&text); err != nil || text != "Frühe Dokumente" {
		t.Fatalf("FTS5 through read-only WAL: %q, %v", text, err)
	}
	if _, err := reader.ExecContext(ctx, "DELETE FROM documents"); err == nil {
		t.Fatal("read-only connection wrote to the DB")
	}
}
