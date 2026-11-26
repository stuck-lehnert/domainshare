package documents

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func (fixture documentFixture) indexer() indexer {
	return indexer{
		IndexOptions: IndexOptions{DocumentRoot: fixture.catalogRoot,
			DataRoot: fixture.DataRoot, PrivateRoot: fixture.PrivateRoot, Policy: fixture.Policy},
		db: fixture.Catalog,
	}
}

func waitIndexFixture(t *testing.T, verify func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if verify() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("native document watcher did not reach expected state")
}

func TestIndexWatcherTracksEventsAndPause(t *testing.T) {
	// Make it impossible for periodic scanning to hide broken inotify.
	t.Setenv("DOCUMENT_SCAN_SECONDS", "3600")
	fixture := makeDocumentFixture(t)
	fixture.openCatalog(t)
	index := fixture.indexer()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		index.watch(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	root := filepath.Join(fixture.DataRoot, "Granted")
	target := "from-watch.txt"
	putDocumentFile(t, root, "initial.txt", "under initial scan", 0o600)
	waitIndexFixture(t, func() bool {
		status, err := WorkerSnapshot(ctx, fixture.Catalog)
		return err == nil && status.LastScan > 0 && status.Online && status.Counts.Total == 1
	})

	putDocumentFile(t, root, target, "only seen by inotify", 0o600)
	waitIndexFixture(t, func() bool {
		results, err := fixture.Search(ctx, fixture.identity, url.Values{"scope": {"name"}, "q": {target}})
		return err == nil && len(results.Items) == 1 && results.Items[0].Name == target
	})

	// New directories (and their eventual file updates) get a watch, too.
	child := filepath.Join(root, "new-directory")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	putDocumentFile(t, child, "inside-markdown.md", "new subtree", 0o600)
	waitIndexFixture(t, func() bool {
		results, err := fixture.Search(ctx, fixture.identity, url.Values{"scope": {"name"}, "q": {"inside-markdown"}})
		return err == nil && len(results.Items) == 1 && results.Items[0].Path == "new-directory/inside-markdown.md"
	})
	if err := os.Remove(filepath.Join(child, "inside-markdown.md")); err != nil {
		t.Fatal(err)
	}
	waitIndexFixture(t, func() bool {
		var count int
		err := fixture.Catalog.QueryRow(`SELECT count(*) FROM documents WHERE path='new-directory/inside-markdown.md'`).Scan(&count)
		return err == nil && count == 0
	})

	status, err := ControlWorker(ctx, fixture.Catalog, "pause", "admin")
	if err != nil || !status.Paused || len(status.Activity) == 0 || status.Activity[0].Actor != "admin" {
		t.Fatalf("pause snapshot = %+v (%v)", status, err)
	}
	if _, err := index.processNext(ctx, false); err != nil {
		t.Fatal(err)
	}
	status, err = WorkerSnapshot(ctx, fixture.Catalog)
	if err != nil || status.State != "paused" {
		t.Fatalf("paused worker = %+v (%v)", status, err)
	}
	if _, err := ControlWorker(ctx, fixture.Catalog, "pause", "admin"); err != nil {
		t.Fatal(err)
	}
	putDocumentFile(t, root, "until-resume.txt", "catalogued after resume", 0o600)
	time.Sleep(650 * time.Millisecond)
	var pausedCount int
	if err := fixture.Catalog.QueryRow(`SELECT count(*) FROM documents WHERE name='until-resume.txt'`).Scan(&pausedCount); err != nil || pausedCount != 0 {
		t.Fatalf("watcher wrote while paused: %d (%v)", pausedCount, err)
	}
	status, err = ControlWorker(ctx, fixture.Catalog, "resume", "admin")
	if err != nil || status.Paused || len(status.Activity) != 2 {
		t.Fatalf("resume snapshot = %+v (%v)", status, err)
	}
	waitIndexFixture(t, func() bool {
		results, err := fixture.Search(ctx, fixture.identity, nil)
		return err == nil && results.Total == 3
	})
}

func TestIndexScanSkipsExcludedPathsAndRetainsIncompleteRows(t *testing.T) {
	fixture := makeDocumentFixture(t)
	fixture.openCatalog(t)
	index := fixture.indexer()
	ctx := t.Context()
	sources, _, err := index.refreshSources(ctx)
	if err != nil || len(sources) != 4 {
		t.Fatalf("source inventory = %+v (%v)", sources, err)
	}
	source := sources["data:id-a"]
	for _, name := range []string{".trash", "ordinary"} {
		if err := os.Mkdir(filepath.Join(source.root, name), 0o700); err != nil {
			t.Fatal(err)
		}
		putDocumentFile(t, filepath.Join(source.root, name), "visible.pdf", "test", 0o600)
	}
	for _, name := range []string{"Thumbs.DB", "~$lock.docx", ".pdf", "image.TIFF", "original.txt"} {
		putDocumentFile(t, source.root, name, "test", 0o600)
	}
	if err := os.Symlink("original.txt", filepath.Join(source.root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(source.root, "pipe.pdf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := index.scanSource(ctx, source, nil, ctx.Err); err != nil {
		t.Fatal(err)
	}
	results, err := fixture.Search(ctx, fixture.identity, nil)
	if err != nil || results.Total != 4 || results.Pending != 2 {
		t.Fatalf("scanner results %+v (%v)", results, err)
	}
	if err := os.Remove(filepath.Join(source.root, "original.txt")); err != nil {
		t.Fatal(err)
	}
	if err := index.scanSource(ctx, source, nil, func() error { return errIndexPaused }); !errors.Is(err, errIndexPaused) {
		t.Fatalf("cancelled scan: %v", err)
	}
	var count int
	if err := fixture.Catalog.QueryRow(`SELECT count(*) FROM documents WHERE name='original.txt'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cancelled scan pruned a row: %d (%v)", count, err)
	}
	if err := index.scanSource(ctx, source, nil, ctx.Err); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Catalog.QueryRow(`SELECT count(*) FROM documents WHERE name='original.txt'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("complete scan didn't prune a missing row: %d (%v)", count, err)
	}
}

func TestDocumentQueueKeepsOCRPhaseAfterFailure(t *testing.T) {
	fixture := makeDocumentFixture(t)
	fixture.openCatalog(t)
	index := fixture.indexer()
	ctx := t.Context()
	sources, _, err := index.refreshSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	source := sources["data:id-a"]
	putDocumentFile(t, source.root, "scanned.pdf", "sample original", 0o600)
	if err := discoverFile(ctx, fixture.Catalog, source, "scanned.pdf", 1); err != nil {
		t.Fatal(err)
	}
	var row catalogRow
	if err := fixture.Catalog.QueryRow(`SELECT ` + documentColumns + ` FROM documents d WHERE path='scanned.pdf'`).Scan(row.columns()...); err != nil {
		t.Fatal(err)
	}
	previewName := "0123456789abcdef0123456789abcdef.jpg"
	if err := immediate(ctx, fixture.Catalog, func(conn *sql.Conn) error {
		return index.finishJob(ctx, conn, row, source, &extractionResult{Pages: 2, NeedsOCR: true, preview: previewName})
	}); err != nil {
		t.Fatal(err)
	}
	if err := immediate(ctx, fixture.Catalog, func(conn *sql.Conn) error {
		return index.finishFailure(ctx, conn, row, source, "ocr", errors.New("transient failure"))
	}); err != nil {
		t.Fatal(err)
	}
	status, err := WorkerSnapshot(ctx, fixture.Catalog)
	if err != nil || status.Processed != 1 || status.Counts.OCR != 1 || status.Counts.Errors != 1 ||
		len(status.Failures) != 1 || status.Failures[0].RetryAt <= unixTime() || status.Failures[0].State != "ocr" {
		t.Fatalf("OCR retry snapshot %+v (%v)", status, err)
	}
	if err := immediate(ctx, fixture.Catalog, func(conn *sql.Conn) error {
		return index.finishJob(ctx, conn, row, source, &extractionResult{Pages: 2, Body: "Recognized writing"})
	}); err != nil {
		t.Fatal(err)
	}
	detail, err := fixture.Detail(ctx, fixture.identity, row.ID)
	if err != nil || !detail.HasPreview || detail.Text != "Recognized writing" || detail.State != "ready" || detail.Attempts != 0 {
		t.Fatalf("OCR completion %+v (%v)", detail, err)
	}
	status, err = WorkerSnapshot(ctx, fixture.Catalog)
	if err != nil || status.Processed != 2 || status.Counts.Complete != 1 || status.Counts.Errors != 0 {
		t.Fatalf("completed snapshot %+v (%v)", status, err)
	}
}
