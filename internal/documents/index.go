package documents

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

type IndexOptions struct {
	DocumentRoot string
	Policy       *sql.DB
	DataRoot     string
	PrivateRoot  string
}

type indexer struct {
	IndexOptions
	db          *sql.DB
	jobsRoot    string
	credentials credentials
	executable  string
}

var errIndexPaused = errors.New("document index is paused")

func indexSetting(key string, fallback, minimum, maximum int) int {
	n, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return min(maximum, max(minimum, n))
}

func (index indexer) log(format string, args ...any) {
	log.Printf("[documents] "+format, args...)
}

func RunIndexer(ctx context.Context, options IndexOptions) error {
	if options.Policy == nil || options.DataRoot == "" || options.PrivateRoot == "" {
		return errors.New("document index requires share policy and roots")
	}
	db, err := OpenCatalog(ctx, options.DocumentRoot)
	if err != nil {
		return err
	}
	defer db.Close()

	lock, err := unix.Open(filepath.Join(options.DocumentRoot, "worker.lock"),
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(lock)
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil
		}
		return err
	}

	credentials, err := documentCredentials()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	jobs, err := os.MkdirTemp("/tmp", "domainshare-document-jobs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(jobs)
	if err := os.Chmod(jobs, 0o711); err != nil {
		return err
	}

	index := indexer{IndexOptions: options, db: db, jobsRoot: jobs, credentials: credentials, executable: executable}
	if err := index.start(ctx); err != nil {
		return err
	}
	index.log("Watching Data and Private; extraction queue is ready")

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		index.watch(ctx)
	}()
	defer func() {
		cancel()
		<-done
		cleanup, release := context.WithTimeout(context.Background(), 2*time.Second)
		defer release()
		_, _ = db.ExecContext(cleanup, `UPDATE document_worker SET scanning=0,heartbeat=0,current_id='',
			state=CASE WHEN paused THEN 'paused' ELSE 'idle' END WHERE id=1`)
	}()

	for iteration := 1; ctx.Err() == nil; iteration++ {
		worked, err := index.processNext(ctx, iteration%5 == 0)
		if err != nil && ctx.Err() == nil {
			index.log("Queue retry: %v", err)
			waitIndex(ctx, time.Second)
		} else if !worked {
			waitIndex(ctx, 500*time.Millisecond)
		}
	}
	return nil
}

func waitIndex(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (index indexer) start(ctx context.Context) error {
	return immediate(ctx, index.db, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(ctx, `UPDATE document_worker SET scanning=0,current_id='',
			state=CASE WHEN paused THEN 'paused' ELSE 'idle' END WHERE id=1`); err != nil {
			return err
		}
		return workerEvent(ctx, conn, "started", "", "", "", "")
	})
}

type indexSource struct {
	id, kind, label, root, sid string
}

func (source indexSource) displayLabel() string {
	if source.kind == "private" && len(source.id) >= len("private:") {
		return source.label + " / " + source.id[len("private:"):]
	}
	return source.label
}

func (index indexer) workerState(ctx context.Context, state, current string) error {
	_, err := index.db.ExecContext(ctx, "UPDATE document_worker SET state=?,current_id=? WHERE id=1 AND (state<>? OR current_id<>?)",
		state, current, state, current)
	return err
}

func (index indexer) processNext(ctx context.Context, preferOCR bool) (bool, error) {
	paused, err := workerPaused(ctx, index.db)
	if err != nil {
		return false, err
	}
	if paused {
		return false, index.workerState(ctx, "paused", "")
	}

	priority := "CASE d.state WHEN 'pending' THEN 0 WHEN 'ocr' THEN 1 ELSE 2 END"
	if preferOCR {
		priority = "CASE d.state WHEN 'ocr' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END"
	}

	var row catalogRow
	var source indexSource
	targets := append(row.columns(), &source.id, &source.kind, &source.label, &source.root, &source.sid)
	err = index.db.QueryRowContext(ctx, `SELECT `+documentColumns+`,s.id,s.kind,s.label,s.root,s.owner_sid FROM documents d
		JOIN document_sources s ON s.id=d.source_id WHERE d.state IN ('pending','ocr','failed') AND d.retry_at<=?
		ORDER BY `+priority+`,d.modified DESC LIMIT 1`, unixTime()).Scan(targets...)
	if errors.Is(err, sql.ErrNoRows) {
		return false, index.workerState(ctx, "idle", "")
	}
	if err != nil {
		return false, err
	}
	if excludedName(row.Name) {
		_, err := index.db.ExecContext(ctx, `DELETE FROM documents WHERE id=? AND fingerprint=?`, row.ID, row.fingerprint)
		return true, err
	}

	root := index.DataRoot
	if source.kind == "private" {
		root = index.PrivateRoot
	} else if source.kind != "data" {
		return false, errors.New("unknown document source kind")
	}
	if path, safe := directChild(root, source.root); !safe || path != source.root {
		return false, errors.New("unsafe extraction source root")
	}

	phase := "text"
	if row.State == "ocr" {
		phase = "ocr"
	}
	if err := index.workerState(ctx, phase, row.ID); err != nil {
		return false, err
	}

	maxBytes := int64(indexSetting("DOCUMENT_MAX_FILE_MB", 512, 1, 4096)) << 20
	if row.Size < 0 || row.Size > maxBytes || !contentType(row.Extension) && !imageType(row.Extension) {
		_, err := index.db.ExecContext(ctx, `UPDATE documents SET body='',state='name-only',pages=0,attempts=0,retry_at=0,indexed_at=?
			WHERE id=? AND fingerprint=?`, unixTime(), row.ID, row.fingerprint)
		if err != nil {
			return false, err
		}
		return true, index.workerState(ctx, "idle", "")
	}
	if err := workerEvent(ctx, index.db, phase, row.Path, source.displayLabel(), "", ""); err != nil {
		return false, err
	}

	result, extractionErr := index.runJob(ctx, row, source, phase)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if errors.Is(extractionErr, errIndexPaused) {
		if err := workerEvent(ctx, index.db, "interrupted", row.Path, source.displayLabel(), "", ""); err != nil {
			return false, err
		}
		return false, index.workerState(ctx, "paused", "")
	}

	err = immediate(ctx, index.db, func(conn *sql.Conn) error {
		paused, err := workerPaused(ctx, conn)
		if err != nil {
			return err
		}
		if paused {
			return errIndexPaused
		}
		switch {
		case extractionErr != nil:
			return index.finishFailure(ctx, conn, row, source, phase, extractionErr)
		case result == nil:
			// The inotify watcher usually already saw the change, but recheck
			// now to recover promptly when there was no usable Linux event.
			var currentRoot string
			if err := conn.QueryRowContext(ctx, `SELECT root FROM document_sources WHERE id=?`, source.id).Scan(&currentRoot); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return nil
				}
				return err
			}
			if currentRoot != source.root {
				return nil
			}
			if err := discoverFile(ctx, conn, source, row.Path, 0); err != nil {
				return err
			}
			return workerEvent(ctx, conn, "changed", row.Path, source.displayLabel(), "", "")
		default:
			return index.finishJob(ctx, conn, row, source, result)
		}
	})
	if errors.Is(err, errIndexPaused) {
		return false, index.workerState(ctx, "paused", "")
	}
	if err != nil {
		return false, err
	}
	return true, index.workerState(ctx, "idle", "")
}

func (index indexer) finishFailure(ctx context.Context, db sqlExecer, row catalogRow, source indexSource, phase string, problem error) error {
	state := "failed"
	if phase == "ocr" {
		state = "ocr"
	}
	attempts := row.Attempts + 1
	retry := unixTime() + float64(min(3600, 30<<min(attempts, 7)))
	updated, err := db.ExecContext(ctx, `UPDATE documents SET state=?,attempts=?,retry_at=? WHERE id=? AND fingerprint=?`,
		state, attempts, retry, row.ID, row.fingerprint)
	if err != nil {
		return err
	}
	if n, _ := updated.RowsAffected(); n == 0 {
		return nil
	}
	index.log("Extraction deferred for %s: %v", row.ID, problem)
	return workerEvent(ctx, db, "failed", row.Path, source.displayLabel(), "", problem.Error())
}

func (index indexer) finishJob(ctx context.Context, db sqlExecer, row catalogRow, source indexSource, result *extractionResult) error {
	state, event := "ready", "complete"
	if !contentType(row.Extension) {
		state, result.Body = "name-only", ""
	} else if row.Extension == ".pdf" && result.NeedsOCR {
		state, event = "ocr", "queued-ocr"
	}
	updated, err := db.ExecContext(ctx, `UPDATE documents SET body=?,state=?,pages=?,preview=CASE WHEN ?='' THEN preview ELSE ? END,
		indexed_at=?,attempts=0,retry_at=0 WHERE id=? AND fingerprint=?`, limitRunes(result.Body, maxText), state,
		result.Pages, result.preview, result.preview, unixTime(), row.ID, row.fingerprint)
	if err != nil {
		return err
	}
	if n, _ := updated.RowsAffected(); n == 0 {
		return nil
	}
	if err := workerEvent(ctx, db, event, row.Path, source.displayLabel(), "", ""); err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE document_worker SET processed=processed+1 WHERE id=1`)
	return err
}

func (index indexer) cancelled(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	paused, err := workerPaused(ctx, index.db)
	if err != nil {
		return fmt.Errorf("read document pause state: %w", err)
	}
	if paused {
		return errIndexPaused
	}
	return nil
}
