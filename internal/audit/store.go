package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Keep the Python-compatible FTS table and insert trigger even when the Go
// query path does not use them. Downgrading must not leave a stale FTS index.
//
//go:embed schema.sql
var schema string

const rollupPolicyVersion = 5

// Store uses the caller's SQLite handle. The caller configures WAL, a busy
// timeout, and an FTS5-capable driver, and remains responsible for closing it.
type Store struct {
	db *sql.DB
}

// NewStore creates or upgrades the audit tables inside the shared state DB.
func NewStore(ctx context.Context, db *sql.DB) (*Store, error) {
	store := &Store{db: db}
	if err := store.write(ctx, ensureSchema); err != nil {
		return nil, fmt.Errorf("initialize audit schema: %w", err)
	}
	return store, nil
}

// A write reservation before the first read avoids SQLITE_BUSY_SNAPSHOT in
// WAL mode and prevents two collectors from backfilling the same ID interval.
func (s *Store) write(ctx context.Context, change func(context.Context, *sql.Conn) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(cleanup, "ROLLBACK"); err != nil {
			// Do not return a connection with unknown transaction state to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()

	if err := change(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

func ensureSchema(ctx context.Context, conn *sql.Conn) error {
	const obsolete = `
		DROP TABLE IF EXISTS audit_read_dedup;
		DROP INDEX IF EXISTS audit_events_time;
		DROP INDEX IF EXISTS audit_events_action_time;
		DROP INDEX IF EXISTS audit_events_success_time;
		DROP INDEX IF EXISTS audit_events_user_time;
		DROP INDEX IF EXISTS audit_events_account_time;
		DROP INDEX IF EXISTS audit_events_share_time;
		DROP INDEX IF EXISTS audit_events_result_time;`
	if _, err := conn.ExecContext(ctx, schema+obsolete); err != nil {
		return err
	}

	for _, column := range []struct{ table, name, definition string }{
		{"audit_events", "path_id", "INTEGER"},
		{"audit_rollup_state", "policy_version", "INTEGER NOT NULL DEFAULT 1"},
	} {
		query := "SELECT EXISTS (SELECT 1 FROM pragma_table_info(?) WHERE name = ?)"
		var exists bool
		if err := conn.QueryRowContext(ctx, query, column.table, column.name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			query := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", column.table, column.name, column.definition)
			if _, err := conn.ExecContext(ctx, query); err != nil {
				return err
			}
		}
	}

	var maxID int64
	if err := conn.QueryRowContext(ctx, "SELECT coalesce(max(id), 0) FROM audit_events").Scan(&maxID); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT OR IGNORE INTO audit_rollup_state (singleton, backfill_next_id, backfill_max_id, ready)
		VALUES (1, 1, ?, ?)`, maxID, maxID == 0); err != nil {
		return err
	}

	var version int
	if err := conn.QueryRowContext(ctx, "SELECT policy_version FROM audit_rollup_state WHERE singleton = 1").Scan(&version); err != nil {
		return err
	}
	if version > rollupPolicyVersion {
		return fmt.Errorf("audit policy version %d is newer than supported version %d", version, rollupPolicyVersion)
	}
	if version < rollupPolicyVersion {
		if _, err := conn.ExecContext(ctx, `
			DELETE FROM audit_event_dedup;
			DELETE FROM audit_daily_totals;
			DELETE FROM audit_daily_counts;
			DELETE FROM audit_daily_facets;`); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `
			UPDATE audit_rollup_state
			SET backfill_next_id = 1, backfill_max_id = ?, ready = ?, policy_version = ?
			WHERE singleton = 1`, maxID, maxID == 0, rollupPolicyVersion); err != nil {
			return err
		}
	}
	return nil
}

// Source records the inode and byte offset of a tailed Samba log.
type Source struct {
	Inode  int64
	Offset int64
}

type rowQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func sourceEntries(ctx context.Context, db rowQuerier) (map[string]Source, error) {
	rows, err := db.QueryContext(ctx, "SELECT path, inode, offset FROM audit_sources")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sources := make(map[string]Source)
	for rows.Next() {
		var path string
		var entry Source
		if err := rows.Scan(&path, &entry.Inode, &entry.Offset); err != nil {
			return nil, err
		}
		sources[path] = entry
	}
	return sources, rows.Err()
}

// SourceEntries returns the persisted log tail positions.
func (s *Store) SourceEntries(ctx context.Context) (map[string]Source, error) {
	return sourceEntries(ctx, s.db)
}

type appendEvent struct {
	Event
	second int64
	dedup  *[16]byte
}

// AppendBatch persists events and advances the offsets atomically. Paths not
// present in seen are removed from audit_sources, never from the event history.
func (s *Store) AppendBatch(ctx context.Context, events []Event, updates map[string]Source, seen map[string]bool) (int, error) {
	rows := make([]appendEvent, 0, len(events))
	fingerprints := make(map[[16]byte]struct{})
	for _, event := range events {
		at, err := eventTime(event.Timestamp)
		if err != nil {
			return 0, err
		}
		row := appendEvent{Event: event, second: unixSecond(at)}
		if dedupEligible(event) {
			key := fingerprint(event, at.UTC().Format(secondLayout))
			if _, repeated := fingerprints[key]; repeated {
				continue
			}
			fingerprints[key] = struct{}{}
			row.dedup = &key
		}
		rows = append(rows, row)
	}

	appended := 0
	err := s.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		accepted, err := newEvents(ctx, conn, rows, fingerprints)
		if err != nil {
			return err
		}
		if len(accepted) != 0 {
			if err := insertEvents(ctx, conn, accepted); err != nil {
				return err
			}
		}
		if err := pruneDedup(ctx, conn, dedupCutoff(time.Now())); err != nil {
			return err
		}
		if err := updateSources(ctx, conn, updates, seen); err != nil {
			return err
		}
		appended = len(accepted)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("append audit batch: %w", err)
	}
	return appended, nil
}

func placeholders(count int) string {
	return strings.Repeat("?,", count-1) + "?" // all callers have nonempty batches
}

func newEvents(ctx context.Context, conn *sql.Conn, events []appendEvent, keys map[[16]byte]struct{}) ([]appendEvent, error) {
	if len(keys) == 0 {
		return events, nil
	}

	args := make([]any, 0, len(keys))
	for key := range keys {
		args = append(args, key[:])
	}
	existing := make(map[[16]byte]bool)
	for batch := range slices.Chunk(args, 500) {
		query := "SELECT fingerprint FROM audit_event_dedup WHERE fingerprint IN (" + placeholders(len(batch)) + ")"
		rows, err := conn.QueryContext(ctx, query, batch...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var key []byte
			if err := rows.Scan(&key); err != nil {
				rows.Close()
				return nil, err
			}
			if len(key) == 16 {
				existing[[16]byte(key)] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	return slices.DeleteFunc(events, func(event appendEvent) bool {
		return event.dedup != nil && existing[*event.dedup]
	}), nil
}

func ensurePaths(ctx context.Context, conn *sql.Conn, events []appendEvent) (map[string]int64, error) {
	unique := make(map[string]bool)
	for _, event := range events {
		unique[event.Path] = true
	}
	paths := make([]string, 0, len(unique))
	for path := range unique {
		paths = append(paths, path)
	}
	slices.Sort(paths)

	pathIDs := make(map[string]int64, len(paths))
	for batch := range slices.Chunk(paths, 500) {
		args := make([]any, len(batch))
		for i, path := range batch {
			args[i] = path
		}
		values := strings.Repeat("(?),", len(batch)-1) + "(?)"
		if _, err := conn.ExecContext(ctx, "INSERT OR IGNORE INTO audit_paths (path) VALUES "+values, args...); err != nil {
			return nil, err
		}

		query := "SELECT path, id FROM audit_paths WHERE path IN (" + placeholders(len(batch)) + ")"
		rows, err := conn.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var path string
			var id int64
			if err := rows.Scan(&path, &id); err != nil {
				rows.Close()
				return nil, err
			}
			pathIDs[path] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return pathIDs, nil
}

const selectEvents = `SELECT id, occurred_at, occurred_second, ingested_at, user, client_ip,
	client, share, action, result, success, path, source FROM audit_events`

func scanEvent(rows *sql.Rows) (Event, int64, error) {
	var e Event
	var second int64
	err := rows.Scan(&e.ID, &e.Timestamp, &second, &e.IngestedAt, &e.User, &e.ClientIP,
		&e.Client, &e.Share, &e.Action, &e.Result, &e.Success, &e.Path, &e.Source)
	e.Operation = e.Action
	return e, second, err
}

func insertEvents(ctx context.Context, conn *sql.Conn, events []appendEvent) error {
	pathIDs, err := ensurePaths(ctx, conn, events)
	if err != nil {
		return err
	}
	insert, err := conn.PrepareContext(ctx, `
		INSERT INTO audit_events (occurred_at, occurred_second, ingested_at, user, account,
			client_ip, client, share, action, result, success, path, path_id, source)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insert.Close()

	dedup, err := conn.PrepareContext(ctx, `
		INSERT INTO audit_event_dedup (fingerprint, occurred_second, event_id) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	defer dedup.Close()

	var firstID, lastID int64
	for i, e := range events {
		res, err := insert.ExecContext(ctx, e.Timestamp, e.second, e.IngestedAt, e.User, accountName(e.User),
			e.ClientIP, e.Client, e.Share, e.Action, e.Result, e.Success, e.Path, pathIDs[e.Path], e.Source)
		if err != nil {
			return err
		}
		lastID, err = res.LastInsertId()
		if err != nil {
			return err
		}
		if i == 0 {
			firstID = lastID
		}
		if e.dedup != nil {
			if _, err := dedup.ExecContext(ctx, e.dedup[:], e.second, lastID); err != nil {
				return err
			}
		}
	}
	return indexAndRollup(ctx, conn, firstID, lastID, false)
}

func pruneDedup(ctx context.Context, conn *sql.Conn, cutoff int64) error {
	_, err := conn.ExecContext(ctx, "DELETE FROM audit_event_dedup WHERE occurred_second < ?", cutoff)
	return err
}

func updateSources(ctx context.Context, conn *sql.Conn, updates map[string]Source, seen map[string]bool) error {
	for path, state := range updates {
		if _, err := conn.ExecContext(ctx, `
			INSERT INTO audit_sources (path, inode, offset) VALUES (?, ?, ?)
			ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset`,
			path, state.Inode, state.Offset); err != nil {
			return err
		}
	}

	sources, err := sourceEntries(ctx, conn)
	if err != nil {
		return err
	}
	for path := range sources {
		if !seen[path] {
			if _, err := conn.ExecContext(ctx, "DELETE FROM audit_sources WHERE path = ?", path); err != nil {
				return err
			}
		}
	}
	return nil
}

// BackfillRollups indexes one bounded legacy ID range. Appends are already
// indexed in their own transactions and are not included in the backfill range.
func (s *Store) BackfillRollups(ctx context.Context, limit int) (int, error) {
	const stateQuery = `SELECT backfill_next_id, backfill_max_id, ready
		FROM audit_rollup_state WHERE singleton = 1`
	var start, maxID int64
	var ready bool
	err := s.db.QueryRowContext(ctx, stateQuery).Scan(&start, &maxID, &ready)
	if errors.Is(err, sql.ErrNoRows) || ready {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read audit rollup state: %w", err)
	}

	count := 0
	err = s.write(ctx, func(ctx context.Context, conn *sql.Conn) error {
		// The read above keeps normal polling lock-free. Recheck after acquiring
		// the write reservation because another process might have made progress.
		err := conn.QueryRowContext(ctx, stateQuery).Scan(&start, &maxID, &ready)
		if errors.Is(err, sql.ErrNoRows) || ready {
			return nil
		}
		if err != nil {
			return err
		}

		var end sql.NullInt64
		if err := conn.QueryRowContext(ctx, `
			SELECT count(*), max(id) FROM (
				SELECT id FROM audit_events WHERE id BETWEEN ? AND ? ORDER BY id LIMIT ?
			)`, start, maxID, max(1, limit)).Scan(&count, &end); err != nil {
			return err
		}
		if !end.Valid {
			_, err := conn.ExecContext(ctx, "UPDATE audit_rollup_state SET ready = 1 WHERE singleton = 1")
			return err
		}

		if err := dedupLegacy(ctx, conn, start, end.Int64); err != nil {
			return err
		}
		if err := indexAndRollup(ctx, conn, start, end.Int64, true); err != nil {
			return err
		}
		next := end.Int64
		if next < 1<<63-1 {
			next++
		}
		_, err = conn.ExecContext(ctx, `
			UPDATE audit_rollup_state SET backfill_next_id = ?, ready = ? WHERE singleton = 1`,
			next, end.Int64 >= maxID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("backfill audit rollups: %w", err)
	}
	return count, nil
}

func dedupLegacy(ctx context.Context, conn *sql.Conn, start, end int64) error {
	cutoff := dedupCutoff(time.Now())
	if err := pruneDedup(ctx, conn, cutoff); err != nil {
		return err
	}

	query := selectEvents + ` WHERE id BETWEEN ? AND ? AND occurred_second >= ?
		AND (action = 'read' OR share = 'FSLogix' COLLATE NOCASE) ORDER BY id`
	rows, err := conn.QueryContext(ctx, query, start, end, cutoff)
	if err != nil {
		return err
	}
	type candidate struct {
		key    [16]byte
		id     int64
		second int64
		path   string
	}
	var candidates []candidate
	for rows.Next() {
		event, second, err := scanEvent(rows)
		if err != nil {
			rows.Close()
			return err
		}
		stamp := event.Timestamp
		if at, err := eventTime(stamp); err == nil {
			stamp = at.UTC().Format(secondLayout)
		}
		candidates = append(candidates, candidate{fingerprint(event, stamp), event.ID, second, event.Path})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}

	register, err := conn.PrepareContext(ctx, `
		INSERT INTO audit_event_dedup (fingerprint, occurred_second, event_id) VALUES (?, ?, ?)
		ON CONFLICT (fingerprint) DO UPDATE SET event_id = coalesce(audit_event_dedup.event_id, excluded.event_id)
		RETURNING event_id`)
	if err != nil {
		return err
	}
	defer register.Close()

	for _, event := range candidates {
		var retained int64
		if err := register.QueryRowContext(ctx, event.key[:], event.second, event.id).Scan(&retained); err != nil {
			return err
		}
		if retained != event.id {
			query := `DELETE FROM audit_path_events
				WHERE path_id = (SELECT id FROM audit_paths WHERE path = ?) AND event_second = ? AND event_id = ?`
			if _, err := conn.ExecContext(ctx, query, event.path, event.second, event.id); err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "DELETE FROM audit_events WHERE id = ?", event.id); err != nil {
				return err
			}
		}
	}
	return nil
}

func indexAndRollup(ctx context.Context, conn *sql.Conn, start, end int64, backfill bool) error {
	if backfill {
		for _, query := range []string{
			`INSERT OR IGNORE INTO audit_paths (path)
			 SELECT DISTINCT path FROM audit_events WHERE id BETWEEN ? AND ?`,
			`UPDATE audit_events SET path_id = (SELECT id FROM audit_paths WHERE audit_paths.path = audit_events.path)
			 WHERE id BETWEEN ? AND ?`,
		} {
			if _, err := conn.ExecContext(ctx, query, start, end); err != nil {
				return err
			}
		}
	}

	// SQLite truncates integer division. Historically the backfill used that
	// behavior, whereas Python's live collector floors toward negative infinity.
	day := "occurred_second / 86400"
	if !backfill {
		day = "(" + day + " - (occurred_second % 86400 < 0))"
	}
	for _, query := range []string{
		`INSERT OR IGNORE INTO audit_path_events (path_id, event_second, event_id)
		 SELECT path_id, occurred_second, id FROM audit_events WHERE id BETWEEN ? AND ?`,
		fmt.Sprintf(`INSERT INTO audit_daily_totals (day, account, event_count)
		 SELECT %[1]s, account, count(*) FROM audit_events WHERE id BETWEEN ? AND ?
		 GROUP BY %[1]s, account
		 ON CONFLICT (day, account) DO UPDATE SET event_count = event_count + excluded.event_count`, day),
		fmt.Sprintf(`INSERT INTO audit_daily_counts (day, account, user, share, action, result, success, event_count)
		 SELECT %[1]s, account, user, share, action, result, success, count(*)
		 FROM audit_events WHERE id BETWEEN ? AND ? GROUP BY %[1]s, account, user, share, action, result, success
		 ON CONFLICT (day, account, user, share, action, result, success)
		 DO UPDATE SET event_count = event_count + excluded.event_count`, day),
	} {
		if _, err := conn.ExecContext(ctx, query, start, end); err != nil {
			return err
		}
	}
	for _, column := range []string{"user", "share", "action"} {
		query := fmt.Sprintf(`INSERT OR IGNORE INTO audit_daily_facets (kind, day, account, value)
			SELECT ?, %[1]s, account, %[2]s FROM audit_events
			WHERE id BETWEEN ? AND ? AND %[2]s <> '' GROUP BY %[1]s, account, %[2]s`, day, column)
		if _, err := conn.ExecContext(ctx, query, column, start, end); err != nil {
			return err
		}
	}
	return nil
}
