package documents

import (
	"context"
	"database/sql"
	"errors"
	"math"
)

type WorkerCounts struct {
	Total    int `json:"total"`
	Complete int `json:"complete"`
	Pending  int `json:"pending"`
	OCR      int `json:"ocr"`
	NameOnly int `json:"nameOnly"`
	Errors   int `json:"errors"`
}

type WorkerCurrent struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Pages  int    `json:"pages"`
	Source string `json:"source"`
	Kind   string `json:"kind"`
}

type WorkerActivity struct {
	ID        int64   `json:"id"`
	Timestamp float64 `json:"timestamp"`
	Action    string  `json:"action"`
	Path      string  `json:"path"`
	Source    string  `json:"source"`
	Actor     string  `json:"actor"`
	Message   string  `json:"message"`
}

type WorkerFailure struct {
	Name     string  `json:"name"`
	Path     string  `json:"path"`
	Source   string  `json:"source"`
	State    string  `json:"state"`
	Attempts int     `json:"attempts"`
	RetryAt  float64 `json:"retry_at"`
}

type WorkerStatus struct {
	ID        int              `json:"id"`
	Paused    bool             `json:"paused"`
	Heartbeat float64          `json:"heartbeat"`
	State     string           `json:"state"`
	CurrentID string           `json:"current_id"`
	Processed int64            `json:"processed"`
	Scanning  int              `json:"scanning"`
	LastScan  float64          `json:"last_scan"`
	Online    bool             `json:"online"`
	Counts    WorkerCounts     `json:"counts"`
	Progress  int              `json:"progress"`
	Current   *WorkerCurrent   `json:"current"`
	Activity  []WorkerActivity `json:"activity"`
	Failures  []WorkerFailure  `json:"failures"`
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqlExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func workerPaused(ctx context.Context, db rowQueryer) (bool, error) {
	var paused bool
	err := db.QueryRowContext(ctx, "SELECT paused FROM document_worker WHERE id=1").Scan(&paused)
	return paused, err
}

func workerEvent(ctx context.Context, db sqlExecer, action, path, source, actor, message string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO document_activity(timestamp,action,path,source,actor,message) VALUES(?,?,?,?,?,?)`,
		unixTime(), action, path, source, actor, limitRunes(message, 200))
	return err
}

func ControlWorker(ctx context.Context, db *sql.DB, action, actor string) (WorkerStatus, error) {
	if action != "pause" && action != "resume" {
		return WorkerStatus{}, searchError("Ungültige Aktion")
	}

	err := immediate(ctx, db, func(conn *sql.Conn) error {
		paused, err := workerPaused(ctx, conn)
		if err != nil || paused == (action == "pause") {
			return err
		}
		if _, err := conn.ExecContext(ctx, "UPDATE document_worker SET paused=? WHERE id=1", action == "pause"); err != nil {
			return err
		}
		return workerEvent(ctx, conn, action, "", "", actor, "")
	})
	if err != nil {
		return WorkerStatus{}, err
	}
	return WorkerSnapshot(ctx, db)
}

func WorkerSnapshot(ctx context.Context, db *sql.DB) (WorkerStatus, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return WorkerStatus{}, err
	}
	defer tx.Rollback()

	status := WorkerStatus{Activity: []WorkerActivity{}, Failures: []WorkerFailure{}}
	err = tx.QueryRowContext(ctx, `SELECT id,paused,heartbeat,state,current_id,processed,scanning,last_scan FROM document_worker WHERE id=1`).
		Scan(&status.ID, &status.Paused, &status.Heartbeat, &status.State, &status.CurrentID, &status.Processed, &status.Scanning, &status.LastScan)
	if err != nil {
		return WorkerStatus{}, err
	}
	status.Online = status.Heartbeat > unixTime()-15

	counts := &status.Counts
	err = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(state IN ('ready','name-only')),0),coalesce(sum(state='pending'),0),
		coalesce(sum(state='ocr'),0),coalesce(sum(state='name-only'),0),coalesce(sum(state='failed' OR attempts>0),0) FROM documents`).
		Scan(&counts.Total, &counts.Complete, &counts.Pending, &counts.OCR, &counts.NameOnly, &counts.Errors)
	if err != nil {
		return WorkerStatus{}, err
	}
	if counts.Total != 0 {
		status.Progress = int(math.RoundToEven(100 * float64(counts.Complete) / float64(counts.Total)))
	}

	const label = `CASE WHEN s.kind='private' THEN s.label || ' / ' || substr(s.id,9) ELSE s.label END`
	var current WorkerCurrent
	err = tx.QueryRowContext(ctx, `SELECT d.name,d.path,d.pages,`+label+`,s.kind
		FROM documents d JOIN document_sources s ON s.id=d.source_id WHERE d.id=?`, status.CurrentID).
		Scan(&current.Name, &current.Path, &current.Pages, &current.Source, &current.Kind)
	if err == nil {
		status.Current = &current
	} else if !errors.Is(err, sql.ErrNoRows) {
		return WorkerStatus{}, err
	}

	activity, err := tx.QueryContext(ctx, `SELECT id,timestamp,action,path,source,actor,message FROM document_activity ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return WorkerStatus{}, err
	}
	defer activity.Close()
	for activity.Next() {
		var entry WorkerActivity
		if err := activity.Scan(&entry.ID, &entry.Timestamp, &entry.Action, &entry.Path, &entry.Source, &entry.Actor, &entry.Message); err != nil {
			return WorkerStatus{}, err
		}
		status.Activity = append(status.Activity, entry)
	}
	if err := activity.Err(); err != nil {
		return WorkerStatus{}, err
	}

	failures, err := tx.QueryContext(ctx, `SELECT d.name,d.path,`+label+`,d.state,d.attempts,d.retry_at
		FROM documents d JOIN document_sources s ON s.id=d.source_id
		WHERE d.state='failed' OR d.attempts>0 ORDER BY d.retry_at LIMIT 50`)
	if err != nil {
		return WorkerStatus{}, err
	}
	defer failures.Close()
	for failures.Next() {
		var entry WorkerFailure
		if err := failures.Scan(&entry.Name, &entry.Path, &entry.Source, &entry.State, &entry.Attempts, &entry.RetryAt); err != nil {
			return WorkerStatus{}, err
		}
		status.Failures = append(status.Failures, entry)
	}
	return status, failures.Err()
}
