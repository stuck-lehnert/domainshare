CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    occurred_second INTEGER NOT NULL,
    ingested_at TEXT NOT NULL,
    user TEXT NOT NULL,
    account TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client TEXT NOT NULL,
    share TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('read', 'write', 'move', 'delete')),
    result TEXT NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    path TEXT NOT NULL,
    path_id INTEGER,
    source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_sources (
    path TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit_event_dedup (
    fingerprint BLOB PRIMARY KEY,
    occurred_second INTEGER NOT NULL,
    event_id INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS audit_event_dedup_time
    ON audit_event_dedup (occurred_second);
CREATE INDEX IF NOT EXISTS audit_events_main_time
    ON audit_events (occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_main_action_time
    ON audit_events (action, occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_main_success_time
    ON audit_events (success, occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_main_user_time
    ON audit_events (user COLLATE NOCASE, occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_main_account_time
    ON audit_events (account, occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_main_share_time
    ON audit_events (share COLLATE NOCASE, occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_main_result_time
    ON audit_events (result COLLATE NOCASE, occurred_second DESC, id DESC)
    WHERE share <> 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_fslogix_time
    ON audit_events (occurred_second DESC, id DESC)
    WHERE share = 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_fslogix_action_time
    ON audit_events (action, occurred_second DESC, id DESC)
    WHERE share = 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_fslogix_success_time
    ON audit_events (success, occurred_second DESC, id DESC)
    WHERE share = 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_fslogix_user_time
    ON audit_events (user COLLATE NOCASE, occurred_second DESC, id DESC)
    WHERE share = 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_fslogix_account_time
    ON audit_events (account, occurred_second DESC, id DESC)
    WHERE share = 'FSLogix' COLLATE NOCASE;
CREATE INDEX IF NOT EXISTS audit_events_fslogix_result_time
    ON audit_events (result COLLATE NOCASE, occurred_second DESC, id DESC)
    WHERE share = 'FSLogix' COLLATE NOCASE;

CREATE TABLE IF NOT EXISTS audit_paths (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE
);
CREATE VIRTUAL TABLE IF NOT EXISTS audit_paths_fts USING fts5(
    path,
    content = 'audit_paths',
    content_rowid = 'id',
    tokenize = 'trigram'
);
CREATE TRIGGER IF NOT EXISTS audit_paths_insert
AFTER INSERT ON audit_paths BEGIN
    INSERT INTO audit_paths_fts (rowid, path) VALUES (new.id, new.path);
END;
CREATE TABLE IF NOT EXISTS audit_path_events (
    path_id INTEGER NOT NULL,
    event_second INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    PRIMARY KEY (path_id, event_second DESC, event_id DESC)
) WITHOUT ROWID;


CREATE TABLE IF NOT EXISTS audit_daily_totals (
    day INTEGER NOT NULL,
    account TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    PRIMARY KEY (day, account)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit_daily_counts (
    day INTEGER NOT NULL,
    account TEXT NOT NULL,
    user TEXT COLLATE NOCASE NOT NULL,
    share TEXT COLLATE NOCASE NOT NULL,
    action TEXT NOT NULL,
    result TEXT COLLATE NOCASE NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    event_count INTEGER NOT NULL,
    PRIMARY KEY (day, account, user, share, action, result, success)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit_daily_facets (
    kind TEXT NOT NULL,
    day INTEGER NOT NULL,
    account TEXT NOT NULL,
    value TEXT COLLATE NOCASE NOT NULL,
    PRIMARY KEY (kind, day, account, value)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS audit_rollup_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    backfill_next_id INTEGER NOT NULL,
    backfill_max_id INTEGER NOT NULL,
    ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
    policy_version INTEGER NOT NULL DEFAULT 5
);
