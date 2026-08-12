#!/usr/bin/env python3
"""Indexed SQLite storage for normalized Samba audit events."""

import datetime as dt
import glob
import os
import sqlite3
from collections import Counter
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    from .audit_policy import (
        account_name,
        deduplication_fingerprint,
        deduplication_fingerprint_values,
        skipped_user_suffixes,
    )
    from .state_db import connect_state_db
except ImportError:
    from audit_policy import (
        account_name,
        deduplication_fingerprint,
        deduplication_fingerprint_values,
        skipped_user_suffixes,
    )
    from state_db import connect_state_db


AUDIT_SCHEMA = """
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

"""

ROLLUP_TOTAL_SQL = """
INSERT INTO audit_daily_totals (day, account, event_count)
VALUES (?, ?, ?)
ON CONFLICT (day, account) DO UPDATE SET
    event_count = event_count + excluded.event_count
"""

ROLLUP_COUNT_SQL = """
INSERT INTO audit_daily_counts (
    day, account, user, share, action, result, success, event_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (day, account, user, share, action, result, success) DO UPDATE SET
    event_count = event_count + excluded.event_count
"""

ROLLUP_FACET_SQL = """
INSERT OR IGNORE INTO audit_daily_facets (kind, day, account, value)
VALUES (?, ?, ?, ?)
"""


def ensure_audit_schema(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE IF EXISTS audit_read_dedup")
    conn.executescript(AUDIT_SCHEMA)
    for legacy_index in (
        "audit_events_time",
        "audit_events_action_time",
        "audit_events_success_time",
        "audit_events_user_time",
        "audit_events_account_time",
        "audit_events_share_time",
        "audit_events_result_time",
    ):
        conn.execute(f"DROP INDEX IF EXISTS {legacy_index}")

    columns = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(audit_events)")
    }
    if "path_id" not in columns:
        conn.execute("ALTER TABLE audit_events ADD COLUMN path_id INTEGER")

    state_columns = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(audit_rollup_state)")
    }
    if "policy_version" not in state_columns:
        conn.execute(
            "ALTER TABLE audit_rollup_state "
            "ADD COLUMN policy_version INTEGER NOT NULL DEFAULT 1"
        )

    max_id = int(
        conn.execute("SELECT coalesce(max(id), 0) FROM audit_events").fetchone()[0]
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO audit_rollup_state (
            singleton, backfill_next_id, backfill_max_id, ready
        ) VALUES (1, 1, ?, ?)
        """,
        (max_id, int(max_id == 0)),
    )
    state = conn.execute(
        """
        SELECT ready, policy_version
        FROM audit_rollup_state
        WHERE singleton = 1
        """
    ).fetchone()
    if state is not None and int(state["policy_version"]) < 5:
        conn.execute("DELETE FROM audit_event_dedup")
        for table in (
            "audit_daily_totals",
            "audit_daily_counts",
            "audit_daily_facets",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.execute(
            """
            UPDATE audit_rollup_state
            SET backfill_next_id = 1, backfill_max_id = ?, ready = ?,
                policy_version = 5
            WHERE singleton = 1
            """,
            (max_id, int(max_id == 0)),
        )
    conn.commit()


DEDUP_DEFAULT_WINDOW_SECONDS = 2 * 86400


def deduplication_cutoff() -> int:
    configured = os.getenv(
        "AUDIT_DEDUP_WINDOW_SECONDS",
        os.getenv(
            "AUDIT_READ_DEDUP_WINDOW_SECONDS",
            str(DEDUP_DEFAULT_WINDOW_SECONDS),
        ),
    )
    try:
        window = int(configured)
    except ValueError:
        window = DEDUP_DEFAULT_WINDOW_SECONDS
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    return now - max(1, window)


def parse_event_second(timestamp: object) -> int:
    parsed = dt.datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return int(parsed.astimezone(dt.timezone.utc).timestamp())


def row_to_event(row: sqlite3.Row) -> Dict[str, object]:
    action = str(row["action"])
    return {
        "id": int(row["id"]),
        "timestamp": str(row["occurred_at"]),
        "ingestedAt": str(row["ingested_at"]),
        "user": str(row["user"]),
        "clientIp": str(row["client_ip"]),
        "client": str(row["client"]),
        "share": str(row["share"]),
        "operation": action,
        "action": action,
        "result": str(row["result"]),
        "success": bool(row["success"]),
        "path": str(row["path"]),
        "source": str(row["source"]),
    }


class AuditStore:
    def __init__(self, database_path: Optional[str] = None):
        self.conn = connect_state_db(database_path)
        self.conn.create_function(
            "audit_event_fingerprint", 8,
            deduplication_fingerprint_values, deterministic=True,
        )
        ensure_audit_schema(self.conn)

    def close(self) -> None:
        self.conn.close()

    def source_entries(self) -> Dict[str, Dict[str, object]]:
        return {
            str(row["path"]): {
                "inode": int(row["inode"]),
                "offset": int(row["offset"]),
            }
            for row in self.conn.execute(
                "SELECT path, inode, offset FROM audit_sources"
            )
        }

    def append_batch(
        self,
        events: Iterable[Dict[str, object]],
        source_updates: Dict[str, Dict[str, object]],
        seen_paths: Set[str],
    ) -> int:
        event_rows = []
        totals = Counter()
        counts = Counter()
        facets = set()
        seen_fingerprints = set()
        for event in events:
            fingerprint = deduplication_fingerprint(event)
            if (
                fingerprint is not None
                and fingerprint in seen_fingerprints
            ):
                continue
            occurred_second = parse_event_second(event["timestamp"])
            user = str(event["user"])
            account = account_name(user).casefold()
            share = str(event["share"])
            action = str(event["action"])
            result = str(event["result"])
            success = int(bool(event["success"]))
            event_rows.append(
                (
                    str(event["timestamp"]),
                    occurred_second,
                    str(event["ingestedAt"]),
                    user,
                    account,
                    str(event["clientIp"]),
                    str(event["client"]),
                    share,
                    action,
                    result,
                    success,
                    str(event["path"]),
                    str(event["source"]),
                    fingerprint,
                )
            )
            if fingerprint is not None:
                seen_fingerprints.add(fingerprint)

        self.conn.execute("BEGIN IMMEDIATE")
        try:
            fingerprints = [
                row[13] for row in event_rows if row[13] is not None
            ]
            existing_fingerprints = set()
            for offset in range(0, len(fingerprints), 500):
                chunk = fingerprints[offset : offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                existing_fingerprints.update(
                    bytes(row[0])
                    for row in self.conn.execute(
                        f"""
                        SELECT fingerprint
                        FROM audit_event_dedup
                        WHERE fingerprint IN ({placeholders})
                        """,
                        chunk,
                    )
                )
            if existing_fingerprints:
                event_rows = [
                    row
                    for row in event_rows
                    if (
                        row[13] is None
                        or row[13] not in existing_fingerprints
                    )
                ]

            for row in event_rows:
                day = int(row[1]) // 86400
                account = str(row[4])
                user = str(row[3])
                share = str(row[7])
                action = str(row[8])
                result = str(row[9])
                success = int(row[10])
                totals[(day, account)] += 1
                counts[(
                    day, account, user, share, action, result, success
                )] += 1
                for kind, value in (
                    ("user", user),
                    ("share", share),
                    ("action", action),
                ):
                    if value:
                        facets.add((kind, day, account, value))

            if event_rows:
                paths = sorted({str(row[11]) for row in event_rows})
                self.conn.executemany(
                    "INSERT OR IGNORE INTO audit_paths (path) VALUES (?)",
                    ((path,) for path in paths),
                )
                path_ids = {}
                for offset in range(0, len(paths), 500):
                    path_chunk = paths[offset : offset + 500]
                    placeholders = ",".join("?" for _ in path_chunk)
                    for row in self.conn.execute(
                        f"""
                        SELECT id, path
                        FROM audit_paths
                        WHERE path IN ({placeholders})
                        """,
                        path_chunk,
                    ):
                        path_ids[str(row["path"])] = int(row["id"])
                indexed_rows = [
                    (*row[:12], path_ids[str(row[11])], row[12])
                    for row in event_rows
                ]
                self.conn.executemany(
                    """
                    INSERT INTO audit_events (
                        occurred_at, occurred_second, ingested_at, user, account,
                        client_ip, client, share, action, result, success, path,
                        path_id, source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    indexed_rows,
                )
                self.conn.execute(
                    """
                    INSERT OR IGNORE INTO audit_path_events (
                        path_id, event_second, event_id
                    )
                    SELECT path_id, occurred_second, id
                    FROM audit_events
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (len(indexed_rows),),
                )
                last_inserted_id = int(
                    self.conn.execute(
                        "SELECT max(id) FROM audit_events"
                    ).fetchone()[0]
                )
                first_inserted_id = last_inserted_id - len(event_rows) + 1
                self.conn.executemany(
                    """
                    INSERT INTO audit_event_dedup (
                        fingerprint, occurred_second, event_id
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        (row[13], int(row[1]), first_inserted_id + offset)
                        for offset, row in enumerate(event_rows)
                        if row[13] is not None
                    ),
                )
                self.conn.executemany(
                    ROLLUP_TOTAL_SQL,
                    ((*key, count) for key, count in totals.items()),
                )
                self.conn.executemany(
                    ROLLUP_COUNT_SQL,
                    ((*key, count) for key, count in counts.items()),
                )
                self.conn.executemany(ROLLUP_FACET_SQL, facets)

            self.conn.execute(
                "DELETE FROM audit_event_dedup WHERE occurred_second < ?",
                (deduplication_cutoff(),),
            )

            if source_updates:
                self.conn.executemany(
                    """
                    INSERT INTO audit_sources (path, inode, offset)
                    VALUES (?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        inode = excluded.inode,
                        offset = excluded.offset
                    """,
                    (
                        (path, int(entry["inode"]), int(entry["offset"]))
                        for path, entry in source_updates.items()
                    ),
                )
            missing_paths = [
                (str(row["path"]),)
                for row in self.conn.execute("SELECT path FROM audit_sources")
                if str(row["path"]) not in seen_paths
            ]
            if missing_paths:
                self.conn.executemany(
                    "DELETE FROM audit_sources WHERE path = ?", missing_paths
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return len(event_rows)

    def backfill_rollups(self, limit: int = 5000) -> int:
        """Backfill one bounded legacy-event chunk without delaying live appends."""
        state = self.conn.execute(
            """
            SELECT backfill_next_id, backfill_max_id, ready
            FROM audit_rollup_state
            WHERE singleton = 1
            """
        ).fetchone()
        if state is None or bool(state["ready"]):
            return 0
        start_id = int(state["backfill_next_id"])
        max_id = int(state["backfill_max_id"])
        chunk = self.conn.execute(
            """
            SELECT count(*), max(id)
            FROM (
                SELECT id
                FROM audit_events
                WHERE id >= ? AND id <= ?
                ORDER BY id
                LIMIT ?
            )
            """,
            (start_id, max_id, max(1, limit)),
        ).fetchone()
        row_count = int(chunk[0])
        if row_count == 0:
            self.conn.execute(
                "UPDATE audit_rollup_state SET ready = 1 WHERE singleton = 1"
            )
            self.conn.commit()
            return 0

        end_id = int(chunk[1])
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            dedup_cutoff = deduplication_cutoff()
            self.conn.execute(
                "DELETE FROM audit_event_dedup WHERE occurred_second < ?",
                (dedup_cutoff,),
            )
            self.conn.execute(
                """
                INSERT INTO audit_event_dedup (
                    fingerprint, occurred_second, event_id
                )
                SELECT audit_event_fingerprint(
                           e.occurred_at, e.action, e.user, e.client_ip, e.share, e.path,
                           e.success, e.result
                       ), e.occurred_second, e.id
                FROM audit_events AS e
                WHERE e.id BETWEEN ? AND ?
                    AND (e.action = 'read' OR e.share = 'FSLogix' COLLATE NOCASE)
                    AND e.occurred_second >= ?
                ORDER BY e.id
                ON CONFLICT (fingerprint) DO UPDATE SET
                    event_id = coalesce(
                        audit_event_dedup.event_id, excluded.event_id
                    )
                """,
                (start_id, end_id, dedup_cutoff),
            )
            duplicate_event_sql = """
                SELECT e.id
                FROM audit_events AS e
                JOIN audit_event_dedup AS d
                  ON d.fingerprint = audit_event_fingerprint(
                      e.occurred_at, e.action, e.user, e.client_ip, e.share, e.path,
                      e.success, e.result
                  )
                WHERE e.id BETWEEN ? AND ?
                    AND (e.action = 'read' OR e.share = 'FSLogix' COLLATE NOCASE)
                    AND e.occurred_second >= ?
                    AND (d.event_id IS NULL OR d.event_id <> e.id)
            """
            self.conn.execute(
                f"DELETE FROM audit_path_events "
                f"WHERE event_id IN ({duplicate_event_sql})",
                (start_id, end_id, dedup_cutoff),
            )
            self.conn.execute(
                f"DELETE FROM audit_events "
                f"WHERE id IN ({duplicate_event_sql})",
                (start_id, end_id, dedup_cutoff),
            )
            self.conn.execute(
                """
                INSERT OR IGNORE INTO audit_paths (path)
                SELECT DISTINCT path
                FROM audit_events
                WHERE id BETWEEN ? AND ?
                """,
                (start_id, end_id),
            )
            self.conn.execute(
                """
                UPDATE audit_events
                SET path_id = (
                    SELECT id
                    FROM audit_paths
                    WHERE audit_paths.path = audit_events.path
                )
                WHERE id BETWEEN ? AND ?
                """,
                (start_id, end_id),
            )
            self.conn.execute(
                """
                INSERT OR IGNORE INTO audit_path_events (
                    path_id, event_second, event_id
                )
                SELECT path_id, occurred_second, id
                FROM audit_events
                WHERE id BETWEEN ? AND ?
                """,
                (start_id, end_id),
            )

            self.conn.execute(
                """
                INSERT INTO audit_daily_totals (day, account, event_count)
                SELECT occurred_second / 86400, account, count(*)
                FROM audit_events
                WHERE id BETWEEN ? AND ?
                GROUP BY occurred_second / 86400, account
                ON CONFLICT (day, account) DO UPDATE SET
                    event_count = event_count + excluded.event_count
                """,
                (start_id, end_id),
            )
            self.conn.execute(
                """
                INSERT INTO audit_daily_counts (
                    day, account, user, share, action, result, success, event_count
                )
                SELECT occurred_second / 86400, account, user, share, action,
                       result, success, count(*)
                FROM audit_events
                WHERE id BETWEEN ? AND ?
                GROUP BY occurred_second / 86400, account, user, share, action,
                         result, success
                ON CONFLICT (
                    day, account, user, share, action, result, success
                ) DO UPDATE SET
                    event_count = event_count + excluded.event_count
                """,
                (start_id, end_id),
            )
            for kind, column in (
                ("user", "user"),
                ("share", "share"),
                ("action", "action"),
            ):
                self.conn.execute(
                    f"""
                    INSERT OR IGNORE INTO audit_daily_facets (
                        kind, day, account, value
                    )
                    SELECT ?, occurred_second / 86400, account, {column}
                    FROM audit_events
                    WHERE id BETWEEN ? AND ?
                        AND {column} <> ''
                    GROUP BY occurred_second / 86400, account, {column}
                    """,
                    (kind, start_id, end_id),
                )
            finished = end_id >= max_id
            self.conn.execute(
                """
                UPDATE audit_rollup_state
                SET backfill_next_id = ?, ready = ?
                WHERE singleton = 1
                """,
                (end_id + 1, int(finished)),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return row_count



def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def date_seconds(day: dt.date) -> int:
    return int(
        dt.datetime.combine(day, dt.time.min, tzinfo=dt.timezone.utc).timestamp()
    )


def activity_filters(params: Dict[str, List[str]]) -> Dict[str, str]:
    return {
        key: params.get(key, [""])[0].casefold().strip()
        for key in ("user", "share", "operation", "action", "path", "result")
    }


def query_flag(
    params: Dict[str, List[str]], name: str, *, default: bool = True
) -> bool:
    fallback = "1" if default else "0"
    return params.get(name, [fallback])[0].strip().casefold() not in {
        "0",
        "false",
        "no",
        "off",
    }


def excluded_account_conditions() -> Tuple[List[str], List[object]]:
    conditions: List[str] = []
    values: List[object] = []
    for suffix in skipped_user_suffixes():
        conditions.append("account NOT LIKE ? ESCAPE '\\'")
        values.append(f"%{escape_like(suffix)}")
    return conditions, values


def activity_stream_condition(stream: str) -> str:
    if stream == "main":
        return "share <> 'FSLogix' COLLATE NOCASE"
    if stream == "fslogix":
        return "share = 'FSLogix' COLLATE NOCASE"
    raise ValueError("Ungültiger Aktivitätsstrom")


def activity_conditions(
    start: dt.date,
    end: dt.date,
    params: Dict[str, List[str]],
    *,
    stream: str,
    include_filters: bool,
    include_path: bool = True,
) -> Tuple[List[str], List[object]]:
    conditions = [
        "occurred_second >= ?",
        "occurred_second < ?",
        activity_stream_condition(stream),
    ]
    values: List[object] = [
        date_seconds(start),
        date_seconds(end + dt.timedelta(days=1)),
    ]
    excluded_conditions, excluded_values = excluded_account_conditions()
    conditions.extend(excluded_conditions)
    values.extend(excluded_values)

    if not include_filters:
        return conditions, values

    filters = activity_filters(params)
    user = filters["user"]
    if user:
        if "\\" in user or "@" in user:
            conditions.append("user = ? COLLATE NOCASE")
        else:
            conditions.append("account = ?")
        values.append(user)
    share = filters["share"]
    if share:
        conditions.append("share = ? COLLATE NOCASE")
        values.append(share)
    path = filters["path"]
    if path and include_path:
        conditions.append("lower(path) LIKE ? ESCAPE '\\'")
        values.append(f"%{escape_like(path)}%")
    action = filters["action"] or filters["operation"]
    if action:
        conditions.append("action = ?")
        values.append(action)
    result = filters["result"]
    if result == "fail":
        conditions.append("success = 0")
    elif result:
        conditions.append("result = ? COLLATE NOCASE")
        values.append(result)
    return conditions, values


def rollup_status(conn: sqlite3.Connection) -> Dict[str, object]:
    try:
        row = conn.execute(
            """
            SELECT backfill_next_id, backfill_max_id, ready
            FROM audit_rollup_state
            WHERE singleton = 1
            """
        ).fetchone()
    except sqlite3.Error:
        row = None
    if row is None:
        return {
            "ready": False,
            "processedEvents": 0,
            "totalEvents": 0,
            "percent": 0.0,
        }

    total = max(0, int(row["backfill_max_id"]))
    ready = bool(row["ready"])
    processed = (
        total
        if ready
        else min(total, max(0, int(row["backfill_next_id"]) - 1))
    )
    percent = (
        100.0
        if ready or total == 0
        else round(processed * 100 / total, 1)
    )
    return {
        "ready": ready,
        "processedEvents": processed,
        "totalEvents": total,
        "percent": percent,
    }



def rollup_range(
    start: dt.date, end: dt.date
) -> Tuple[List[str], List[object]]:
    conditions = ["day >= ?", "day <= ?"]
    values: List[object] = [
        date_seconds(start) // 86400,
        date_seconds(end) // 86400,
    ]
    excluded_conditions, excluded_values = excluded_account_conditions()
    conditions.extend(excluded_conditions)
    values.extend(excluded_values)
    return conditions, values


def rollup_matched(
    conn: sqlite3.Connection,
    start: dt.date,
    end: dt.date,
    params: Dict[str, List[str]],
    *,
    stream: str,
) -> Optional[int]:
    filters = activity_filters(params)
    if filters["path"]:
        return None

    conditions, values = rollup_range(start, end)
    conditions.append(activity_stream_condition(stream))
    user = filters["user"]
    if user:
        if "\\" in user or "@" in user:
            conditions.append("user = ? COLLATE NOCASE")
        else:
            conditions.append("account = ?")
        values.append(user)
    if filters["share"]:
        conditions.append("share = ? COLLATE NOCASE")
        values.append(filters["share"])
    action = filters["action"] or filters["operation"]
    if action:
        conditions.append("action = ?")
        values.append(action)
    result = filters["result"]
    if result == "fail":
        conditions.append("success = 0")
    elif result:
        conditions.append("result = ? COLLATE NOCASE")
        values.append(result)

    row = conn.execute(
        f"""
        SELECT coalesce(sum(event_count), 0)
        FROM audit_daily_counts
        WHERE {" AND ".join(conditions)}
        """,
        values,
    ).fetchone()
    return int(row[0])


def rollup_facets(
    conn: sqlite3.Connection,
    start: dt.date,
    end: dt.date,
    *,
    stream: str,
) -> Dict[str, List[str]]:
    range_conditions, range_values = rollup_range(start, end)

    def distinct(column: str) -> List[str]:
        conditions = [
            *range_conditions,
            activity_stream_condition(stream),
            f"{column} <> ?",
        ]
        return [
            str(row[0])
            for row in conn.execute(
                f"""
                SELECT DISTINCT {column}
                FROM audit_daily_counts
                WHERE {" AND ".join(conditions)}
                ORDER BY {column} COLLATE NOCASE
                """,
                (*range_values, ""),
            )
        ]

    actions = distinct("action")
    return {
        "users": distinct("user"),
        "shares": distinct("share"),
        "operations": actions,
        "actions": actions,
    }


def indexed_path_ids(
    conn: sqlite3.Connection, path: str, *, maximum: int = 500
) -> Optional[List[int]]:
    if len(path) < 3:
        return None
    phrase = '"' + path.replace('"', '""') + '"'
    try:
        rows = conn.execute(
            """
            SELECT rowid
            FROM audit_paths_fts
            WHERE audit_paths_fts MATCH ?
            LIMIT ?
            """,
            (phrase, maximum + 1),
        ).fetchall()
    except sqlite3.Error:
        return None
    if len(rows) > maximum:
        return None
    return [int(row[0]) for row in rows]



def path_event_set_is_selective(
    conn: sqlite3.Connection,
    path_ids: List[int],
    start: dt.date,
    end: dt.date,
    *,
    maximum_events: int = 5000,
) -> bool:
    placeholders = ",".join("?" for _ in path_ids)
    row = conn.execute(
        f"""
        SELECT count(*)
        FROM (
            SELECT 1
            FROM audit_path_events
            WHERE path_id IN ({placeholders})
              AND event_second >= ? AND event_second < ?
            LIMIT ?
        )
        """,
        (
            *path_ids,
            date_seconds(start),
            date_seconds(end + dt.timedelta(days=1)),
            maximum_events + 1,
        ),
    ).fetchone()
    return int(row[0]) <= maximum_events


def query_activity(
    conn: sqlite3.Connection,
    start: dt.date,
    end: dt.date,
    params: Dict[str, List[str]],
    *,
    stream: str = "main",
) -> Dict[str, object]:
    limit = min(500, max(1, int(params.get("limit", ["100"])[0])))
    indexing = rollup_status(conn)
    ready = bool(indexing["ready"])
    path = activity_filters(params)["path"]
    path_ids = indexed_path_ids(conn, path) if ready and path else None
    if (
        path_ids
        and len(path_ids) > 1
        and not path_event_set_is_selective(conn, path_ids, start, end)
    ):
        path_ids = None
    conditions, values = activity_conditions(
        start,
        end,
        params,
        stream=stream,
        include_filters=True,
        include_path=path_ids is None,
    )
    single_path_id = None
    if path_ids is not None:
        if len(path_ids) == 1:
            single_path_id = path_ids[0]
        elif path_ids:
            path_placeholders = ",".join("?" for _ in path_ids)
            conditions.append(
                f"id IN (SELECT event_id FROM audit_path_events "
                f"WHERE path_id IN ({path_placeholders}) "
                "AND event_second >= ? AND event_second < ?)"
            )
            values.extend(path_ids)
            values.extend(
                (date_seconds(start), date_seconds(end + dt.timedelta(days=1)))
            )
        else:
            conditions.append("0")

    cursor = params.get("cursor", [""])[0].strip()
    page_conditions = list(conditions)
    page_values = list(values)
    from_sql = "audit_events"
    order_sql = "occurred_second DESC, id DESC"
    if single_path_id is not None:
        from_sql = (
            "audit_path_events AS pe "
            "CROSS JOIN audit_events ON id = pe.event_id"
        )
        order_sql = "pe.event_second DESC, pe.event_id DESC"
        page_conditions.extend(
            ["pe.path_id = ?", "pe.event_second >= ?", "pe.event_second < ?"]
        )
        page_values.extend(
            (
                single_path_id,
                date_seconds(start),
                date_seconds(end + dt.timedelta(days=1)),
            )
        )
    if cursor:
        try:
            cursor_second, cursor_id = (int(part) for part in cursor.split(":", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError("Ungültiger Seitenzeiger") from exc
        cursor_condition = (
            "(pe.event_second < ? OR "
            "(pe.event_second = ? AND pe.event_id < ?))"
            if single_path_id is not None
            else "(occurred_second < ? OR (occurred_second = ? AND id < ?))"
        )
        page_conditions.append(cursor_condition)
        page_values.extend((cursor_second, cursor_second, cursor_id))
    rows = conn.execute(
        f"""
        SELECT id, occurred_at, occurred_second, ingested_at, user, client_ip,
               client, share, action, result, success, path, source
        FROM {from_sql}
        WHERE {" AND ".join(page_conditions)}
        ORDER BY {order_sql}
        LIMIT ?
        """,
        (*page_values, limit + 1),
    ).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    events = [row_to_event(row) for row in rows]
    next_cursor = None
    if has_more and rows:
        next_cursor = f"{int(rows[-1]['occurred_second'])}:{int(rows[-1]['id'])}"

    include_count = query_flag(params, "count")
    matched: Optional[int] = None
    if include_count and ready:
        matched = rollup_matched(conn, start, end, params, stream=stream)
    if include_count and matched is None and not cursor and not has_more:
        matched = len(events)

    empty_facets = {
        "users": [],
        "shares": [],
        "operations": [],
        "actions": [],
    }
    include_facets = query_flag(params, "facets")
    facets = (
        rollup_facets(conn, start, end, stream=stream)
        if include_facets and ready
        else empty_facets
    )

    return {
        "events": events,
        "hasMore": has_more,
        "nextCursor": next_cursor,
        "matched": matched,
        "matchedExact": matched is not None,
        "facets": facets,
        "indexing": indexing,
        "stream": stream,
    }


def audit_summary(conn: sqlite3.Connection, database_path: str) -> Dict[str, object]:
    indexing = rollup_status(conn)

    def second_day(value: object) -> Optional[str]:
        if value is None:
            return None
        return dt.datetime.fromtimestamp(
            int(value), tz=dt.timezone.utc
        ).date().isoformat()

    if indexing["ready"]:
        row = conn.execute(
            """
            SELECT count(DISTINCT day), min(day), max(day)
            FROM audit_daily_counts
            WHERE share <> 'FSLogix' COLLATE NOCASE
            """
        ).fetchone()
        days = int(row[0] or 0)
        oldest = second_day(None if row[1] is None else int(row[1]) * 86400)
        newest = second_day(None if row[2] is None else int(row[2]) * 86400)
    else:
        oldest_row = conn.execute(
            """
            SELECT occurred_second FROM audit_events
            WHERE share <> 'FSLogix' COLLATE NOCASE
            ORDER BY occurred_second, id LIMIT 1
            """
        ).fetchone()
        newest_row = conn.execute(
            """
            SELECT occurred_second FROM audit_events
            WHERE share <> 'FSLogix' COLLATE NOCASE
            ORDER BY occurred_second DESC, id DESC LIMIT 1
            """
        ).fetchone()
        oldest = second_day(oldest_row[0]) if oldest_row else None
        newest = second_day(newest_row[0]) if newest_row else None
        days = (
            (dt.date.fromisoformat(newest) - dt.date.fromisoformat(oldest)).days + 1
            if oldest and newest
            else 0
        )

    database_bytes = 0
    for suffix in ("", "-wal"):
        try:
            database_bytes += os.path.getsize(f"{database_path}{suffix}")
        except OSError:
            pass
    return {
        "days": days,
        "bytes": database_bytes,
        "oldest": oldest,
        "newest": newest,
        "indexing": indexing,
    }


def drop_legacy_audit_files(directory: str) -> int:
    removed = 0
    patterns = (
        "????-??-??.jsonl",
        "????-??-??.jsonl.gz",
        "collector-state.json",
        "collector-state.json.tmp",
    )
    for pattern in patterns:
        for path in glob.glob(os.path.join(directory, pattern)):
            if not os.path.isfile(path):
                continue
            os.remove(path)
            removed += 1
    try:
        os.rmdir(directory)
    except OSError:
        pass
    return removed
