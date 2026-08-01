#!/usr/bin/env python3
"""Indexed SQLite storage for normalized Samba audit events."""

import datetime as dt
import glob
import os
import sqlite3
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    from .audit_policy import (
        account_name,
        read_deduplication_key,
        skipped_user_suffixes,
    )
    from .state_db import connect_state_db
except ImportError:
    from audit_policy import account_name, read_deduplication_key, skipped_user_suffixes
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
    source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_sources (
    path TEXT PRIMARY KEY,
    inode INTEGER NOT NULL,
    offset INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS audit_events_time
    ON audit_events (occurred_second DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_action_time
    ON audit_events (action, occurred_second DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_success_time
    ON audit_events (success, occurred_second DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_user_time
    ON audit_events (user COLLATE NOCASE, occurred_second DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_account_time
    ON audit_events (account, occurred_second DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_share_time
    ON audit_events (share COLLATE NOCASE, occurred_second DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_result_time
    ON audit_events (result COLLATE NOCASE, occurred_second DESC, id DESC);
"""


def ensure_audit_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(AUDIT_SCHEMA)
    conn.commit()


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


def last_event(conn: sqlite3.Connection) -> Optional[Dict[str, object]]:
    row = conn.execute(
        """
        SELECT id, occurred_at, ingested_at, user, client_ip, client, share,
               action, result, success, path, source
        FROM audit_events
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    return row_to_event(row) if row is not None else None


class AuditStore:
    def __init__(self, database_path: Optional[str] = None):
        self.conn = connect_state_db(database_path)
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
        inserted = 0
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            previous_key = read_deduplication_key(last_event(self.conn) or {})
            for event in events:
                current_key = read_deduplication_key(event)
                if current_key is not None and current_key == previous_key:
                    continue
                self.conn.execute(
                    """
                    INSERT INTO audit_events (
                        occurred_at, occurred_second, ingested_at, user, account,
                        client_ip, client, share, action, result, success, path,
                        source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(event["timestamp"]),
                        parse_event_second(event["timestamp"]),
                        str(event["ingestedAt"]),
                        str(event["user"]),
                        account_name(str(event["user"])).casefold(),
                        str(event["clientIp"]),
                        str(event["client"]),
                        str(event["share"]),
                        str(event["action"]),
                        str(event["result"]),
                        int(bool(event["success"])),
                        str(event["path"]),
                        str(event["source"]),
                    ),
                )
                inserted += 1
                previous_key = current_key

            for path, entry in source_updates.items():
                self.conn.execute(
                    """
                    INSERT INTO audit_sources (path, inode, offset)
                    VALUES (?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET
                        inode = excluded.inode,
                        offset = excluded.offset
                    """,
                    (path, int(entry["inode"]), int(entry["offset"])),
                )
            for row in self.conn.execute("SELECT path FROM audit_sources").fetchall():
                path = str(row["path"])
                if path not in seen_paths:
                    self.conn.execute("DELETE FROM audit_sources WHERE path = ?", (path,))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return inserted


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def date_seconds(day: dt.date) -> int:
    return int(
        dt.datetime.combine(day, dt.time.min, tzinfo=dt.timezone.utc).timestamp()
    )


def activity_conditions(
    start: dt.date,
    end: dt.date,
    params: Dict[str, List[str]],
    *,
    include_filters: bool,
) -> Tuple[List[str], List[object]]:
    conditions = ["occurred_second >= ?", "occurred_second < ?"]
    values: List[object] = [
        date_seconds(start),
        date_seconds(end + dt.timedelta(days=1)),
    ]
    for suffix in skipped_user_suffixes():
        conditions.append("lower(account) NOT LIKE ? ESCAPE '\\'")
        values.append(f"%{escape_like(suffix)}")

    if not include_filters:
        return conditions, values

    filters = {
        key: params.get(key, [""])[0].casefold().strip()
        for key in ("user", "share", "operation", "action", "path", "result")
    }
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
    if path:
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


def query_activity(
    conn: sqlite3.Connection,
    start: dt.date,
    end: dt.date,
    params: Dict[str, List[str]],
) -> Dict[str, object]:
    limit = min(500, max(1, int(params.get("limit", ["100"])[0])))
    conditions, values = activity_conditions(start, end, params, include_filters=True)
    where_sql = " AND ".join(conditions)
    matched = int(
        conn.execute(
            f"SELECT count(*) FROM audit_events WHERE {where_sql}",
            values,
        ).fetchone()[0]
    )

    cursor = params.get("cursor", [""])[0].strip()
    page_conditions = list(conditions)
    page_values = list(values)
    if cursor:
        try:
            cursor_second, cursor_id = (int(part) for part in cursor.split(":", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError("Ungültiger Seitenzeiger") from exc
        page_conditions.append(
            "(occurred_second < ? OR (occurred_second = ? AND id < ?))"
        )
        page_values.extend((cursor_second, cursor_second, cursor_id))

    rows = conn.execute(
        f"""
        SELECT id, occurred_at, occurred_second, ingested_at, user, client_ip,
               client, share, action, result, success, path, source
        FROM audit_events
        WHERE {" AND ".join(page_conditions)}
        ORDER BY occurred_second DESC, id DESC
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

    facet_conditions, facet_values = activity_conditions(
        start, end, params, include_filters=False
    )
    facet_where = " AND ".join(facet_conditions)

    def distinct(column: str) -> List[str]:
        return [
            str(row[0])
            for row in conn.execute(
                f"""
                SELECT DISTINCT {column}
                FROM audit_events
                WHERE {facet_where} AND {column} <> ''
                ORDER BY {column} COLLATE NOCASE
                """,
                facet_values,
            )
        ]

    actions = distinct("action")
    return {
        "events": events,
        "nextCursor": next_cursor,
        "matched": matched,
        "facets": {
            "users": distinct("user"),
            "shares": distinct("share"),
            "operations": actions,
            "actions": actions,
        },
    }


def audit_summary(conn: sqlite3.Connection, database_path: str) -> Dict[str, object]:
    row = conn.execute(
        """
        SELECT count(DISTINCT substr(occurred_at, 1, 10)),
               min(substr(occurred_at, 1, 10)),
               max(substr(occurred_at, 1, 10))
        FROM audit_events
        """
    ).fetchone()
    database_bytes = 0
    for suffix in ("", "-wal"):
        try:
            database_bytes += os.path.getsize(f"{database_path}{suffix}")
        except OSError:
            pass
    return {
        "days": int(row[0] or 0),
        "bytes": database_bytes,
        "oldest": row[1],
        "newest": row[2],
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
