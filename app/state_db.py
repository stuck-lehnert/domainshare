#!/usr/bin/env python3
"""Connections to the shared persistent SQLite state database."""

import os
import sqlite3
from typing import Optional


STATE_DB_PATH = os.getenv(
    "STATE_DB_PATH",
    os.getenv("SHARE_DB_PATH", "/state/shares.db"),
)


def connect_state_db(
    path: Optional[str] = None,
    *,
    read_only: bool = False,
) -> sqlite3.Connection:
    database_path = path or STATE_DB_PATH
    if read_only:
        conn = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
            timeout=30,
        )
    else:
        directory = os.path.dirname(database_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        conn = sqlite3.connect(database_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def ensure_web_cache_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS web_cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()


def drop_legacy_web_cache(directory: Optional[str] = None) -> int:
    legacy_directory = directory or os.getenv("WEB_STATE_DIR", "/state/web")
    removed = 0
    for name in ("usage.json", "usage.json.tmp"):
        path = os.path.join(legacy_directory, name)
        try:
            os.remove(path)
            removed += 1
        except FileNotFoundError:
            pass
    try:
        os.rmdir(legacy_directory)
    except OSError:
        pass
    return removed

