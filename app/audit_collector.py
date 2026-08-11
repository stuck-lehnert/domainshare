#!/usr/bin/env python3
"""Persist selected Samba full_audit records in indexed SQLite tables."""

import datetime as dt
import glob
import os
import re
import signal
import sys
import time
from typing import Dict, Optional

try:
    from .audit_policy import action_for, skip_user
    from .audit_store import AuditStore, drop_legacy_audit_files
except ImportError:
    from audit_policy import action_for, skip_user
    from audit_store import AuditStore, drop_legacy_audit_files


SAMBA_LOG_GLOB = os.getenv("AUDIT_SOURCE_GLOB", "/var/log/samba/log.*")
LEGACY_AUDIT_DIR = os.getenv("AUDIT_ARCHIVE_DIR", "/state/audit")
POLL_SECONDS = max(0.2, float(os.getenv("AUDIT_POLL_SECONDS", "1")))
AUDIT_MARKER_RE = re.compile(r"smbd_audit:\s*(.*)$")
AUDIT_PAYLOAD_RE = re.compile(
    r"^\s*\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\|"
)
SAMBA_LOG_TIME_RE = re.compile(
    r"^\s*\[?(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)
STOP = False


def log(message: str) -> None:
    print(f"[audit] {message}", flush=True)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_samba_timestamp(raw_line: str, fallback: dt.datetime) -> str:
    match = SAMBA_LOG_TIME_RE.match(raw_line)
    if not match:
        return fallback.isoformat(timespec="milliseconds")
    try:
        parsed = dt.datetime.strptime(match.group(1).split(".")[0], "%Y/%m/%d %H:%M:%S")
        return parsed.replace(tzinfo=dt.timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return fallback.isoformat(timespec="milliseconds")


def parse_audit_line(raw_line: str, source: str) -> Optional[Dict[str, object]]:
    match = AUDIT_MARKER_RE.search(raw_line)
    if match:
        payload = match.group(1)
    elif AUDIT_PAYLOAD_RE.match(raw_line):
        payload = raw_line.strip()
    else:
        return None
    fields = payload.rstrip("\r\n").split("|")
    if len(fields) < 8:
        return None
    observed_at = utc_now()
    operation = fields[5].strip()
    action = action_for(operation)
    user = fields[1].strip()
    if action is None or skip_user(user):
        return None
    result = fields[6].strip()
    return {
        "timestamp": parse_samba_timestamp(raw_line, observed_at),
        "ingestedAt": observed_at.isoformat(timespec="milliseconds"),
        "user": user,
        "clientIp": fields[2].strip(),
        "client": fields[3].strip(),
        "share": fields[4].strip(),
        "operation": operation,
        "action": action,
        "result": result,
        "success": result.upper() == "OK",
        "path": "|".join(fields[7:]).strip(),
        "source": os.path.basename(source),
    }


def read_new_events(path: str, entry: Dict[str, object]):
    stat = os.stat(path)
    inode = int(stat.st_ino)
    previous_inode = int(entry.get("inode", -1))
    offset = int(entry.get("offset", 0))
    if previous_inode != inode or stat.st_size < offset:
        offset = 0

    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        while True:
            line_start = handle.tell()
            line = handle.readline()
            if not line:
                break
            if not line.endswith("\n"):
                handle.seek(line_start)
                break
            event = parse_audit_line(line, path)
            if event is not None:
                events.append(event)
        new_offset = handle.tell()
    return events, {"inode": inode, "offset": new_offset}


def collect_once(store: AuditStore) -> int:
    state = store.source_entries()
    all_events = []
    source_updates = {}
    seen = set()
    initial_by_inode = {
        int(entry.get("inode", -1)): entry
        for entry in state.values()
        if int(entry.get("inode", -1)) >= 0
    }
    candidates = []
    for path in glob.glob(SAMBA_LOG_GLOB):
        if not os.path.isfile(path):
            continue
        try:
            stat = os.stat(path)
        except OSError as exc:
            log(f"Unable to inspect {path}: {exc}")
            continue
        known_inode = int(stat.st_ino) in initial_by_inode
        candidates.append((not known_inode, stat.st_mtime_ns, path, int(stat.st_ino)))

    for _is_new, _mtime_ns, path, current_inode in sorted(candidates):
        seen.add(path)
        try:
            path_entry = state.get(path, {})
            if int(path_entry.get("inode", -1)) != current_inode:
                path_entry = initial_by_inode.get(current_inode, {})
            events, new_entry = read_new_events(path, path_entry)
            all_events.extend(events)
            source_updates[path] = new_entry
        except OSError as exc:
            log(f"Unable to read {path}: {exc}")
    return store.append_batch(all_events, source_updates, seen)


def stop(_signum, _frame) -> None:
    global STOP
    STOP = True


def main() -> int:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    store = AuditStore()
    removed = drop_legacy_audit_files(LEGACY_AUDIT_DIR)
    if removed:
        log(f"Dropped {removed} legacy audit archive file(s)")
    log(f"Watching {SAMBA_LOG_GLOB}; storing events in SQLite")
    try:
        while not STOP:
            try:
                count = collect_once(store)
                if count:
                    log(f"Stored {count} event(s)")
                store.backfill_rollups()
            except Exception as exc:  # pylint: disable=broad-except
                log(f"Collector cycle failed: {exc}")
            time.sleep(POLL_SECONDS)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
