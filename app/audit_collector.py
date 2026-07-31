#!/usr/bin/env python3
"""Persist Samba full_audit records as immutable daily NDJSON archives."""

import datetime as dt
import glob
import gzip
import json
import os
import re
import signal
import sys
import time
from typing import Dict, Iterable, Optional


SAMBA_LOG_GLOB = os.getenv("AUDIT_SOURCE_GLOB", "/var/log/samba/log.*")
ARCHIVE_DIR = os.getenv("AUDIT_ARCHIVE_DIR", "/state/audit")
STATE_FILE = os.path.join(ARCHIVE_DIR, "collector-state.json")
POLL_SECONDS = max(0.2, float(os.getenv("AUDIT_POLL_SECONDS", "1")))
COMPRESS_AFTER_HOURS = max(
    1, int(os.getenv("AUDIT_COMPRESS_AFTER_HOURS", "24"))
)
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


def atomic_json(path: str, value: object) -> None:
    temp_path = f"{path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def load_state() -> Dict[str, Dict[str, object]]:
    try:
        with open(STATE_FILE, encoding="utf-8") as handle:
            value = json.load(handle)
        if isinstance(value, dict):
            return value
    except (OSError, ValueError):
        pass
    return {}


def parse_samba_timestamp(raw_line: str, fallback: dt.datetime) -> str:
    match = SAMBA_LOG_TIME_RE.match(raw_line)
    if not match:
        return fallback.isoformat(timespec="milliseconds")
    try:
        parsed = dt.datetime.strptime(match.group(1).split(".")[0], "%Y/%m/%d %H:%M:%S")
        return parsed.replace(tzinfo=dt.timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return fallback.isoformat(timespec="milliseconds")


def action_for(operation: str) -> str:
    operation = operation.lower()
    if operation in {
        "read", "pread", "pread_recv", "pread_send", "recvfile", "sendfile",
        "offload_read_recv", "offload_read_send",
    }:
        return "read"
    if operation in {
        "write", "pwrite", "pwrite_recv", "pwrite_send", "ftruncate",
        "fallocate", "create_file", "mkdirat", "mknodat", "renameat",
        "unlinkat", "symlinkat", "linkat", "offload_write_recv",
        "offload_write_send", "fsetxattr", "removexattr", "fremovexattr",
        "mkdir", "rmdir", "rename", "unlink",
    }:
        return "write"
    if operation in {"opendir", "fdopendir", "readdir", "freaddir_attr", "closedir"}:
        return "list"
    if operation in {"connect", "disconnect"}:
        return "session"
    return "metadata"


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
    result = fields[6].strip()
    return {
        "timestamp": parse_samba_timestamp(raw_line, observed_at),
        "ingestedAt": observed_at.isoformat(timespec="milliseconds"),
        "user": fields[1].strip(),
        "clientIp": fields[2].strip(),
        "client": fields[3].strip(),
        "share": fields[4].strip(),
        "operation": operation,
        "action": action_for(operation),
        "result": result,
        "success": result.upper() == "OK",
        "path": "|".join(fields[7:]).strip(),
        "source": os.path.basename(source),
    }


def archive_events(events: Iterable[Dict[str, object]]) -> int:
    handles: Dict[str, object] = {}
    count = 0
    try:
        for event in events:
            day = str(event["ingestedAt"])[:10]
            path = os.path.join(ARCHIVE_DIR, f"{day}.jsonl")
            handle = handles.get(path)
            if handle is None:
                handle = open(path, "a", encoding="utf-8")
                handles[path] = handle
            handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True))
            handle.write("\n")
            count += 1
        for handle in handles.values():
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        for handle in handles.values():
            handle.close()
    return count


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


def compress_old_archives() -> None:
    cutoff = utc_now() - dt.timedelta(hours=COMPRESS_AFTER_HOURS)
    today = utc_now().date().isoformat()
    for path in glob.glob(os.path.join(ARCHIVE_DIR, "????-??-??.jsonl")):
        day = os.path.basename(path)[:10]
        if day == today:
            continue
        try:
            modified = dt.datetime.fromtimestamp(os.path.getmtime(path), dt.timezone.utc)
            if modified > cutoff:
                continue
            target = f"{path}.gz"
            temp_target = f"{target}.tmp"
            with open(path, "rb") as source, gzip.open(temp_target, "wb", compresslevel=6) as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            os.replace(temp_target, target)
            os.remove(path)
            log(f"Compressed {os.path.basename(path)}")
        except OSError as exc:
            log(f"Unable to compress {path}: {exc}")


def collect_once(state: Dict[str, Dict[str, object]]) -> int:
    total = 0
    seen = set()
    initial_by_inode = {
        int(entry.get("inode", -1)): entry
        for entry in state.values()
        if isinstance(entry, dict) and int(entry.get("inode", -1)) >= 0
    }
    for path in sorted(glob.glob(SAMBA_LOG_GLOB)):
        if not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            path_entry = state.get(path, {})
            current_inode = os.stat(path).st_ino
            if int(path_entry.get("inode", -1)) != current_inode:
                path_entry = initial_by_inode.get(current_inode, {})
            events, new_entry = read_new_events(path, path_entry)
            if events:
                total += archive_events(events)
            state[path] = new_entry
        except OSError as exc:
            log(f"Unable to read {path}: {exc}")
    for stale_path in list(state):
        if stale_path not in seen:
            state.pop(stale_path, None)
    atomic_json(STATE_FILE, state)
    return total


def stop(_signum, _frame) -> None:
    global STOP
    STOP = True


def main() -> int:
    os.makedirs(ARCHIVE_DIR, mode=0o750, exist_ok=True)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    state = load_state()
    last_compress = 0.0
    log(f"Watching {SAMBA_LOG_GLOB}")
    while not STOP:
        try:
            count = collect_once(state)
            if count:
                log(f"Archived {count} event(s)")
            if time.monotonic() - last_compress >= 3600:
                compress_old_archives()
                last_compress = time.monotonic()
        except Exception as exc:  # pylint: disable=broad-except
            log(f"Collector cycle failed: {exc}")
        time.sleep(POLL_SECONDS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
