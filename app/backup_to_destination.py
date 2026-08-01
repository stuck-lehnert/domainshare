#!/usr/bin/env python3

import datetime as dt
import fcntl
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, TextIO, Tuple
from urllib.parse import SplitResult, unquote, urlsplit


STATE_ROOT = os.getenv("STATE_ROOT", "/state")
STATE_DB_PATH = os.getenv(
    "STATE_DB_PATH",
    os.getenv("SHARE_DB_PATH", os.path.join(STATE_ROOT, "shares.db")),
)
LOCK_PATH = os.path.join(STATE_ROOT, "backup.lock")
DEFAULT_BACKUP_LOG_FILE = "/var/log/backup.log"
DEFAULT_BACKUP_STATUS_FILE = "/state/backup-status.json"
DEFAULT_PROGRESS_MODE = "auto"
DEFAULT_PROGRESS_INTERVAL_SECONDS = 10
PROGRESS_BAR_WIDTH = 28
MAX_PARALLEL_FILE_UPLOADS = 12
MAX_CAPTURED_OUTPUT_LINES = 50
MAX_CAPTURED_OUTPUT_RECORD_LENGTH = 1000
SNAPSHOT_NAME_RE = re.compile(r"^\d{8}T\d{6}Z$")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RCLONE_FILE_PROGRESS_RE = re.compile(
    r"^\s*\*\s+(?P<file>.+?):\s+(?P<percent>\d+(?:\.\d+)?)%\s*(?P<detail>.*)$"
)
RSYNC_FILE_PROGRESS_RE = re.compile(
    r"^\s*(?P<transferred>[\d,.]+(?:\s*[A-Za-z]+)?)\s+"
    r"(?P<percent>\d+(?:\.\d+)?)%\s+(?P<detail>.+)$"
)
RSYNC_IGNORED_RECORD_PREFIXES = (
    "sending incremental file list",
    "receiving incremental file list",
    "sent ",
    "total size is ",
)

BACKUP_SOURCES: List[Tuple[str, str]] = [
    ("/data/private", "data/private"),
    ("/data/groups", "data/groups"),
    ("/data/fslogix", "data/fslogix"),
    (STATE_ROOT, "state"),
    ("/var/lib/samba/private", "samba/private"),
]

RCLONE_SCHEME_MAP = {
    "sftp": "sftp",
    "smb": "smb",
    "cifs": "smb",
    "davfs": "webdav",
    "dav": "webdav",
    "webdav": "webdav",
    "http": "webdav",
    "https": "webdav",
}

DEFAULT_BACKUP_START_HOUR = 2
DEFAULT_RETENTION_DAILY = 3
DEFAULT_RETENTION_WEEKLY = 2
DEFAULT_RETENTION_MONTHLY = 2
DEFAULT_RETENTION_YEARLY = 1


@dataclass
class Destination:
    raw_url: str
    scheme: str
    parts: SplitResult
    username: str
    password: str
    hostname: str
    port: Optional[int]
    path: str


@dataclass
class RetentionPolicy:
    daily: int
    weekly: int
    monthly: int
    yearly: int


@dataclass(frozen=True)
class Snapshot:
    name: str
    timestamp: dt.datetime


@dataclass(frozen=True)
class FileProgress:
    file_path: str
    percent: float
    transferred_bytes: int
    total_bytes: int
    detail: str

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.total_bytes - self.transferred_bytes)


class BackupLogger:
    def __init__(
        self,
        *,
        console_stream: TextIO = sys.stdout,
        error_stream: TextIO = sys.stderr,
    ):
        self.console_stream = console_stream
        self.error_stream = error_stream
        self.log_path: Optional[str] = None
        self._handle: Optional[TextIO] = None

    def configure(self, log_path: str) -> None:
        self.close()
        self.log_path = log_path
        if not log_path:
            return

        log_dir = os.path.dirname(log_path)
        try:
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            self._handle = open(log_path, "a", encoding="utf-8")
        except OSError as exc:
            self._handle = None
            print(
                f"[backup] WARNING: unable to open log file {log_path}: {exc}",
                file=self.error_stream,
                flush=True,
            )

    def close(self) -> None:
        if self._handle is None:
            return
        self._handle.close()
        self._handle = None

    def log(self, message: str, *, console: bool = True) -> None:
        line = f"[backup] {message}"
        if console:
            print(line, file=self.console_stream, flush=True)
        if self._handle is not None:
            timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            self._handle.write(f"{timestamp} {line}\n")
            self._handle.flush()


LOGGER = BackupLogger()


class BackupStatus:
    """Atomic machine-readable status consumed by the read-only web UI."""

    def __init__(self, path: str):
        self.path = path
        self.value: Dict[str, object] = {
            "enabled": True,
            "state": "starting",
            "percent": 0.0,
            "transferredBytes": 0,
            "totalBytes": 0,
            "activeFiles": [],
        }

    def write(self, **changes: object) -> None:
        self.value.update(changes)
        self.value["updatedAt"] = dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="seconds"
        )
        try:
            status_dir = os.path.dirname(self.path)
            if status_dir:
                os.makedirs(status_dir, exist_ok=True)
            temp_path = f"{self.path}.tmp"
            with open(temp_path, "w", encoding="utf-8") as handle:
                json.dump(self.value, handle, separators=(",", ":"), sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
        except OSError as exc:
            print(
                f"[backup] WARNING: unable to update status file {self.path}: {exc}",
                file=sys.stderr,
                flush=True,
            )

    def begin(self, destination: str) -> None:
        self.write(
            state="starting",
            startedAt=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            finishedAt=None,
            destination=destination,
            snapshot=None,
            currentSource=None,
            percent=0.0,
            transferredBytes=0,
            totalBytes=0,
            activeFiles=[],
            message="Starting backup",
        )

    def progress(self, reporter: "SyncProgressReporter") -> None:
        active = []
        for entry in reporter._visible_active_files():  # pylint: disable=protected-access
            active.append(
                {
                    "path": entry.file_path,
                    "percent": entry.percent,
                    "transferredBytes": entry.transferred_bytes,
                    "totalBytes": entry.total_bytes,
                    "detail": entry.detail,
                }
            )
        self.write(
            state="running",
            currentSource=reporter.source_path,
            percent=round(reporter.overall_progress.percent, 2),
            transferredBytes=reporter.overall_progress.transferred_bytes,
            totalBytes=reporter.overall_progress.total_bytes,
            activeFiles=active,
            message=f"Syncing {reporter.source_path}",
        )

    def complete(self, message: str) -> None:
        self.write(
            state="completed",
            finishedAt=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            percent=100.0,
            transferredBytes=self.value.get("totalBytes", 0),
            activeFiles=[],
            currentSource=None,
            message=message,
        )

    def fail(self, message: str) -> None:
        self.write(
            state="failed",
            finishedAt=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            activeFiles=[],
            message=message,
        )


BACKUP_STATUS: Optional[BackupStatus] = None


def configure_logging() -> None:
    LOGGER.configure(os.getenv("BACKUP_LOG_FILE", DEFAULT_BACKUP_LOG_FILE).strip())


def close_logging() -> None:
    LOGGER.close()


def log(message: str, *, console: bool = True) -> None:
    LOGGER.log(message, console=console)


def run_command(
    command: List[str],
    *,
    env: Optional[Dict[str, str]] = None,
    input_text: Optional[str] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        input=input_text,
    )
    if check and result.returncode != 0:
        output = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Command failed ({command[0]}): {output}")
    return result


def parse_progress_mode() -> str:
    raw_value = os.getenv("BACKUP_PROGRESS", DEFAULT_PROGRESS_MODE).strip().lower()
    if raw_value in {"auto", "always", "never"}:
        return raw_value
    log(f"Invalid BACKUP_PROGRESS='{raw_value}', using default {DEFAULT_PROGRESS_MODE}")
    return DEFAULT_PROGRESS_MODE


def should_show_progress_bar(mode: str, stream: TextIO = sys.stderr) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return bool(stream.isatty())


def format_percent(percent: float) -> str:
    percent = clamp_percent(percent)
    if percent.is_integer():
        return str(int(percent))
    return f"{percent:.1f}".rstrip("0").rstrip(".")


def clamp_percent(percent: float) -> float:
    return max(0.0, min(100.0, percent))


def percent_for(transferred_bytes: int, total_bytes: int) -> float:
    if total_bytes <= 0:
        return 100.0
    return clamp_percent((transferred_bytes / total_bytes) * 100.0)


def shorten_middle(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    if max_length <= 3:
        return value[:max_length]
    left = (max_length - 3) // 2
    right = max_length - 3 - left
    return f"{value[:left]}...{value[-right:]}"


def format_bytes(byte_count: int) -> str:
    value = float(max(0, byte_count))
    units = ["B", "kB", "MB", "GB", "TB", "PB"]
    unit = units[0]
    for candidate in units:
        unit = candidate
        if value < 1024.0 or candidate == units[-1]:
            break
        value /= 1024.0
    if unit == "B":
        return f"{int(value)} B"
    if value >= 100.0:
        return f"{value:.0f} {unit}"
    if value >= 10.0:
        return f"{value:.1f} {unit}"
    return f"{value:.2f} {unit}"


def format_amounts(transferred_bytes: int, total_bytes: int) -> str:
    remaining_bytes = max(0, total_bytes - transferred_bytes)
    return f"{format_bytes(transferred_bytes)} / {format_bytes(remaining_bytes)} left"


def normalize_size_number(raw_value: str) -> float:
    value = raw_value.strip()
    if "," in value and "." not in value:
        if re.match(r"^\d{1,3}(,\d{3})+$", value):
            value = value.replace(",", "")
        else:
            value = value.replace(",", ".")
    else:
        value = value.replace(",", "")
    return float(value)


def parse_data_size(raw_value: str) -> Optional[int]:
    match = re.search(
        r"(?P<value>\d+(?:[,.]\d+)*)(?:\s*(?P<unit>[A-Za-z]+))?",
        raw_value.strip().lstrip("/"),
    )
    if not match:
        return None

    unit = (match.group("unit") or "B").lower()
    multipliers = {
        "b": 1,
        "byte": 1,
        "bytes": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "ki": 1024,
        "kbyte": 1024,
        "kbytes": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "mi": 1024**2,
        "mbyte": 1024**2,
        "mbytes": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
        "gi": 1024**3,
        "gbyte": 1024**3,
        "gbytes": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "tib": 1024**4,
        "ti": 1024**4,
        "p": 1024**5,
        "pb": 1024**5,
        "pib": 1024**5,
        "pi": 1024**5,
    }
    multiplier = multipliers.get(unit)
    if multiplier is None:
        return None
    return int(round(normalize_size_number(match.group("value")) * multiplier))


def measure_path_bytes(path: str) -> int:
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError as exc:
                        log(f"Skipping unreadable backup source entry {entry.path}: {exc}")
        except OSError as exc:
            log(f"Skipping unreadable backup source directory {current}: {exc}")
    return total


def measure_backup_payload(sources: List[Tuple[str, str]]) -> Tuple[Dict[str, int], int]:
    source_sizes: Dict[str, int] = {}
    total = 0
    for source_path, _destination_path in sources:
        size = measure_path_bytes(source_path)
        source_sizes[source_path] = size
        total += size
    return source_sizes, total


def clean_output_record(record: str) -> str:
    return ANSI_ESCAPE_RE.sub("", record).strip()


def truncate_output_record(record: str) -> str:
    if len(record) <= MAX_CAPTURED_OUTPUT_RECORD_LENGTH:
        return record
    return f"{record[:MAX_CAPTURED_OUTPUT_RECORD_LENGTH]}..."


def parse_rclone_total_bytes(detail: str) -> int:
    match = re.search(r"/\s*(?P<size>[\d,.]+\s*[A-Za-z]+)", detail)
    if not match:
        return 0
    return parse_data_size(match.group("size")) or 0


def parse_rclone_progress_record(record: str) -> Optional[FileProgress]:
    match = RCLONE_FILE_PROGRESS_RE.match(record)
    if not match:
        return None
    percent = clamp_percent(float(match.group("percent")))
    detail = match.group("detail").strip()
    total_bytes = parse_rclone_total_bytes(detail)
    transferred_bytes = int(round(total_bytes * (percent / 100.0)))
    return FileProgress(
        file_path=match.group("file").strip(),
        percent=percent,
        transferred_bytes=transferred_bytes,
        total_bytes=total_bytes,
        detail=detail,
    )


def rsync_file_candidate(record: str) -> Optional[str]:
    stripped = record.strip()
    if not stripped:
        return None
    lower = stripped.lower()
    if any(lower.startswith(prefix) for prefix in RSYNC_IGNORED_RECORD_PREFIXES):
        return None
    if lower.startswith("deleting "):
        return None
    if stripped.endswith("/"):
        return None
    if RSYNC_FILE_PROGRESS_RE.match(stripped):
        return None
    return stripped


def parse_rsync_progress_record(
    record: str, current_file: Optional[str], known_total_bytes: Optional[int] = None
) -> Optional[FileProgress]:
    if not current_file:
        return None
    match = RSYNC_FILE_PROGRESS_RE.match(record)
    if not match:
        return None
    percent = clamp_percent(float(match.group("percent")))
    transferred_bytes = parse_data_size(match.group("transferred")) or 0
    if known_total_bytes is not None and known_total_bytes > 0:
        total_bytes = known_total_bytes
    elif percent > 0:
        total_bytes = int(round(transferred_bytes * 100.0 / percent))
    else:
        total_bytes = transferred_bytes
    return FileProgress(
        file_path=current_file,
        percent=percent,
        transferred_bytes=min(transferred_bytes, total_bytes),
        total_bytes=total_bytes,
        detail=match.group("detail").strip(),
    )


class OutputRecordSplitter:
    def __init__(self) -> None:
        self._buffer = ""

    def feed(self, chunk: str) -> List[str]:
        records: List[str] = []
        for char in chunk:
            if char in {"\r", "\n"}:
                record = clean_output_record(self._buffer)
                self._buffer = ""
                if record:
                    records.append(record)
                continue
            self._buffer += char
        return records

    def close(self) -> List[str]:
        record = clean_output_record(self._buffer)
        self._buffer = ""
        if not record:
            return []
        return [record]


class OverallProgress:
    def __init__(self, total_bytes: int):
        self.total_bytes = max(0, total_bytes)
        self.completed_source_bytes = 0
        self.current_source_bytes = 0
        self.current_source_total_bytes = 0

    def begin_source(self, source_total_bytes: int) -> None:
        self.current_source_bytes = 0
        self.current_source_total_bytes = max(0, source_total_bytes)

    def update_current_source(self, transferred_bytes: int) -> None:
        capped = min(max(0, transferred_bytes), self.current_source_total_bytes)
        self.current_source_bytes = max(self.current_source_bytes, capped)

    def complete_source(self) -> None:
        self.completed_source_bytes = min(
            self.total_bytes,
            self.completed_source_bytes + self.current_source_total_bytes,
        )
        self.current_source_bytes = 0
        self.current_source_total_bytes = 0

    @property
    def transferred_bytes(self) -> int:
        return min(
            self.total_bytes,
            self.completed_source_bytes + self.current_source_bytes,
        )

    @property
    def percent(self) -> float:
        return percent_for(self.transferred_bytes, self.total_bytes)


class SyncProgressReporter:
    def __init__(
        self,
        backend_name: str,
        source_path: str,
        destination_path: str,
        *,
        source_total_bytes: int,
        overall_progress: OverallProgress,
        interval_seconds: int,
        interactive: bool,
        stream: TextIO = sys.stderr,
        now: Callable[[], float] = time.monotonic,
        log_func: Callable[..., None] = log,
    ):
        self.backend_name = backend_name
        self.source_path = source_path
        self.destination_path = destination_path
        self.source_total_bytes = max(0, source_total_bytes)
        self.overall_progress = overall_progress
        self.interval_seconds = interval_seconds
        self.interactive = interactive
        self.stream = stream
        self.now = now
        self.log_func = log_func
        self.current_rsync_file: Optional[str] = None
        self._completed_file_bytes = 0
        self._completed_files: Set[str] = set()
        self._active_files: Dict[str, FileProgress] = {}
        self._active_seen_at: Dict[str, float] = {}
        self._last_log_at: Dict[str, float] = {}
        self._last_logged_percent: Dict[str, float] = {}
        self._last_total_log_at: Optional[float] = None
        self._last_logged_total_percent: Optional[float] = None
        self._rendered_lines = 0
        self.overall_progress.begin_source(self.source_total_bytes)

    def observe(self, record: str) -> None:
        progress: Optional[FileProgress]
        if self.backend_name == "rclone":
            progress = parse_rclone_progress_record(record)
            if progress is not None:
                progress = self._with_known_file_size(progress)
        else:
            progress = parse_rsync_progress_record(
                record,
                self.current_rsync_file,
                self._known_file_size(self.current_rsync_file),
            )
            if progress is None:
                candidate = rsync_file_candidate(record)
                if candidate is not None:
                    self.current_rsync_file = candidate
                return

        if progress is None:
            return

        now = self.now()
        self._active_files[progress.file_path] = progress
        self._active_seen_at[progress.file_path] = now
        self._sync_total_progress()
        self._render_dashboard()
        self._log_progress(progress, now)
        self._log_total_progress(now)

        if progress.percent >= 100.0:
            self._complete_file(progress)
            self._sync_total_progress()
        if BACKUP_STATUS is not None:
            BACKUP_STATUS.progress(self)

    def finish(self, *, success: bool) -> None:
        if success:
            self.overall_progress.complete_source()
            self._render_dashboard()
            self._log_total_progress(self.now(), force=True)
        if BACKUP_STATUS is not None:
            BACKUP_STATUS.progress(self)
        self._clear_dashboard()

    def _known_file_size(self, file_path: Optional[str]) -> Optional[int]:
        if not file_path:
            return None
        candidates = []
        if os.path.isabs(file_path):
            candidates.append(file_path)
        relative_path = file_path.lstrip("/")
        candidates.append(os.path.join(self.source_path, relative_path))
        source_name = os.path.basename(self.source_path.rstrip("/"))
        prefix = f"{source_name}/"
        if relative_path.startswith(prefix):
            candidates.append(os.path.join(self.source_path, relative_path[len(prefix) :]))

        for candidate in candidates:
            try:
                return os.stat(candidate).st_size
            except OSError:
                continue
        return None

    def _with_known_file_size(self, progress: FileProgress) -> FileProgress:
        if progress.total_bytes > 0:
            return progress
        total_bytes = self._known_file_size(progress.file_path)
        if not total_bytes:
            return progress
        return FileProgress(
            file_path=progress.file_path,
            percent=progress.percent,
            transferred_bytes=int(round(total_bytes * (progress.percent / 100.0))),
            total_bytes=total_bytes,
            detail=progress.detail,
        )

    def _complete_file(self, progress: FileProgress) -> None:
        if progress.file_path in self._completed_files:
            self._active_files.pop(progress.file_path, None)
            self._active_seen_at.pop(progress.file_path, None)
            return
        self._completed_files.add(progress.file_path)
        self._completed_file_bytes += progress.total_bytes or progress.transferred_bytes
        self._completed_file_bytes = min(
            self._completed_file_bytes,
            self.source_total_bytes,
        )
        self._active_files.pop(progress.file_path, None)
        self._active_seen_at.pop(progress.file_path, None)

    def _source_transferred_bytes(self) -> int:
        active_bytes = sum(entry.transferred_bytes for entry in self._active_files.values())
        return min(self.source_total_bytes, self._completed_file_bytes + active_bytes)

    def _sync_total_progress(self) -> None:
        self.overall_progress.update_current_source(self._source_transferred_bytes())

    def _visible_active_files(self) -> List[FileProgress]:
        now = self.now()
        stale_after = max(2, self.interval_seconds * 2)
        candidates = [
            entry
            for path, entry in self._active_files.items()
            if now - self._active_seen_at.get(path, now) <= stale_after
        ]
        candidates.sort(
            key=lambda entry: self._active_seen_at.get(entry.file_path, 0.0),
            reverse=True,
        )
        return candidates[:MAX_PARALLEL_FILE_UPLOADS]

    def _log_progress(self, progress: FileProgress, now: float) -> None:
        key = progress.file_path
        last_log_at = self._last_log_at.get(key)
        last_logged_percent = self._last_logged_percent.get(key)
        is_final = progress.percent >= 100.0
        if (
            last_log_at is not None
            and now - last_log_at < self.interval_seconds
            and not (is_final and last_logged_percent != 100.0)
        ):
            return

        detail = f" ({progress.detail})" if progress.detail else ""
        self.log_func(
            "Upload progress "
            f"{self.source_path} -> {self.destination_path}: "
            f"{progress.file_path} {format_percent(progress.percent)}% "
            f"({format_amounts(progress.transferred_bytes, progress.total_bytes)})"
            f"{detail}",
            console=not self.interactive,
        )
        self._last_log_at[key] = now
        self._last_logged_percent[key] = progress.percent

    def _log_total_progress(self, now: float, *, force: bool = False) -> None:
        percent = self.overall_progress.percent
        is_final = percent >= 100.0
        if (
            not force
            and self._last_total_log_at is not None
            and now - self._last_total_log_at < self.interval_seconds
            and not (is_final and self._last_logged_total_percent != 100.0)
        ):
            return

        self.log_func(
            "Total upload progress: "
            f"{format_percent(percent)}% "
            f"({format_amounts(self.overall_progress.transferred_bytes, self.overall_progress.total_bytes)})",
            console=not self.interactive,
        )
        self._last_total_log_at = now
        self._last_logged_total_percent = percent

    def _progress_line(self, label: str, percent: float, transferred: int, total: int) -> str:
        filled = int(PROGRESS_BAR_WIDTH * (clamp_percent(percent) / 100.0))
        bar = "#" * filled + "-" * (PROGRESS_BAR_WIDTH - filled)
        return (
            f"[backup] {shorten_middle(label, 44):44} "
            f"[{bar}] {format_percent(percent):>5}% "
            f"{format_amounts(transferred, total)}"
        )

    def _render_dashboard(self) -> None:
        if not self.interactive:
            return
        lines = []
        for progress in self._visible_active_files():
            lines.append(
                self._progress_line(
                    progress.file_path,
                    progress.percent,
                    progress.transferred_bytes,
                    progress.total_bytes,
                )
            )
        lines.append(
            self._progress_line(
                "TOTAL",
                self.overall_progress.percent,
                self.overall_progress.transferred_bytes,
                self.overall_progress.total_bytes,
            )
        )
        self._render_lines(lines)

    def _render_lines(self, lines: List[str]) -> None:
        rendered_lines = max(self._rendered_lines, len(lines))
        if self._rendered_lines > 1:
            self.stream.write(f"\x1b[{self._rendered_lines - 1}F")
        elif self._rendered_lines == 1:
            self.stream.write("\r")
        for index in range(rendered_lines):
            self.stream.write("\r\x1b[2K")
            if index < len(lines):
                self.stream.write(lines[index])
            if index < rendered_lines - 1:
                self.stream.write("\n")
        self.stream.flush()
        self._rendered_lines = rendered_lines

    def _clear_dashboard(self) -> None:
        if not self.interactive or self._rendered_lines == 0:
            return
        if self._rendered_lines > 1:
            self.stream.write(f"\x1b[{self._rendered_lines - 1}F")
        else:
            self.stream.write("\r")
        for index in range(self._rendered_lines):
            self.stream.write("\r\x1b[2K")
            if index < self._rendered_lines - 1:
                self.stream.write("\n")
        self.stream.write("\r")
        self.stream.flush()
        self._rendered_lines = 0


def run_streaming_command(
    command: List[str],
    *,
    progress: SyncProgressReporter,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    splitter = OutputRecordSplitter()
    captured_records: List[str] = []
    returncode: Optional[int] = None

    try:
        if process.stdout is not None:
            while True:
                chunk = process.stdout.read(1)
                if chunk == "":
                    if process.poll() is not None:
                        break
                    continue
                for record in splitter.feed(chunk):
                    captured_records.append(truncate_output_record(record))
                    captured_records = captured_records[-MAX_CAPTURED_OUTPUT_LINES:]
                    progress.observe(record)

        for record in splitter.close():
            captured_records.append(truncate_output_record(record))
            captured_records = captured_records[-MAX_CAPTURED_OUTPUT_LINES:]
            progress.observe(record)

        returncode = process.wait()
    finally:
        progress.finish(success=returncode == 0)

    stdout = "\n".join(captured_records)
    if returncode != 0:
        output = stdout.strip() or f"exit code {returncode}"
        raise RuntimeError(f"Command failed ({command[0]}): {output}")
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")


def parse_destination(raw_url: str) -> Destination:
    parts = urlsplit(raw_url)
    scheme = parts.scheme.lower()
    if not scheme:
        raise RuntimeError("BACKUP_DESTINATION must include a URL scheme")

    hostname = parts.hostname or ""
    if not hostname:
        raise RuntimeError("BACKUP_DESTINATION must include a hostname")

    return Destination(
        raw_url=raw_url,
        scheme=scheme,
        parts=parts,
        username=unquote(parts.username or ""),
        password=unquote(parts.password or ""),
        hostname=hostname,
        port=parts.port,
        path=unquote(parts.path or ""),
    )


def redact_destination(raw_url: str) -> str:
    parts = urlsplit(raw_url)
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parts.port is not None:
        host = f"{host}:{parts.port}"

    if parts.username:
        username = unquote(parts.username)
        if parts.password is not None:
            auth = f"{username}:***"
        else:
            auth = username
        netloc = f"{auth}@{host}"
    else:
        netloc = host

    return f"{parts.scheme}://{netloc}{parts.path}"


def prepare_state_snapshot(
    state_root: str = STATE_ROOT,
    database_path: str = STATE_DB_PATH,
) -> Tuple[str, str]:
    """Copy state and replace the live WAL database with an online snapshot."""
    state_root = os.path.abspath(state_root)
    database_path = os.path.abspath(database_path)
    database_relative = os.path.relpath(database_path, state_root)
    if database_relative == ".." or database_relative.startswith(f"..{os.sep}"):
        raise RuntimeError("STATE_DB_PATH must be located below STATE_ROOT")

    temporary_root = tempfile.mkdtemp(prefix="backup-state-")
    staged_state = os.path.join(temporary_root, "state")
    excluded = {
        database_relative,
        f"{database_relative}-wal",
        f"{database_relative}-shm",
    }

    def ignore_live_database(directory: str, names: List[str]) -> Set[str]:
        relative_directory = os.path.relpath(directory, state_root)
        return {
            name
            for name in names
            if os.path.normpath(os.path.join(relative_directory, name)) in excluded
        }

    try:
        shutil.copytree(
            state_root,
            staged_state,
            symlinks=True,
            ignore=ignore_live_database,
        )
        if os.path.isfile(database_path):
            staged_database = os.path.join(staged_state, database_relative)
            os.makedirs(os.path.dirname(staged_database), exist_ok=True)
            source = sqlite3.connect(
                f"file:{database_path}?mode=ro",
                uri=True,
                timeout=30,
            )
            destination = sqlite3.connect(staged_database, timeout=30)
            try:
                source.execute("PRAGMA busy_timeout = 30000")
                source.backup(destination)
                if destination.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("SQLite state snapshot failed its integrity check")
            finally:
                destination.close()
                source.close()
        return temporary_root, staged_state
    except Exception:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise


def available_sources(
    state_snapshot: Optional[str] = None,
) -> List[Tuple[str, str]]:
    sources: List[Tuple[str, str]] = []
    for source_path, destination_path in BACKUP_SOURCES:
        effective_source = (
            state_snapshot
            if destination_path == "state" and state_snapshot is not None
            else source_path
        )
        if os.path.isdir(effective_source):
            sources.append((effective_source, destination_path))
        else:
            log(f"Skipping missing source: {source_path}")
    return sources


def format_host(hostname: str) -> str:
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname


def join_path(prefix: str, suffix: str) -> str:
    left = prefix.strip("/")
    right = suffix.strip("/")
    if left and right:
        return f"{left}/{right}"
    return left or right


def parse_int_env(
    name: str, default: int, *, minimum: int, maximum: Optional[int]
) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default

    try:
        value = int(raw_value)
    except ValueError:
        log(f"Invalid {name}='{raw_value}', using default {default}")
        return default

    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            log(f"Invalid {name}='{raw_value}', using default {default}")
        else:
            log(
                f"Invalid {name}='{raw_value}' (expected {minimum}-{maximum}), using default {default}"
            )
        return default

    return value


def parse_retention_policy() -> RetentionPolicy:
    return RetentionPolicy(
        daily=parse_int_env(
            "BACKUP_RETENTION_DAILY", DEFAULT_RETENTION_DAILY, minimum=0, maximum=None
        ),
        weekly=parse_int_env(
            "BACKUP_RETENTION_WEEKLY",
            DEFAULT_RETENTION_WEEKLY,
            minimum=0,
            maximum=None,
        ),
        monthly=parse_int_env(
            "BACKUP_RETENTION_MONTHLY",
            DEFAULT_RETENTION_MONTHLY,
            minimum=0,
            maximum=None,
        ),
        yearly=parse_int_env(
            "BACKUP_RETENTION_YEARLY",
            DEFAULT_RETENTION_YEARLY,
            minimum=0,
            maximum=None,
        ),
    )


def parse_smb_identity(username: str) -> Tuple[str, str]:
    if not username:
        return "", ""
    if ";" in username:
        domain, user = username.split(";", 1)
        return domain, user
    if "\\" in username:
        domain, user = username.split("\\", 1)
        return domain, user
    return "", username


def obscure_secret(secret: str) -> str:
    result = run_command(["rclone", "obscure", secret])
    value = result.stdout.strip()
    if not value:
        raise RuntimeError("rclone obscure returned an empty value")
    return value


def parse_snapshot_name(name: str) -> Optional[dt.datetime]:
    if not SNAPSHOT_NAME_RE.match(name):
        return None
    try:
        parsed = dt.datetime.strptime(name, "%Y%m%dT%H%M%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.timezone.utc)


def choose_snapshot_name(existing_names: Set[str]) -> str:
    base = dt.datetime.now(dt.timezone.utc)
    for offset in range(0, 120):
        candidate = (base + dt.timedelta(seconds=offset)).strftime("%Y%m%dT%H%M%SZ")
        if candidate not in existing_names:
            return candidate
    raise RuntimeError("Unable to generate a unique snapshot name")


def is_week_start(timestamp: dt.datetime) -> bool:
    return timestamp.weekday() == 0


def is_month_start(timestamp: dt.datetime) -> bool:
    return timestamp.day == 1


def is_year_start(timestamp: dt.datetime) -> bool:
    return timestamp.month == 1 and timestamp.day == 1


def select_newest(snapshot_pool: List[Snapshot], limit: int) -> Set[str]:
    if limit <= 0:
        return set()
    sorted_pool = sorted(snapshot_pool, key=lambda entry: entry.timestamp, reverse=True)
    return {entry.name for entry in sorted_pool[:limit]}


def compute_retained_snapshots(
    snapshots: List[Snapshot], policy: RetentionPolicy
) -> Set[str]:
    retained: Set[str] = set()
    retained.update(select_newest(snapshots, policy.daily))
    retained.update(
        select_newest(
            [entry for entry in snapshots if is_week_start(entry.timestamp)],
            policy.weekly,
        )
    )
    retained.update(
        select_newest(
            [entry for entry in snapshots if is_month_start(entry.timestamp)],
            policy.monthly,
        )
    )
    retained.update(
        select_newest(
            [entry for entry in snapshots if is_year_start(entry.timestamp)],
            policy.yearly,
        )
    )
    return retained


class RcloneBackend:
    def __init__(self, destination: Destination):
        self.base_prefix = ""
        options, self.base_prefix = self._build_remote(destination)
        self.config_path = self._write_config(options)

    def close(self) -> None:
        if os.path.exists(self.config_path):
            os.remove(self.config_path)

    def _run(
        self,
        args: List[str],
        *,
        check: bool = True,
        input_text: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        return run_command(
            ["rclone", *args, "--config", self.config_path],
            check=check,
            input_text=input_text,
        )

    def _build_remote(self, destination: Destination) -> Tuple[Dict[str, str], str]:
        backend = RCLONE_SCHEME_MAP.get(destination.scheme)
        if backend is None:
            supported = ", ".join(["rsync", *sorted(RCLONE_SCHEME_MAP.keys())])
            raise RuntimeError(
                f"Unsupported BACKUP_DESTINATION scheme '{destination.scheme}'. Supported schemes: {supported}"
            )

        options: Dict[str, str] = {"type": backend}
        remote_prefix = ""

        if backend == "sftp":
            options["host"] = destination.hostname
            if destination.port is not None:
                options["port"] = str(destination.port)
            if destination.username:
                options["user"] = destination.username
            if destination.password:
                options["pass"] = obscure_secret(destination.password)
            remote_prefix = destination.path.strip("/")
            return options, remote_prefix

        if backend == "smb":
            path_segments = [
                segment for segment in destination.path.split("/") if segment
            ]
            if not path_segments:
                raise RuntimeError(
                    "smb destinations must include a share name in the path (example: smb://user:pass@host/share/path)"
                )

            share_name = path_segments[0]
            remote_prefix = "/".join(path_segments[1:])

            options["host"] = destination.hostname
            options["share"] = share_name
            if destination.port is not None:
                options["port"] = str(destination.port)

            domain, user = parse_smb_identity(destination.username)
            if user:
                options["user"] = user
            if domain:
                options["domain"] = domain
            if destination.password:
                options["pass"] = obscure_secret(destination.password)

            return options, remote_prefix

        webdav_scheme = (
            destination.scheme if destination.scheme in {"http", "https"} else "https"
        )
        host = format_host(destination.hostname)
        if destination.port is not None:
            host = f"{host}:{destination.port}"
        webdav_path = destination.path or "/"

        options["url"] = f"{webdav_scheme}://{host}{webdav_path}"
        options["vendor"] = "other"
        if destination.username:
            options["user"] = destination.username
        if destination.password:
            options["pass"] = obscure_secret(destination.password)

        return options, remote_prefix

    def _write_config(self, options: Dict[str, str]) -> str:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("[backup]\n")
            for key, value in options.items():
                handle.write(f"{key} = {value}\n")
            config_path = handle.name

        os.chmod(config_path, 0o600)
        return config_path

    def _snapshots_root(self) -> str:
        return join_path(self.base_prefix, "snapshots")

    def _snapshot_root(self, snapshot_name: str) -> str:
        return join_path(self._snapshots_root(), snapshot_name)

    def sync_source(
        self,
        snapshot_name: str,
        source_path: str,
        destination_path: str,
        *,
        source_total_bytes: int,
        overall_progress: OverallProgress,
        progress_interval_seconds: int,
        interactive_progress: bool,
    ) -> None:
        remote_path = join_path(self._snapshot_root(snapshot_name), destination_path)
        progress = SyncProgressReporter(
            "rclone",
            source_path,
            destination_path,
            source_total_bytes=source_total_bytes,
            overall_progress=overall_progress,
            interval_seconds=progress_interval_seconds,
            interactive=interactive_progress,
        )
        run_streaming_command(
            [
                "rclone",
                "sync",
                f"{source_path}/",
                f"backup:{remote_path}",
                "--create-empty-src-dirs",
                "--progress",
                "--stats",
                f"{progress_interval_seconds}s",
                "--transfers",
                str(MAX_PARALLEL_FILE_UPLOADS),
                "--log-level",
                "INFO",
                "--config",
                self.config_path,
            ],
            progress=progress,
        )

    def write_marker(self, snapshot_name: str) -> None:
        marker_path = join_path(self._snapshot_root(snapshot_name), ".backup_complete")
        self._run(
            ["rcat", f"backup:{marker_path}"],
            input_text=f"{dt.datetime.now(dt.timezone.utc).isoformat()}\n",
        )

    def _snapshot_has_marker(self, snapshot_name: str) -> bool:
        result = self._run(
            [
                "lsf",
                f"backup:{self._snapshot_root(snapshot_name)}",
                "--files-only",
                "--include",
                ".backup_complete",
            ],
            check=False,
        )
        if result.returncode != 0:
            return False
        return any(
            line.strip() == ".backup_complete" for line in result.stdout.splitlines()
        )

    def list_snapshots(self) -> List[str]:
        result = self._run(
            ["lsf", f"backup:{self._snapshots_root()}", "--dirs-only", "--format", "p"],
            check=False,
        )
        if result.returncode != 0:
            output = (result.stderr.strip() or result.stdout.strip()).lower()
            if "not found" in output or "doesn't exist" in output:
                return []
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())

        names: List[str] = []
        for line in result.stdout.splitlines():
            candidate = line.strip().rstrip("/")
            if not SNAPSHOT_NAME_RE.match(candidate):
                continue
            if self._snapshot_has_marker(candidate):
                names.append(candidate)
        return sorted(set(names))

    def delete_snapshot(self, snapshot_name: str) -> None:
        result = self._run(
            ["purge", f"backup:{self._snapshot_root(snapshot_name)}"],
            check=False,
        )
        if result.returncode != 0:
            log(
                f"Failed to delete snapshot {snapshot_name}: {result.stderr.strip() or result.stdout.strip()}"
            )


class RsyncBackend:
    def __init__(self, destination: Destination):
        module_path = destination.path.lstrip("/")
        if not module_path:
            raise RuntimeError(
                "rsync destinations must include a module path (example: rsync://user:pass@host/module/path)"
            )

        host = format_host(destination.hostname)
        if destination.port is not None:
            host = f"{host}:{destination.port}"

        user_prefix = f"{destination.username}@" if destination.username else ""
        self.remote_base = f"rsync://{user_prefix}{host}/{module_path.rstrip('/')}"
        self.command_env = os.environ.copy()
        if destination.password:
            self.command_env["RSYNC_PASSWORD"] = destination.password

    def close(self) -> None:
        return

    def _remote_path(self, path: str) -> str:
        trimmed = path.strip("/")
        if not trimmed:
            return self.remote_base
        return f"{self.remote_base}/{trimmed}"

    def sync_source(
        self,
        snapshot_name: str,
        source_path: str,
        destination_path: str,
        *,
        source_total_bytes: int,
        overall_progress: OverallProgress,
        progress_interval_seconds: int,
        interactive_progress: bool,
    ) -> None:
        target = self._remote_path(
            join_path(f"snapshots/{snapshot_name}", destination_path)
        )
        progress = SyncProgressReporter(
            "rsync",
            source_path,
            destination_path,
            source_total_bytes=source_total_bytes,
            overall_progress=overall_progress,
            interval_seconds=progress_interval_seconds,
            interactive=interactive_progress,
        )
        run_streaming_command(
            [
                "rsync",
                "-a",
                "--delete",
                "--mkpath",
                "--progress",
                "--outbuf=L",
                f"{source_path}/",
                f"{target}/",
            ],
            env=self.command_env,
            progress=progress,
        )

    def write_marker(self, snapshot_name: str) -> None:
        marker_remote = self._remote_path(f"snapshots/{snapshot_name}/.backup_complete")
        marker_file = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", delete=False
            ) as handle:
                marker_file = handle.name
                handle.write(f"{dt.datetime.now(dt.timezone.utc).isoformat()}\n")
            run_command(
                ["rsync", "-a", marker_file, marker_remote], env=self.command_env
            )
        finally:
            if marker_file and os.path.exists(marker_file):
                os.remove(marker_file)

    def _snapshot_has_marker(self, snapshot_name: str) -> bool:
        marker_remote = self._remote_path(f"snapshots/{snapshot_name}/.backup_complete")
        result = run_command(
            ["rsync", "--list-only", marker_remote],
            env=self.command_env,
            check=False,
        )
        return result.returncode == 0

    def list_snapshots(self) -> List[str]:
        root = self._remote_path("snapshots")
        result = run_command(
            ["rsync", "--list-only", f"{root}/"],
            env=self.command_env,
            check=False,
        )
        if result.returncode != 0:
            output = result.stderr.strip() or result.stdout.strip()
            lower = output.lower()
            if (
                "no such file" in lower
                or "not found" in lower
                or "chdir failed" in lower
            ):
                return []
            raise RuntimeError(output)

        names: List[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("receiving"):
                continue
            parts = line.split()
            if not parts:
                continue
            candidate = parts[-1].rstrip("/")
            if not SNAPSHOT_NAME_RE.match(candidate):
                continue
            if self._snapshot_has_marker(candidate):
                names.append(candidate)
        return sorted(set(names))

    def delete_snapshot(self, snapshot_name: str) -> None:
        snapshot_remote = self._remote_path(f"snapshots/{snapshot_name}")
        empty_dir = tempfile.mkdtemp(prefix="backup-empty-")
        try:
            run_command(
                ["rsync", "-a", "--delete", f"{empty_dir}/", f"{snapshot_remote}/"],
                env=self.command_env,
                check=False,
            )

            run_command(
                [
                    "rsync",
                    "-a",
                    "--delete",
                    "--prune-empty-dirs",
                    "--include",
                    f"/{snapshot_name}/***",
                    "--exclude",
                    "*",
                    f"{empty_dir}/",
                    f"{self._remote_path('snapshots')}/",
                ],
                env=self.command_env,
                check=False,
            )
        finally:
            os.rmdir(empty_dir)


def build_backend(destination: Destination):
    if destination.scheme == "rsync":
        return RsyncBackend(destination)
    return RcloneBackend(destination)


def parse_snapshot_inventory(snapshot_names: List[str]) -> List[Snapshot]:
    snapshots: List[Snapshot] = []
    for name in snapshot_names:
        timestamp = parse_snapshot_name(name)
        if timestamp is None:
            continue
        snapshots.append(Snapshot(name=name, timestamp=timestamp))
    snapshots.sort(key=lambda entry: entry.timestamp, reverse=True)
    return snapshots


def run_backup() -> int:
    global BACKUP_STATUS
    destination_url = os.getenv("BACKUP_DESTINATION", "").strip()
    if not destination_url:
        log("BACKUP_DESTINATION is unset, skipping backup")
        return 0

    policy = parse_retention_policy()
    progress_interval_seconds = parse_int_env(
        "BACKUP_PROGRESS_INTERVAL_SECONDS",
        DEFAULT_PROGRESS_INTERVAL_SECONDS,
        minimum=1,
        maximum=None,
    )
    progress_mode = parse_progress_mode()
    interactive_progress = should_show_progress_bar(progress_mode)

    destination = parse_destination(destination_url)
    BACKUP_STATUS = BackupStatus(
        os.getenv("BACKUP_STATUS_FILE", DEFAULT_BACKUP_STATUS_FILE).strip()
    )
    BACKUP_STATUS.begin(redact_destination(destination.raw_url))
    backend = None
    state_snapshot_root = None
    try:
        state_snapshot = None
        if os.path.isdir(STATE_ROOT):
            BACKUP_STATUS.write(message="Creating consistent state database snapshot")
            state_snapshot_root, state_snapshot = prepare_state_snapshot()
        sources = available_sources(state_snapshot)
        if not sources:
            log("No backup sources are available, skipping backup")
            return 0

        backend = build_backend(destination)
        log(f"Starting backup to {redact_destination(destination.raw_url)}")

        existing = set(backend.list_snapshots())
        snapshot_name = choose_snapshot_name(existing)
        log(f"Creating snapshot {snapshot_name}")
        BACKUP_STATUS.write(snapshot=snapshot_name, message="Measuring backup payload")

        log("Measuring backup payload size")
        source_sizes, total_bytes = measure_backup_payload(sources)
        log(f"Backup payload size: {format_bytes(total_bytes)}")
        overall_progress = OverallProgress(total_bytes)
        BACKUP_STATUS.write(
            state="running",
            totalBytes=total_bytes,
            message=f"Backup payload: {format_bytes(total_bytes)}",
        )

        for source_path, destination_path in sources:
            log(f"Syncing {destination_path}")
            backend.sync_source(
                snapshot_name,
                source_path,
                destination_path,
                source_total_bytes=source_sizes[source_path],
                overall_progress=overall_progress,
                progress_interval_seconds=progress_interval_seconds,
                interactive_progress=interactive_progress,
            )

        backend.write_marker(snapshot_name)

        all_snapshot_names = backend.list_snapshots()
        snapshots = parse_snapshot_inventory(all_snapshot_names)
        retained = compute_retained_snapshots(snapshots, policy)

        deleted_count = 0
        for snapshot in snapshots:
            if snapshot.name in retained:
                continue
            log(f"Pruning snapshot {snapshot.name}")
            backend.delete_snapshot(snapshot.name)
            deleted_count += 1

        log(
            f"Backup completed (snapshots total={len(snapshots)}, retained={len(retained)}, pruned={deleted_count})"
        )
        BACKUP_STATUS.complete(
            f"Backup completed; {len(retained)} snapshot(s) retained"
        )
        return 0
    finally:
        if backend is not None:
            backend.close()
        if state_snapshot_root is not None:
            shutil.rmtree(state_snapshot_root, ignore_errors=True)


def with_lock() -> int:
    lock_dir = os.path.dirname(LOCK_PATH)
    if lock_dir and not os.path.isdir(lock_dir):
        os.makedirs(lock_dir, exist_ok=True)
    with open(LOCK_PATH, "w", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("Another backup process is already running; skipping this cycle")
            return 0
        return run_backup()


def main() -> int:
    configure_logging()
    try:
        backup_hour = parse_int_env(
            "BACKUP_START_HOUR",
            DEFAULT_BACKUP_START_HOUR,
            minimum=0,
            maximum=23,
        )
        if backup_hour != DEFAULT_BACKUP_START_HOUR:
            log(f"Configured backup start hour is {backup_hour}:00")

        try:
            return with_lock()
        except Exception as exc:  # pylint: disable=broad-except
            log(f"ERROR: {exc}")
            if BACKUP_STATUS is not None:
                BACKUP_STATUS.fail(str(exc))
            return 1
    finally:
        close_logging()


if __name__ == "__main__":
    sys.exit(main())
