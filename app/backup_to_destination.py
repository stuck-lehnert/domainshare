#!/usr/bin/env python3

import datetime as dt
import fcntl
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import SplitResult, unquote, urlsplit


LOCK_PATH = "/state/backup.lock"
SNAPSHOT_NAME_RE = re.compile(r"^\d{8}T\d{6}Z$")

BACKUP_SOURCES: List[Tuple[str, str]] = [
    ("/data/private", "data/private"),
    ("/data/groups", "data/groups"),
    ("/data/fslogix", "data/fslogix"),
    ("/state", "state"),
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


def log(message: str) -> None:
    print(f"[backup] {message}", flush=True)


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


def available_sources() -> List[Tuple[str, str]]:
    sources: List[Tuple[str, str]] = []
    for source_path, destination_path in BACKUP_SOURCES:
        if os.path.isdir(source_path):
            sources.append((source_path, destination_path))
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
        self, snapshot_name: str, source_path: str, destination_path: str
    ) -> None:
        remote_path = join_path(self._snapshot_root(snapshot_name), destination_path)
        self._run(
            [
                "sync",
                f"{source_path}/",
                f"backup:{remote_path}",
                "--create-empty-src-dirs",
            ]
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
        self, snapshot_name: str, source_path: str, destination_path: str
    ) -> None:
        target = self._remote_path(
            join_path(f"snapshots/{snapshot_name}", destination_path)
        )
        run_command(
            ["rsync", "-a", "--delete", f"{source_path}/", f"{target}/"],
            env=self.command_env,
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
    destination_url = os.getenv("BACKUP_DESTINATION", "").strip()
    if not destination_url:
        log("BACKUP_DESTINATION is unset, skipping backup")
        return 0

    policy = parse_retention_policy()
    sources = available_sources()
    if not sources:
        log("No backup sources are available, skipping backup")
        return 0

    destination = parse_destination(destination_url)
    backend = build_backend(destination)
    try:
        log(f"Starting backup to {redact_destination(destination.raw_url)}")

        existing = set(backend.list_snapshots())
        snapshot_name = choose_snapshot_name(existing)
        log(f"Creating snapshot {snapshot_name}")

        for source_path, destination_path in sources:
            log(f"Syncing {source_path}")
            backend.sync_source(snapshot_name, source_path, destination_path)

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
        return 0
    finally:
        backend.close()


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
        return 1


if __name__ == "__main__":
    sys.exit(main())
