#!/usr/bin/env python3

import fcntl
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import SplitResult, unquote, urlsplit


LOCK_PATH = "/state/backup.lock"
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


def log(message: str) -> None:
    print(f"[backup] {message}", flush=True)


def run_command(
    command: List[str],
    *,
    env: Optional[Dict[str, str]] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True, env=env)
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


def obscure_secret(secret: str) -> str:
    result = run_command(["rclone", "obscure", secret])
    value = result.stdout.strip()
    if not value:
        raise RuntimeError("rclone obscure returned an empty value")
    return value


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


def sync_with_rsync(destination: Destination, sources: List[Tuple[str, str]]) -> None:
    module_path = destination.path.lstrip("/")
    if not module_path:
        raise RuntimeError(
            "rsync destinations must include a module path (example: rsync://user:pass@host/module/path)"
        )

    host = format_host(destination.hostname)
    if destination.port is not None:
        host = f"{host}:{destination.port}"

    user_prefix = f"{destination.username}@" if destination.username else ""
    remote_base = f"rsync://{user_prefix}{host}/{module_path.rstrip('/')}"

    command_env = os.environ.copy()
    if destination.password:
        command_env["RSYNC_PASSWORD"] = destination.password

    for source_path, destination_path in sources:
        remote_path = f"{remote_base}/{destination_path.strip('/')}/"
        log(f"Syncing {source_path} to rsync destination")
        run_command(
            ["rsync", "-a", "--delete", f"{source_path}/", remote_path],
            env=command_env,
        )


def build_rclone_remote(destination: Destination) -> Tuple[Dict[str, str], str]:
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
        path_segments = [segment for segment in destination.path.split("/") if segment]
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


def write_rclone_config(options: Dict[str, str]) -> str:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write("[backup]\n")
        for key, value in options.items():
            handle.write(f"{key} = {value}\n")
        config_path = handle.name

    os.chmod(config_path, 0o600)
    return config_path


def sync_with_rclone(destination: Destination, sources: List[Tuple[str, str]]) -> None:
    options, remote_prefix = build_rclone_remote(destination)
    config_path = write_rclone_config(options)

    try:
        for source_path, destination_path in sources:
            remote_path = join_path(remote_prefix, destination_path)
            log(f"Syncing {source_path} to {destination.scheme} destination")
            run_command(
                [
                    "rclone",
                    "sync",
                    f"{source_path}/",
                    f"backup:{remote_path}",
                    "--config",
                    config_path,
                    "--create-empty-src-dirs",
                ]
            )
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)


def run_backup() -> int:
    destination_url = os.getenv("BACKUP_DESTINATION", "").strip()
    if not destination_url:
        log("BACKUP_DESTINATION is unset, skipping backup")
        return 0

    sources = available_sources()
    if not sources:
        log("No backup sources are available, skipping backup")
        return 0

    destination = parse_destination(destination_url)
    log(f"Starting backup to {redact_destination(destination.raw_url)}")

    if destination.scheme == "rsync":
        sync_with_rsync(destination, sources)
    else:
        sync_with_rclone(destination, sources)

    log("Backup completed")
    return 0


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
    try:
        return with_lock()
    except Exception as exc:  # pylint: disable=broad-except
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
