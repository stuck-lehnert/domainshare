#!/usr/bin/env python3
"""HTTPS administration UI for the AD-integrated file server."""

import base64
import datetime as dt
import fcntl
import hashlib
import hmac
import http.cookies
import json
import os
import pwd
import re
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

try:
    from app import reconcile_shares as directory
    from app import trash
except ImportError:  # Container execution uses /app as the import root.
    import reconcile_shares as directory
    import trash

try:
    from app.audit_store import (
        audit_summary as sqlite_audit_summary,
        ensure_audit_schema,
        query_activity,
    )
    from app.state_db import (
        STATE_DB_PATH,
        connect_state_db,
        drop_legacy_web_cache,
        ensure_web_cache_schema,
    )
except ImportError:  # Container execution uses /app as the import root.
    from audit_store import (
        audit_summary as sqlite_audit_summary,
        ensure_audit_schema,
        query_activity,
    )
    from state_db import (
        STATE_DB_PATH,
        connect_state_db,
        drop_legacy_web_cache,
        ensure_web_cache_schema,
    )


STATIC_ROOT = os.getenv("WEB_STATIC_DIR", "/app/web")
STATE_DB = STATE_DB_PATH
BACKUP_STATUS_FILE = os.getenv("BACKUP_STATUS_FILE", "/state/backup-status.json")
BACKUP_LOG_FILE = os.getenv("BACKUP_LOG_FILE", "/var/log/backup.log")
BACKUP_LOCK_FILE = os.path.join(os.getenv("STATE_ROOT", "/state"), "backup.lock")
RECONCILE_STATUS_FILE = os.getenv(
    "RECONCILE_STATUS_FILE", "/state/reconcile-status.json"
)
RECONCILE_LOG_FILE = os.getenv("RECONCILE_LOG_FILE", "/var/log/reconcile.log")
RECONCILE_LOCK_FILE = "/state/reconcile.lock"
TLS_CERT_FILE = os.getenv("WEB_TLS_CERT_FILE", "/state/tls/web.crt")
TLS_KEY_FILE = os.getenv("WEB_TLS_KEY_FILE", "/state/tls/web.key")
JWT_COOKIE = "adfs_session"
JWT_ISSUER = "ad-file-server-web"
JWT_AUDIENCE = "domain-admins"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SID_RE = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
LOGIN_LIMIT: Dict[str, deque] = {}
LOGIN_LIMIT_LOCK = threading.Lock()
ACTION_LAUNCH_LOCK = threading.Lock()
ACTIVE_PROCESS_STATES = frozenset({"starting", "running"})


def log(message: str) -> None:
    print(f"[web] {message}", flush=True)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.getenv(name, str(default)))))
    except ValueError:
        return default


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def query_includes_log(params: Dict[str, List[str]]) -> bool:
    raw = params.get("log", ["1"])[0].strip().casefold()
    return raw not in {"0", "false", "no", "off"}


def lock_is_held(path: str) -> bool:
    try:
        with open(path, "r+", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle, fcntl.LOCK_UN)
    except OSError:
        return False
    return False


class ActionConflict(RuntimeError):
    pass


def launch_background(command: List[str], extra_env: Dict[str, str]) -> None:
    environment = os.environ.copy()
    environment.update(extra_env)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise RuntimeError(f"Aktion konnte nicht gestartet werden: {exc}") from exc
    threading.Thread(target=process.wait, name="action-reaper", daemon=True).start()


def start_backup_action(username: str) -> Dict[str, object]:
    if not os.getenv("BACKUP_DESTINATION", "").strip():
        raise ActionConflict("Es ist kein Sicherungsziel eingerichtet")
    if not os.getenv("BACKUP_ARCHIVE_PASSWORD", ""):
        raise ActionConflict("BACKUP_ARCHIVE_PASSWORD ist nicht gesetzt")
    with ACTION_LAUNCH_LOCK:
        if lock_is_held(BACKUP_LOCK_FILE):
            raise ActionConflict("Eine Sicherung läuft bereits")
        launch_background(
            [sys.executable, "/app/backup_to_destination.py"],
            {"BACKUP_TRIGGER": "web"},
        )
    log(f"{username} started a manual backup")
    return {"accepted": True, "action": "backup"}


def start_reconciliation_action(username: str) -> Dict[str, object]:
    with ACTION_LAUNCH_LOCK:
        if lock_is_held(RECONCILE_LOCK_FILE):
            raise ActionConflict("Ein Freigabenabgleich läuft bereits")
        launch_background(
            [sys.executable, "/app/reconcile_shares.py"],
            {"RECONCILE_TRIGGER": "web"},
        )
    log(f"{username} started a manual share reconciliation")
    return {"accepted": True, "action": "reconciliation"}


def read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json_atomic(path: str, value: Dict[str, object]) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temp_path = f"{path}.recovery.tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except (OSError, TypeError, ValueError):
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise


def reconcile_backup_process_status(value: Dict[str, object]) -> Dict[str, object]:
    """Replace stale active state when no worker owns the backup lock."""
    if str(value.get("state", "")) not in ACTIVE_PROCESS_STATES:
        value["processRunning"] = False
        return value

    try:
        lock_dir = os.path.dirname(BACKUP_LOCK_FILE)
        if lock_dir:
            os.makedirs(lock_dir, exist_ok=True)
        with open(BACKUP_LOCK_FILE, "a+", encoding="utf-8") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                value["processRunning"] = True
                return value

            latest = read_json(BACKUP_STATUS_FILE, value)
            if str(latest.get("state", "")) in ACTIVE_PROCESS_STATES:
                latest.update(
                    {
                        "state": "failed",
                        "finishedAt": now_utc().isoformat(timespec="seconds"),
                        "activeFiles": [],
                        "currentSource": None,
                        "workerPid": None,
                        "interrupted": True,
                        "message": (
                            "Backup interrupted because the worker process "
                            "is no longer running"
                        ),
                    }
                )
                write_json_atomic(BACKUP_STATUS_FILE, latest)
                log("Recovered stale backup status after worker interruption")
            latest["processRunning"] = False
            fcntl.flock(lock_file, fcntl.LOCK_UN)
            return latest
    except OSError as exc:
        log(f"Unable to verify backup worker state: {exc}")
        value["processRunning"] = None
        return value


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if not hmac.compare_digest(base64url(decoded), value):
        raise ValueError("non-canonical base64url")
    return decoded


class TokenManager:
    def __init__(self, secret: str, ttl_seconds: int):
        if len(secret.encode("utf-8")) < 32:
            raise RuntimeError("WEB_JWT_SECRET must contain at least 32 bytes")
        self.secret = secret.encode("utf-8")
        self.ttl_seconds = ttl_seconds

    def issue(self, username: str) -> Tuple[str, int]:
        issued = int(time.time())
        expires = issued + self.ttl_seconds
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "sub": username,
            "role": "domain-admin",
            "iat": issued,
            "exp": expires,
            "jti": secrets.token_urlsafe(16),
        }
        signing_input = ".".join(
            [
                base64url(json.dumps(header, separators=(",", ":")).encode()),
                base64url(json.dumps(payload, separators=(",", ":")).encode()),
            ]
        )
        signature = hmac.new(self.secret, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{base64url(signature)}", expires

    def verify(self, token: str) -> Dict[str, object]:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
            signing_input = f"{encoded_header}.{encoded_payload}"
            expected = hmac.new(
                self.secret, signing_input.encode(), hashlib.sha256
            ).digest()
            supplied = base64url_decode(encoded_signature)
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("signature")
            header = json.loads(base64url_decode(encoded_header))
            payload = json.loads(base64url_decode(encoded_payload))
            if header != {"alg": "HS256", "typ": "JWT"}:
                raise ValueError("header")
            if payload.get("iss") != JWT_ISSUER or payload.get("aud") != JWT_AUDIENCE:
                raise ValueError("issuer")
            if payload.get("role") != "domain-admin":
                raise ValueError("role")
            if int(payload.get("exp", 0)) <= int(time.time()):
                raise ValueError("expired")
            if int(payload.get("iat", 0)) > int(time.time()) + 60:
                raise ValueError("issued")
            return payload
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid or expired session") from exc


def normalize_username(username: str) -> str:
    username = username.strip()
    if not username or len(username) > 256 or any(char in username for char in "\r\n\0"):
        raise ValueError("Invalid username")
    if "\\" not in username and "@" not in username:
        username = f"{os.environ['WORKGROUP']}\\{username}"
    return username


def authenticate_domain_admin(username: str, password: str) -> Optional[str]:
    if not password or len(password) > 4096 or any(char in password for char in "\r\n\0"):
        return None
    try:
        qualified = normalize_username(username)
    except ValueError:
        return None

    workgroup = os.environ["WORKGROUP"]
    realm = os.environ["REALM"]
    if "\\" in qualified:
        domain_name, account = qualified.split("\\", 1)
        if domain_name.casefold() != workgroup.casefold():
            return None
    else:
        account, principal_realm = qualified.rsplit("@", 1)
        if principal_realm.casefold() != realm.casefold():
            return None
    if not account:
        return None
    canonical_name = f"{workgroup}\\{account}"
    principal = f"{account}@{realm}"

    cache_fd = -1
    cache_path = ""
    try:
        cache_fd, cache_path = tempfile.mkstemp(
            prefix="web-auth-", dir=os.getenv("WEB_AUTH_CACHE_DIR", "/tmp")
        )
        os.close(cache_fd)
        cache_fd = -1
        command_env = os.environ.copy()
        command_env["KRB5CCNAME"] = f"FILE:{cache_path}"
        auth_result = subprocess.run(
            ["kinit", principal],
            input=f"{password}\n",
            capture_output=True,
            text=True,
            env=command_env,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    finally:
        if cache_fd >= 0:
            os.close(cache_fd)
        if cache_path:
            try:
                os.remove(cache_path)
            except OSError:
                pass
    if auth_result.returncode != 0:
        return None

    try:
        sid_result = subprocess.run(
            ["wbinfo", "--name-to-sid", canonical_name],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        user_sid_match = SID_RE.search(sid_result.stdout)
        if sid_result.returncode != 0 or user_sid_match is None:
            return None
        group_result = subprocess.run(
            ["wbinfo", "--user-sids", user_sid_match.group(0)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if group_result.returncode != 0:
        return None
    admin_sid = os.environ["DOMAIN_ADMINS_SID"].casefold()
    group_sids = {value.casefold() for value in SID_RE.findall(group_result.stdout)}
    return canonical_name if admin_sid in group_sids else None


def login_allowed(remote: str) -> bool:
    now = time.monotonic()
    window = 300
    limit = env_int("WEB_LOGIN_ATTEMPTS_PER_5_MIN", 10, 3, 100)
    with LOGIN_LIMIT_LOCK:
        attempts = LOGIN_LIMIT.setdefault(remote, deque())
        while attempts and now - attempts[0] > window:
            attempts.popleft()
        return len(attempts) < limit


def record_login_failure(remote: str) -> None:
    with LOGIN_LIMIT_LOCK:
        LOGIN_LIMIT.setdefault(remote, deque()).append(time.monotonic())


def clear_login_failures(remote: str) -> None:
    with LOGIN_LIMIT_LOCK:
        LOGIN_LIMIT.pop(remote, None)


def path_size(path: str) -> int:
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def fslogix_username(entry: os.DirEntry) -> str:
    try:
        owner = pwd.getpwuid(entry.stat(follow_symlinks=False).st_uid).pw_name
        owner = owner.split("\\")[-1]
        if owner.lower() not in {"root", "nobody"} and not owner.isdigit():
            return owner
    except (KeyError, OSError):
        pass
    name = re.sub(r"_S-1-\d+(?:-\d+)+$", "", entry.name, flags=re.IGNORECASE)
    return name or entry.name


def scan_children(root: str) -> List[Dict[str, object]]:
    rows = []
    try:
        entries = sorted(os.scandir(root), key=lambda item: item.name.casefold())
    except OSError:
        return rows
    for entry in entries:
        if entry.name == trash.TRASH_DIRECTORY:
            continue
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
            rows.append({"name": entry.name, "bytes": path_size(entry.path)})
        except OSError:
            continue
    return rows


def load_usage_cache() -> Dict[str, object]:
    try:
        conn = connect_state_db(STATE_DB)
        try:
            ensure_web_cache_schema(conn)
            row = conn.execute(
                "SELECT value FROM web_cache WHERE key = 'usage'"
            ).fetchone()
            value = json.loads(str(row[0])) if row is not None else {}
            return value if isinstance(value, dict) else {}
        finally:
            conn.close()
    except (sqlite3.Error, ValueError):
        return {}


def store_usage_cache(value: Dict[str, object]) -> None:
    conn = connect_state_db(STATE_DB)
    try:
        ensure_web_cache_schema(conn)
        with conn:
            conn.execute(
                """
                INSERT INTO web_cache (key, value, updated_at)
                VALUES ('usage', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (
                    json.dumps(value, separators=(",", ":"), sort_keys=True),
                    now_utc().isoformat(timespec="seconds"),
                ),
            )
    finally:
        conn.close()


class UsageScanner:
    def __init__(self):
        self.interval = env_int("WEB_USAGE_SCAN_INTERVAL_SECONDS", 900, 60, 86400)
        self.lock = threading.Lock()
        self.data = load_usage_cache()
        self.stop = threading.Event()

    def snapshot(self) -> Dict[str, object]:
        with self.lock:
            return json.loads(json.dumps(self.data))

    def scan(self) -> Dict[str, object]:
        started = now_utc()
        groups = scan_children(os.getenv("GROUP_ROOT", "/data/groups/data"))
        private = scan_children(os.getenv("PRIVATE_ROOT", "/data/private"))
        fslogix_rows = scan_children(os.getenv("FSLOGIX_ROOT", "/data/fslogix"))
        users: Dict[str, Dict[str, object]] = {}
        for row in private:
            key = str(row["name"]).casefold()
            users[key] = {
                "name": row["name"], "privateBytes": row["bytes"], "fslogixBytes": 0
            }
        fslogix_root = os.getenv("FSLOGIX_ROOT", "/data/fslogix")
        try:
            fs_entries = {entry.name: entry for entry in os.scandir(fslogix_root)}
        except OSError:
            fs_entries = {}
        for row in fslogix_rows:
            entry = fs_entries.get(str(row["name"]))
            name = fslogix_username(entry) if entry else str(row["name"])
            key = name.casefold()
            user = users.setdefault(
                key, {"name": name, "privateBytes": 0, "fslogixBytes": 0}
            )
            user["fslogixBytes"] = int(user["fslogixBytes"]) + int(row["bytes"])
        user_rows = []
        for user in users.values():
            user["totalBytes"] = int(user["privateBytes"]) + int(user["fslogixBytes"])
            user_rows.append(user)
        user_rows.sort(key=lambda row: int(row["totalBytes"]), reverse=True)
        groups.sort(key=lambda row: int(row["bytes"]), reverse=True)
        value = {
            "scannedAt": now_utc().isoformat(timespec="seconds"),
            "scanSeconds": round((now_utc() - started).total_seconds(), 3),
            "groups": groups,
            "users": user_rows,
            "totals": {
                "dataBytes": sum(int(row["bytes"]) for row in groups),
                "privateBytes": sum(int(row["privateBytes"]) for row in user_rows),
                "fslogixBytes": sum(int(row["fslogixBytes"]) for row in user_rows),
            },
        }
        store_usage_cache(value)
        with self.lock:
            self.data = value
        return value

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                self.scan()
            except Exception as exc:  # pylint: disable=broad-except
                log(f"Usage scan failed: {exc}")
            self.stop.wait(self.interval)


def display_name(entry) -> str:
    return (
        directory.ldap_first(entry, "displayName")
        or directory.ldap_first(entry, "sAMAccountName")
        or directory.ldap_first(entry, "cn")
        or directory.entry_dn(entry).split(",", 1)[0].removeprefix("CN=")
        or "Unbekannt"
    )


class DirectoryCache:
    ATTRS = [
        "objectGUID", "objectSid", "distinguishedName", "sAMAccountName",
        "displayName", "cn", "objectClass", "member", "primaryGroupID",
    ]

    def __init__(self):
        self.ttl = env_int("WEB_DIRECTORY_CACHE_SECONDS", 300, 30, 3600)
        self.max_nodes = env_int("WEB_MAX_GROUP_NODES", 10000, 100, 100000)
        self.lock = threading.Lock()
        self.cached_at = 0.0
        self.value: Dict[str, object] = {"groups": [], "fetchedAt": None}

    def get(self) -> Dict[str, object]:
        with self.lock:
            if time.monotonic() - self.cached_at < self.ttl:
                return self.value
            self.value = self.fetch()
            self.cached_at = time.monotonic()
            return self.value

    def fetch(self) -> Dict[str, object]:
        roots = directory.fetch_fileshare_groups()
        entries: Dict[str, object] = {}
        pending = deque()
        for root in roots:
            for dn in root.get("memberDns", []):
                pending.append(str(dn))
        requested = set()
        while pending and len(entries) < self.max_nodes:
            batch = []
            while pending and len(batch) < 100:
                dn = pending.popleft()
                key = directory.normalize_dn(dn)
                if not key or key in requested:
                    continue
                requested.add(key)
                batch.append(dn)
            if not batch:
                continue
            for entry in directory.search_directory_entries(
                directory.build_distinguished_name_filter(batch), self.ATTRS
            ):
                key = directory.normalize_dn(directory.entry_dn(entry))
                if not key:
                    continue
                entries[key] = entry
                classes = {value.lower() for value in directory.ldap_values(entry, "objectClass")}
                if "group" in classes:
                    pending.extend(directory.ldap_values(entry, "member"))

        group_keys_by_primary_rid: Dict[int, List[str]] = {}
        for root in roots:
            root_key = directory.normalize_dn(str(root.get("distinguishedName") or ""))
            rid = directory.sid_rid(str(root.get("objectSid") or ""))
            if root_key and rid is not None:
                group_keys_by_primary_rid.setdefault(rid, []).append(root_key)
        for key, entry in entries.items():
            classes = {
                value.lower()
                for value in directory.ldap_values(entry, "objectClass")
            }
            if "group" not in classes:
                continue
            principal = directory.parse_principal_from_entry(entry)
            rid = directory.sid_rid(
                str(principal.get("objectSid") or "") if principal else ""
            )
            if rid is not None:
                group_keys_by_primary_rid.setdefault(rid, []).append(key)

        primary_members: Dict[str, List[str]] = {}
        primary_members_truncated = False
        if group_keys_by_primary_rid and len(entries) < self.max_nodes:
            primary_entries = directory.search_directory_entries(
                directory.build_primary_group_users_filter(
                    group_keys_by_primary_rid.keys()
                ),
                self.ATTRS,
            )
            for entry in primary_entries:
                key = directory.normalize_dn(directory.entry_dn(entry))
                rid = directory.parse_int(
                    directory.ldap_first(entry, "primaryGroupID") or "",
                    -1,
                )
                if not key or rid not in group_keys_by_primary_rid:
                    continue
                if key not in entries and len(entries) >= self.max_nodes:
                    primary_members_truncated = True
                    continue
                entries[key] = entry
                for group_key in group_keys_by_primary_rid[rid]:
                    primary_members.setdefault(group_key, []).append(
                        directory.entry_dn(entry)
                    )
        elif group_keys_by_primary_rid:
            primary_members_truncated = True

        def effective_members(group_key: str, explicit_dns) -> List[str]:
            result = []
            seen = set()
            for dn in [*explicit_dns, *primary_members.get(group_key, [])]:
                key = directory.normalize_dn(str(dn))
                if key and key not in seen:
                    seen.add(key)
                    result.append(str(dn))
            return result

        folder_map = {}
        try:
            conn = connect_state_db(STATE_DB, read_only=True)
            try:
                folder_map = {
                    row[0]: {"folder": os.path.basename(row[1]), "active": bool(row[2])}
                    for row in conn.execute("SELECT objectGUID, path, isActive FROM shares")
                }
            finally:
                conn.close()
        except sqlite3.Error:
            pass

        def make_node(dn: str, ancestors: set) -> Dict[str, object]:
            key = directory.normalize_dn(dn)
            entry = entries.get(key)
            if entry is None:
                return {"id": dn, "name": dn, "sam": "", "type": "unknown", "members": []}
            classes = {value.lower() for value in directory.ldap_values(entry, "objectClass")}
            node_type = "group" if "group" in classes else "computer" if "computer" in classes else "user"
            node = {
                "id": directory.entry_dn(entry),
                "name": display_name(entry),
                "sam": directory.ldap_first(entry, "sAMAccountName") or "",
                "type": node_type,
                "members": [],
            }
            if key in ancestors:
                node["cycle"] = True
                return node
            if node_type == "group":
                next_ancestors = {*ancestors, key}
                node["members"] = [
                    make_node(child, next_ancestors)
                    for child in effective_members(
                        key,
                        directory.ldap_values(entry, "member"),
                    )
                ]
            return node

        group_rows = []
        for root in sorted(roots, key=lambda item: str(item["shareName"]).casefold()):
            root_key = directory.normalize_dn(
                str(root.get("distinguishedName") or "")
            )
            members = [
                make_node(dn, set())
                for dn in effective_members(root_key, root.get("memberDns", []))
            ]
            flat_users = set()
            flat_groups = set()

            def count_nodes(nodes):
                for node in nodes:
                    target = flat_groups if node["type"] == "group" else flat_users if node["type"] == "user" else None
                    if target is not None:
                        target.add(str(node.get("sam") or node["id"]).casefold())
                    count_nodes(node.get("members", []))

            count_nodes(members)
            folder = folder_map.get(str(root["objectGUID"]), {})
            group_rows.append(
                {
                    "guid": root["objectGUID"],
                    "name": root["shareName"],
                    "sam": root["samAccountName"],
                    "folder": folder.get("folder", root["shareName"]),
                    "active": folder.get("active", True),
                    "userCount": len(flat_users),
                    "groupCount": len(flat_groups),
                    "members": members,
                }
            )
        return {
            "groups": group_rows,
            "fetchedAt": now_utc().isoformat(timespec="seconds"),
            "truncated": bool(pending) or primary_members_truncated,
        }




def query_audit(
    params: Dict[str, List[str]], *, stream: str = "main"
) -> Dict[str, object]:
    today = now_utc().date()
    default_start = today - dt.timedelta(days=1)
    try:
        start = dt.date.fromisoformat(params.get("from", [default_start.isoformat()])[0])
        end = dt.date.fromisoformat(params.get("to", [today.isoformat()])[0])
    except ValueError as exc:
        raise ValueError("Datumsangaben müssen YYYY-MM-DD verwenden") from exc
    max_days = env_int("AUDIT_QUERY_MAX_DAYS", 31, 1, 366)
    if end < start or (end - start).days >= max_days:
        raise ValueError(f"Der Datumsbereich darf höchstens {max_days} Tage umfassen")
    conn = connect_state_db(STATE_DB, read_only=True)
    try:
        return query_activity(conn, start, end, params, stream=stream)
    finally:
        conn.close()


def tail_lines(path: str, count: int) -> List[str]:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            data = b""
            while position > 0 and data.count(b"\n") <= count:
                read_size = min(8192, position)
                position -= read_size
                handle.seek(position)
                data = handle.read(read_size) + data
        return data.decode("utf-8", errors="replace").splitlines()[-count:]
    except OSError:
        return []


def backup_payload(include_log: bool = True) -> Dict[str, object]:
    value = read_json(BACKUP_STATUS_FILE, {})
    value = reconcile_backup_process_status(value)
    value.pop("log", None)
    configured = bool(os.getenv("BACKUP_DESTINATION", "").strip())
    automatic = configured and env_bool("BACKUP_AUTO_ENABLED", True)
    value["enabled"] = configured
    value["manualEnabled"] = configured
    value["automaticEnabled"] = automatic
    value["scheduledHour"] = env_int("BACKUP_START_HOUR", 2, 0, 23)
    if "state" not in value:
        value["state"] = "waiting" if configured else "disabled"
        value["percent"] = 0.0
    if include_log:
        value["log"] = tail_lines(BACKUP_LOG_FILE, 100)
    return value


def reconciliation_payload(include_log: bool = True) -> Dict[str, object]:
    value = read_json(RECONCILE_STATUS_FILE, {})
    value.pop("log", None)
    if "state" not in value:
        value.update(
            {
                "state": "waiting",
                "phase": "waiting",
                "percent": 0.0,
                "message": "No reconciliation has run yet",
            }
        )
    value["automaticEnabled"] = True
    value["scheduledIntervalMinutes"] = 5
    if include_log:
        value["log"] = tail_lines(RECONCILE_LOG_FILE, 150)
    return value


def share_count() -> int:
    try:
        conn = connect_state_db(STATE_DB, read_only=True)
        try:
            return int(conn.execute("SELECT count(*) FROM shares WHERE isActive = 1").fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def audit_archive_summary() -> Dict[str, object]:
    try:
        conn = connect_state_db(STATE_DB, read_only=True)
        try:
            return sqlite_audit_summary(conn, STATE_DB)
        finally:
            conn.close()
    except sqlite3.Error:
        return {"days": 0, "bytes": 0, "oldest": None, "newest": None}


def tls_summary() -> Dict[str, object]:
    try:
        value = ssl._ssl._test_decode_cert(TLS_CERT_FILE)  # pylint: disable=protected-access
        raw_expiry = value.get("notAfter")
        expiry = None
        if raw_expiry:
            expiry = dt.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(raw_expiry), dt.timezone.utc
            ).isoformat(timespec="seconds")
        return {"subject": dict(item[0] for item in value.get("subject", [])), "issuer": dict(item[0] for item in value.get("issuer", [])), "notAfter": expiry, "sans": value.get("subjectAltName", [])}
    except (OSError, ValueError, ssl.SSLError):
        return {}


class App:
    def __init__(self):
        secret = os.environ.get("WEB_JWT_SECRET", "")
        self.tokens = TokenManager(secret, env_int("WEB_JWT_TTL_SECONDS", 28800, 300, 604800))
        removed = drop_legacy_web_cache()
        if removed:
            log(f"Dropped {removed} legacy web cache file(s)")
        self.usage = UsageScanner()
        conn = connect_state_db(STATE_DB)
        try:
            ensure_audit_schema(conn)
            ensure_web_cache_schema(conn)
        finally:
            conn.close()
        self.directory = DirectoryCache()
        threading.Thread(target=self.usage.run, name="usage-scanner", daemon=True).start()

    def overview(self) -> Dict[str, object]:
        usage = self.usage.snapshot()
        recent = query_audit({"limit": ["12"], "facets": ["0"]})
        event_count = recent["matched"]
        if event_count is None:
            event_count = f"{len(recent['events'])}+"
        return {
            "usage": usage,
            "activeGroups": share_count(),
            "recentEvents": recent["events"],
            "eventCount": event_count,
            "backup": backup_payload(),
            "audit": audit_archive_summary(),
        }

    def system_summary(self) -> Dict[str, object]:
        checks = {}
        commands = {
            "domainTrust": ["wbinfo", "-t"],
            "sambaConfig": ["testparm", "-s"],
        }
        for name, command in commands.items():
            try:
                result = subprocess.run(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
                checks[name] = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                checks[name] = False
        return {
            "hostname": os.getenv("WEB_HOSTNAME", ""),
            "checks": checks,
            "tls": tls_summary(),
            "serverTime": now_utc().isoformat(timespec="seconds"),
        }

    def system(self) -> Dict[str, object]:
        value = self.system_summary()
        value["audit"] = audit_archive_summary()
        value["usage"] = self.usage.snapshot()
        return value

    def report(self) -> Dict[str, object]:
        """Return every reportable snapshot without reading either log."""
        return {
            "generatedAt": now_utc().isoformat(timespec="seconds"),
            "groups": self.directory.get(),
            "storage": self.usage.snapshot(),
            "backup": backup_payload(include_log=False),
            "system": self.system_summary(),
        }


APP: Optional[App] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ADFileServerUI/1"

    def log_message(self, fmt: str, *args) -> None:
        log(f"{self.client_address[0]} {fmt % args}")

    def security_headers(self, cache_control: str = "no-store") -> None:
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", cache_control)

    def send_json(self, value: object, status: int = 200, cookie: Optional[str] = None) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json({"error": message}, status)

    def token(self) -> Optional[str]:
        authorization = self.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            return authorization[7:].strip()
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(JWT_COOKIE)
        return morsel.value if morsel else None

    def user(self) -> Optional[Dict[str, object]]:
        token = self.token()
        if not token:
            return None
        try:
            return APP.tokens.verify(token) if APP else None
        except ValueError:
            return None

    def require_user(self) -> Optional[Dict[str, object]]:
        value = self.user()
        if value is None:
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "Anmeldung erforderlich")
        return value

    def read_json_body(self) -> Dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Ungültige Anfragelänge") from exc
        if length <= 0 or length > 16384:
            raise ValueError("Ungültiger Anfrageinhalt")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValueError("Ungültiges JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("Ein JSON-Objekt ist erforderlich")
        return value

    def send_trash_download(self, params: Dict[str, List[str]]) -> None:
        item_id = params.get("id", [""])[0]
        try:
            handle, item = trash.open_download(item_id)
        except FileNotFoundError:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Datei nicht gefunden oder abgelaufen")
            return
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except OSError as exc:
            log(f"Trash download failed: {exc}")
            self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "Download konnte nicht geöffnet werden")
            return

        filename = str(item["name"])
        encoded_name = urllib.parse.quote(filename, safe="")
        with handle:
            self.send_response(HTTPStatus.OK)
            self.security_headers()
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(item["size"]))
            self.send_header(
                "Content-Disposition",
                f"attachment; filename*=UTF-8{chr(39) * 2}{encoded_name}",
            )
            self.end_headers()
            try:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass


    def do_POST(self) -> None:  # pylint: disable=invalid-name
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/login":
            remote = self.client_address[0]
            if not login_allowed(remote):
                self.send_error_json(HTTPStatus.TOO_MANY_REQUESTS, "Zu viele Anmeldeversuche; bitte später erneut versuchen")
                return
            try:
                body = self.read_json_body()
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            username = authenticate_domain_admin(str(body.get("username", "")), str(body.get("password", "")))
            if username is None:
                record_login_failure(remote)
                time.sleep(0.4)
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Ungültige Zugangsdaten oder keine Mitgliedschaft bei den Domänenadministratoren")
                return
            clear_login_failures(remote)
            token, expires = APP.tokens.issue(username)
            max_age = max(0, expires - int(time.time()))
            cookie = f"{JWT_COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
            self.send_json({"user": username, "expiresAt": expires, "token": token, "tokenType": "Bearer"}, cookie=cookie)
            return
        if parsed.path == "/api/logout":
            cookie = f"{JWT_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
            self.send_json({"ok": True}, cookie=cookie)
            return
        if parsed.path == "/api/trash/restore":
            user = self.require_user()
            if user is None:
                return
            try:
                body = self.read_json_body()
                result = trash.restore_item(str(body.get("id", "")))
            except FileExistsError:
                self.send_error_json(
                    HTTPStatus.CONFLICT,
                    "Am Originalpfad existiert bereits eine Datei",
                )
                return
            except FileNotFoundError:
                self.send_error_json(
                    HTTPStatus.NOT_FOUND,
                    "Datei nicht gefunden oder abgelaufen",
                )
                return
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            except (OSError, RuntimeError) as exc:
                log(f"Trash restore failed: {exc}")
                self.send_error_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "Datei konnte nicht wiederhergestellt werden",
                )
                return
            log(
                f"{user['sub']} restored "
                f"{result['share']}:{result['path']}"
            )
            self.send_json(result)
            return

        if parsed.path.startswith("/api/actions/"):
            user = self.require_user()
            if user is None:
                return
            try:
                if parsed.path == "/api/actions/backup":
                    result = start_backup_action(str(user["sub"]))
                elif parsed.path == "/api/actions/reconciliation":
                    result = start_reconciliation_action(str(user["sub"]))
                else:
                    self.send_error_json(HTTPStatus.NOT_FOUND, "Nicht gefunden")
                    return
                self.send_json(result, HTTPStatus.ACCEPTED)
            except ActionConflict as exc:
                self.send_error_json(HTTPStatus.CONFLICT, str(exc))
            except RuntimeError as exc:
                log(f"Action {parsed.path} failed: {exc}")
                self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
            return
        self.send_error_json(HTTPStatus.NOT_FOUND, "Nicht gefunden")

    def do_GET(self) -> None:  # pylint: disable=invalid-name,too-many-return-statements
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self.send_json({"status": "ok"})
            return
        if path.startswith("/api/"):
            user = self.require_user()
            if user is None:
                return
            params = urllib.parse.parse_qs(parsed.query)
            try:
                if path == "/api/session":
                    self.send_json({"user": user["sub"], "expiresAt": user["exp"]})
                elif path == "/api/overview":
                    self.send_json(APP.overview())
                elif path == "/api/groups":
                    self.send_json(APP.directory.get())
                elif path == "/api/storage":
                    self.send_json(APP.usage.snapshot())
                elif path == "/api/activity":
                    self.send_json(query_audit(params))
                elif path == "/api/fslogix-activity":
                    self.send_json(query_audit(params, stream="fslogix"))
                elif path == "/api/trash/download":
                    self.send_trash_download(params)
                elif path == "/api/trash":
                    self.send_json(
                        trash.list_items(
                            share=params.get("share", [""])[0],
                            path=params.get("path", [""])[0],
                            limit=int(params.get("limit", ["200"])[0]),
                        )
                    )
                elif path == "/api/backup":
                    self.send_json(
                        backup_payload(include_log=query_includes_log(params))
                    )
                elif path == "/api/reconciliation":
                    self.send_json(
                        reconciliation_payload(include_log=query_includes_log(params))
                    )
                elif path == "/api/system":
                    self.send_json(APP.system())
                elif path == "/api/report":
                    self.send_json(APP.report())
                else:
                    self.send_error_json(HTTPStatus.NOT_FOUND, "Nicht gefunden")
            except (ValueError, OSError, RuntimeError) as exc:
                log(f"Request {path} failed: {exc}")
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.serve_static(path)

    def serve_static(self, path: str) -> None:
        files = {
            "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/assets/report.mjs": ("report.mjs", "text/javascript; charset=utf-8"),
            "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/assets/vendor/typst/0.6.0-csp1/typst.mjs": ("vendor/typst/typst.mjs", "text/javascript; charset=utf-8"),
            "/assets/vendor/typst/0.6.0-csp1/compiler.wasm": ("vendor/typst/compiler.wasm", "application/wasm"),
            "/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Regular.otf": ("vendor/typst/LibertinusSerif-Regular.otf", "font/otf"),
            "/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Semibold.otf": ("vendor/typst/LibertinusSerif-Semibold.otf", "font/otf"),
            "/favicon.svg": ("favicon.svg", "image/svg+xml"),
        }
        if path in files:
            filename, content_type = files[path]
        else:
            filename, content_type = "index.html", "text/html; charset=utf-8"
        try:
            with open(os.path.join(STATIC_ROOT, filename), "rb") as handle:
                body = handle.read()
        except OSError:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Statische Datei nicht gefunden")
            return
        self.send_response(HTTPStatus.OK)
        cache_control = (
            "public, max-age=31536000, immutable"
            if path.startswith("/assets/vendor/typst/")
            else "no-store"
        )
        self.security_headers(cache_control)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_https() -> None:
    address = os.getenv("WEB_BIND_ADDRESS", "0.0.0.0")
    port = env_int("WEB_BIND_PORT", 8443, 1, 65535)
    cert_mtime = -1.0
    log(f"Serving https://{os.getenv('WEB_HOSTNAME', address)}:{port}")
    while True:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
        server = ReusableHTTPServer((address, port), Handler)
        server.timeout = 1
        server.socket = context.wrap_socket(server.socket, server_side=True)
        cert_mtime = os.path.getmtime(TLS_CERT_FILE)
        try:
            while os.path.getmtime(TLS_CERT_FILE) == cert_mtime:
                server.handle_request()
        finally:
            server.server_close()
        log("TLS certificate changed; reloading HTTPS listener")


def main() -> int:
    global APP
    if not os.path.isfile(TLS_CERT_FILE) or not os.path.isfile(TLS_KEY_FILE):
        raise RuntimeError("TLS certificate or key is missing")
    APP = App()
    serve_https()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:  # pylint: disable=broad-except
        log(f"ERROR: {exc}")
        sys.exit(1)
