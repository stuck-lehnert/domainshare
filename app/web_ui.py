#!/usr/bin/env python3
"""HTTPS administration UI for DomainShare."""

import base64
import datetime as dt
import errno
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
    from app import agent_api, trash, access_control, documents, web_security, configuration
    from app.account_policy import is_excluded_user
except ImportError:  # Container execution uses /app as the import root.
    import reconcile_shares as directory
    import agent_api, trash, access_control, documents, web_security, configuration
    from account_policy import is_excluded_user

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
JWT_COOKIE = "domainshare_session"
JWT_ISSUER = "domainshare-web"
JWT_AUDIENCE = "ad-users"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SID_RE = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
LOGIN_LIMIT: Dict[tuple, deque] = {}
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
    if CONFIG is not None:
        environment.update(CONFIG.environment())
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
    if env_bool('BACKUP_ENCRYPTION_ENABLED', False) and not os.getenv("BACKUP_ARCHIVE_PASSWORD", ""):
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
    def __init__(self, secret: str, ttl_seconds: int, sessions=None, identity_resolver=None):
        if len(secret.encode("utf-8")) < 32:
            raise RuntimeError("WEB_JWT_SECRET must contain at least 32 bytes")
        self.secret = secret.encode("utf-8")
        self.ttl_seconds = ttl_seconds
        self.sessions = sessions if sessions is not None else web_security.Sessions()
        self.identity_resolver = identity_resolver

    def issue(self, username: str, sid: str, role: str = "user", uid: Optional[int] = None) -> Tuple[str, int]:
        issued = int(time.time())
        expires = issued + self.ttl_seconds
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "sub": username,
            "sid": sid,
            "uid": uid,
            "role": role,
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
        self.sessions.issue(payload)
        return f"{signing_input}.{base64url(signature)}", expires

    def verify(self, token: str, refresh_identity: bool = True) -> Dict[str, object]:
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
            if payload.get("role") not in {"domain-admin", "user"} or not SID_RE.fullmatch(str(payload.get("sid", ""))):
                raise ValueError("role")
            if int(payload.get("exp", 0)) <= int(time.time()):
                raise ValueError("expired")
            if int(payload.get("iat", 0)) > int(time.time()) + 60:
                raise ValueError("issued")
            jti = payload.get('jti')
            if not isinstance(jti, str) or not jti or len(jti) > 128:
                raise ValueError('session id')
            current = self.sessions.get(jti, time.time())
            if current is None or current['sid'] != payload['sid'] or current['expires'] != payload['exp']:
                raise ValueError('revoked')
            interval = env_int('WEB_AUTH_RECHECK_SECONDS', 60, 5, 300)
            if refresh_identity and self.identity_resolver and time.time() - current['checked'] >= interval:
                identity = self.identity_resolver(payload['sid'])
                if identity is None or identity.get('sid') != payload['sid']:
                    # Fail closed on an unavailable directory; do not keep
                    # trusting old admin claims while winbind is unreachable.
                    raise ValueError('directory unavailable')
                self.sessions.refresh(jti, identity, time.time())
                current = self.sessions.get(jti, time.time())
                if current is None:
                    raise ValueError('revoked')
            payload.update(sub=current['username'], uid=current['uid'], role=current['role'])
            return payload
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid or expired session") from exc

    def csrf(self, payload):
        return base64url(hmac.new(self.secret, ('csrf:' + payload['jti']).encode(), hashlib.sha256).digest())

    def revoke(self, payload):
        self.sessions.revoke(payload['jti'])


def normalize_username(username: str) -> str:
    username = username.strip()
    if not username or len(username) > 256 or any(char in username for char in "\r\n\0"):
        raise ValueError("Invalid username")
    if "\\" not in username and "@" not in username:
        username = f"{os.environ['WORKGROUP']}\\{username}"
    return username


def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    if not password or len(password) > 4096 or any(char in password for char in "\r\n\0"):
        return None
    try:
        qualified = normalize_username(username)
    except ValueError:
        return None

    workgroup = os.environ["WORKGROUP"]
    realm = os.environ["REALM"]
    is_upn = "\\" not in qualified
    if "\\" in qualified:
        domain_name, account = qualified.split("\\", 1)
        if domain_name.casefold() != workgroup.casefold():
            return None
        principal = f"{account}@{realm}"
    else:
        if qualified.count("@") != 1:
            return None
        account, principal_realm = qualified.rsplit("@", 1)
        # A UPN suffix belongs to AD, including alternate DNS suffixes. DOMAIN
        # names the domain controller; WORKGROUP is only for DOMAIN\user logins.
        if not principal_realm or principal_realm.casefold() == workgroup.casefold() or any(char.isspace() for char in principal_realm):
            return None
        principal = qualified
    if not account or any(char in account for char in "@\\/") or is_excluded_user(account):
        return None
    canonical_name = f"{workgroup}\\{account}"

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
        command_env["LC_ALL"] = "C"
        auth_result = subprocess.run(
            ["kinit", *(["-C", "-E"] if is_upn else []), "--", principal],
            input=f"{password}\n",
            capture_output=True,
            text=True,
            env=command_env,
            timeout=15,
            check=False,
        )
        if auth_result.returncode != 0:
            return None
        if is_upn:
            # Use the KDC-confirmed account, never assume the UPN prefix is its
            # sAMAccountName. Keep the ticket private and remove it below.
            ticket = subprocess.run(["klist", "-c", cache_path], capture_output=True, text=True,
                                    env=command_env, timeout=15, check=False)
            matched = re.search(r"^Default principal:\s*([^\s@\\/]+)@([^\s]+)\s*$", ticket.stdout, re.MULTILINE)
            if ticket.returncode != 0 or not matched or matched.group(2).casefold() != realm.casefold():
                return None
            account = matched.group(1)
            if is_excluded_user(account):
                return None
            canonical_name = f"{workgroup}\\{account}"
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
    except (OSError, subprocess.TimeoutExpired):
        return None
    return current_identity(user_sid_match.group(0))


def current_identity(sid: str, admin_sid=None):
    try:
        group_result = subprocess.run(["wbinfo", "--user-sids", sid], capture_output=True,
                                      text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if group_result.returncode != 0:
        return None
    admin_sid = (admin_sid or os.environ["DOMAIN_ADMINS_SID"]).casefold()
    group_sids = {value.casefold() for value in SID_RE.findall(group_result.stdout)}
    try:
        resolved = subprocess.run(["wbinfo", "--sid-to-name", sid], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if resolved.returncode != 0 or not resolved.stdout.strip().endswith(" 1"):
        return None
    canonical_name = resolved.stdout.strip().rsplit(" ", 1)[0]
    if is_excluded_user(canonical_name):
        return None
    try:
        mapped = subprocess.run(["wbinfo", "--sid-to-uid", sid], capture_output=True, text=True, timeout=15, check=False)
        uid = int(mapped.stdout.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
    if mapped.returncode or uid < 0:
        return None
    return {"sub": canonical_name, "sid": sid, "uid": uid, "role": "domain-admin" if admin_sid in group_sids else "user"}


def authenticate_domain_admin(username: str, password: str) -> Optional[str]:
    identity = authenticate_user(username, password)
    return identity["sub"] if identity and identity["role"] == "domain-admin" else None


def reserve_login(remote: str, username: str) -> bool:
    now = time.monotonic()
    window = 300
    ip_limit = env_int("WEB_LOGIN_ATTEMPTS_PER_5_MIN", 10, 3, 100)
    account_limit = env_int('WEB_LOGIN_ACCOUNT_ATTEMPTS_PER_5_MIN', 10, 3, 100)
    # The supported domain-qualified spellings share the same target budget.
    account = username.strip().rsplit('\\', 1)[-1].split('@', 1)[0].casefold()[:256]
    keys = (('ip', remote), ('account', account))
    with LOGIN_LIMIT_LOCK:
        for key in list(LOGIN_LIMIT):
            attempts = LOGIN_LIMIT[key]
            while attempts and now - attempts[0] >= window:
                attempts.popleft()
            if not attempts:
                del LOGIN_LIMIT[key]
        attempts = [LOGIN_LIMIT.get(key, ()) for key in keys]
        if len(attempts[0]) >= ip_limit or len(attempts[1]) >= account_limit:
            return False
        for key in keys:
            LOGIN_LIMIT.setdefault(key, deque()).append(now)
        return True


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
            value = json.loads(json.dumps(self.data))
            value["users"] = [row for row in value.get("users", []) if not is_excluded_user(str(row["name"]))]
            return value

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
            "users": [row for row in user_rows if not is_excluded_user(str(row["name"]))],
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


class DirectoryCache:
    def __init__(self):
        self.ttl = env_int("WEB_DIRECTORY_CACHE_SECONDS", 300, 30, 3600)
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
        conn = directory.open_db()
        try:
            access_control.ensure_schema(conn)
            return access_control.report_folders(conn)
        finally:
            conn.close()



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
    def __init__(self, agent_tokens=None):
        self.agent_tokens = agent_tokens
        secret = os.environ.get("WEB_JWT_SECRET", "")
        self.tokens = TokenManager(secret, env_int("WEB_JWT_TTL_SECONDS", 28800, 300, 604800),
                                   web_security.Sessions(STATE_DB), current_identity)
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
CONFIG = None


class Handler(BaseHTTPRequestHandler):
    server_version = "DomainShare/1"

    def log_message(self, fmt: str, *args) -> None:
        log(f"{self.client_address[0]} {fmt % args}")

    def log_request(self, code='-', size='-'):
        if self.path.partition('?')[0].startswith('/api/agent/'):
            self.log_message('"%s /api/agent/…" %s %s', self.command, str(code), str(size))
            return
        super().log_request(code, size)

    def reload_configuration(self):
        if CONFIG is not None:
            for name in ('LDAP_URI', 'LDAP_BASE_DN', 'AD_DNS_NAME'):
                os.environ.pop(name, None)
            os.environ.update(CONFIG.environment(materialize=False))

    def domain_groups(self):
        entries = directory.search_directory_entries('(objectClass=group)', access_control.ATTRS)
        result = []
        for entry in entries:
            principal = directory.parse_principal_from_entry(entry)
            if principal and directory.is_group_principal(principal):
                sid = str(principal.get('objectSid') or '')
                if SID_RE.fullmatch(sid):
                    result.append({'sid': sid, 'name': str(principal.get('samAccountName') or sid)})
        return sorted(result, key=lambda row: row['name'].casefold())

    def bootstrap(self, path, mutation=False):
        if CONFIG is None:
            self.send_error_json(HTTPStatus.NOT_FOUND, 'Nicht gefunden')
            return
        snap = CONFIG.snapshot()
        if path == '/api/bootstrap/status' and not mutation:
            self.send_json({'phase': snap['phase'], 'configured': snap['phase'] == 'configured'})
            return
        if not CONFIG.accepts_bootstrap(self.headers.get('X-Setup-Token', '')):
            self.send_error_json(HTTPStatus.FORBIDDEN, 'Ungültiger Einrichtungscode oder Einrichtung abgeschlossen')
            return
        if mutation:
            if self.headers.get_content_type() != 'application/json' or self.headers.get('Sec-Fetch-Site') in {'cross-site', 'same-site'}:
                self.send_error_json(HTTPStatus.FORBIDDEN, 'Einrichtung erfordert JSON vom selben Origin')
                return
            origin = self.headers.get('Origin')
            if origin:
                try:
                    if web_security.origin(origin) != web_security.origin('https://' + self.headers.get('Host', '')):
                        raise ValueError()
                except ValueError:
                    self.send_error_json(HTTPStatus.FORBIDDEN, 'Ungültiger Einrichtungs-Origin')
                    return
        try:
            if not mutation and path == '/api/bootstrap/settings':
                value = CONFIG.public()
                value['services'] = read_json(str(CONFIG.root / 'services-status.json'), {'state': 'waiting'})
                self.send_json(value)
            elif not mutation and path == '/api/bootstrap/groups':
                if not os.path.exists('/run/domainshare-domain-ready'):
                    raise ValueError('Domänenbeitritt ist noch nicht abgeschlossen')
                self.send_json({'groups': self.domain_groups()})
            elif mutation and path == '/api/bootstrap/domain':
                body = self.read_json_body(262144)
                changes = body.get('values', {})
                if not isinstance(changes, dict) or any(key not in configuration.FIELDS or configuration.FIELDS[key]['section'] not in {'domain', 'network', 'tls'} for key in changes):
                    raise ValueError('Nur Domänen-, Server- und HTTPS-Einstellungen sind hier zulässig')
                if not all(changes.get(key) or snap['values'].get(key) for key in ('REALM', 'WORKGROUP', 'DOMAIN', 'JOIN_USER', 'JOIN_PASSWORD')):
                    raise ValueError('Domäne und Zugangsdaten für den Beitritt sind erforderlich')
                CONFIG.save(changes, body.get('revision'), bootstrap=True)
                CONFIG.phase('joining')
                self.reload_configuration()
                self.send_json(CONFIG.public(), HTTPStatus.ACCEPTED)
            elif mutation and path == '/api/bootstrap/finish':
                if not os.path.exists('/run/domainshare-domain-ready'):
                    raise ValueError('Domänenbeitritt ist noch nicht abgeschlossen')
                body = self.read_json_body()
                changes = body.get('values', {})
                if not isinstance(changes, dict) or set(changes) != {'DOMAIN_USERS_SID', 'DOMAIN_ADMINS_SID', 'FSLOGIX_GROUP_SID'}:
                    raise ValueError('Benutzer-, Administratoren- und FSLogix-Gruppe auswählen')
                groups = {row['sid'] for row in self.domain_groups()}
                if any(sid not in groups for sid in changes.values()):
                    raise ValueError('Ausgewählte Gruppe ist nicht im aktuellen AD vorhanden')
                identity = authenticate_user(body.get('username', snap['values']['JOIN_USER']), body.get('password', snap['values']['JOIN_PASSWORD']))
                administrator = current_identity(identity['sid'], admin_sid=changes['DOMAIN_ADMINS_SID']) if identity else None
                if not administrator or administrator['role'] != 'domain-admin':
                    raise ValueError('Das Einrichtungskonto muss zur ausgewählten Administratorengruppe gehören')
                result = CONFIG.save(changes, body.get('revision'), bootstrap=True)
                CONFIG.finish(result['revision'])
                self.send_json({'configured': True, 'hostname': CONFIG.snapshot()['values']['WEB_HOSTNAME']})
            elif mutation and path == '/api/bootstrap/import':
                body = self.read_json_body(262144)
                if not CONFIG.import_legacy(configuration.parse_legacy(body.get('text', ''))):
                    raise ValueError('Frühere Konfiguration ist unvollständig')
                self.reload_configuration()
                self.send_json({'configured': True})
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, 'Nicht gefunden')
        except configuration.Conflict as exc:
            self.send_error_json(HTTPStatus.CONFLICT, str(exc))
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def settings_write(self, path, user):
        if CONFIG is None:
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, 'Einstellungen nicht verfügbar')
            return
        try:
            body = self.read_json_body(262144)
            with ACTION_LAUNCH_LOCK:
                if lock_is_held(BACKUP_LOCK_FILE):
                    raise configuration.Conflict('Während einer Sicherung können Einstellungen und Schlüssel nicht geändert werden')
                if path == '/api/settings':
                    values = body.get('values', {})
                    if isinstance(values, dict) and any(key in values for key in ('DOMAIN_USERS_SID', 'DOMAIN_ADMINS_SID', 'FSLOGIX_GROUP_SID')):
                        groups = {row['sid'] for row in self.domain_groups()}
                        if any(values[key] not in groups for key in values if key in ('DOMAIN_USERS_SID', 'DOMAIN_ADMINS_SID', 'FSLOGIX_GROUP_SID')):
                            raise ValueError('Ausgewählte Gruppe ist nicht im aktuellen AD vorhanden')
                        if 'DOMAIN_ADMINS_SID' in values:
                            identity = current_identity(user['sid'], admin_sid=values['DOMAIN_ADMINS_SID'])
                            if not identity or identity['role'] != 'domain-admin':
                                raise ValueError('Sie müssen Mitglied der ausgewählten Administratorengruppe sein')
                    result = CONFIG.save(values, body.get('revision'))
                    if 'DOMAIN_ADMINS_SID' in values:
                        APP.tokens.sessions.recheck_all()
                    result['restartRequired'] = any(configuration.FIELDS[key]['section'] != 'backup' for key in values)
                elif path == '/api/settings/backup-key/generate':
                    result = CONFIG.generate_key(str(user['jti']))
                elif path == '/api/settings/backup-key/activate':
                    result = CONFIG.activate_key(str(user['jti']), body.get('nonce'), body.get('writtenDown'), body.get('acknowledgeOldBackups'))
                else:
                    self.send_error_json(HTTPStatus.NOT_FOUND, 'Nicht gefunden')
                    return
            self.reload_configuration()
            self.send_json(result)
        except configuration.Conflict as exc:
            self.send_error_json(HTTPStatus.CONFLICT, str(exc))
        except (ValueError, TypeError, OSError) as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))

    def security_headers(self, cache_control: str = "no-store", pdf_viewer: bool = False) -> None:
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            ("default-src 'self'; connect-src 'self' blob: data:; img-src 'self' data: blob:; "
             "worker-src 'self' blob:; font-src 'self' data: blob:; media-src blob:; "
             if pdf_viewer else "default-src 'self'; connect-src 'self'; img-src 'self' data:; ") +
            "style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
            "base-uri 'none'; frame-ancestors " + ("'self'" if pdf_viewer else "'none'") + "; form-action 'self'",
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

    def user(self, refresh_identity: bool = True) -> Optional[Dict[str, object]]:
        token = self.token()
        if not token:
            return None
        try:
            return APP.tokens.verify(token, refresh_identity=refresh_identity) if APP else None
        except ValueError:
            return None

    def require_user(self, refresh_identity: bool = True) -> Optional[Dict[str, object]]:
        value = self.user(refresh_identity=refresh_identity)
        if value is None:
            self.send_error_json(HTTPStatus.UNAUTHORIZED, "Anmeldung erforderlich")
        return value

    def require_admin(self, value=None) -> Optional[Dict[str, object]]:
        if value is None:
            value = self.require_user()
        if value is not None and value.get("role") != "domain-admin":
            self.send_error_json(HTTPStatus.FORBIDDEN, "Domänenadministrator erforderlich")
            return None
        return value

    def read_json_body(self, maximum: int = 16384) -> Dict[str, object]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Ungültige Anfragelänge") from exc
        if length <= 0 or length > maximum:
            raise ValueError("Ungültiger Anfrageinhalt")
        try:
            value = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValueError("Ungültiges JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("Ein JSON-Objekt ist erforderlich")
        return value

    def check_write_origin(self) -> bool:
        if self.headers.get_content_type() != 'application/json':
            self.send_error_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, 'application/json erforderlich')
            return False
        value = self.headers.get('Origin')
        if value is not None:
            configured = os.getenv('WEB_TRUSTED_ORIGINS', '').strip()
            if not configured:
                hostname = os.getenv('WEB_HOSTNAME', os.getenv('AD_DNS_NAME', 'localhost'))
                port = env_int('WEB_HTTPS_PORT', 443, 1, 65535)
                configured = f'https://{hostname}' + (f':{port}' if port != 443 else '')
            try:
                allowed = {web_security.origin(item.strip()) for item in configured.split(',')}
                if web_security.origin(value) not in allowed:
                    raise ValueError()
            except ValueError:
                self.send_error_json(HTTPStatus.FORBIDDEN, 'Nicht vertrauenswürdiger Origin')
                return False
        if self.headers.get('Sec-Fetch-Site') in {'cross-site', 'same-site'}:
            self.send_error_json(HTTPStatus.FORBIDDEN, 'Anfrage muss vom selben Origin stammen')
            return False
        return True

    def check_csrf(self, user) -> bool:
        supplied = self.headers.get('X-CSRF-Token', '')
        # Origin-less API clients must explicitly carry their bearer token;
        # browser cookie requests always need an exact trusted Origin as well.
        bearer = self.headers.get('Authorization', '').startswith('Bearer ')
        if (not self.headers.get('Origin') and not bearer or
                not hmac.compare_digest(supplied.encode('utf-8'), APP.tokens.csrf(user).encode('ascii'))):
            self.send_error_json(HTTPStatus.FORBIDDEN, 'Ungültiger CSRF-Schutz')
            return False
        return True

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
        self.reload_configuration()
        if parsed.path.startswith('/api/bootstrap/'):
            self.bootstrap(parsed.path, mutation=True)
            return
        if CONFIG is not None and CONFIG.snapshot()['phase'] != 'configured':
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, 'Ersteinrichtung erforderlich')
            return
        if not self.check_write_origin():
            return
        if parsed.path == "/api/login":
            # Login has no authenticated session yet. A custom header and JSON
            # prevent simple cross-origin requests; Origin is checked above.
            if self.headers.get('X-CSRF-Token') != 'login':
                self.send_error_json(HTTPStatus.FORBIDDEN, 'Ungültiger CSRF-Schutz')
                return
            remote = self.client_address[0]
            try:
                body = self.read_json_body()
            except ValueError as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
                return
            username = str(body.get('username', ''))
            if not reserve_login(remote, username):
                self.send_error_json(HTTPStatus.TOO_MANY_REQUESTS, "Zu viele Anmeldeversuche; bitte später erneut versuchen")
                return
            identity = authenticate_user(username, str(body.get("password", "")))
            if identity is None:
                time.sleep(0.4)
                self.send_error_json(HTTPStatus.UNAUTHORIZED, "Ungültige Zugangsdaten")
                return
            token, expires = APP.tokens.issue(identity["sub"], identity["sid"], identity["role"], identity["uid"])
            conn = directory.open_db()
            try:
                access_control.ensure_schema(conn)
                sam = identity["sub"].split("\\")[-1]
                conn.execute("INSERT INTO access_users(sid,sam,name) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET sam=excluded.sam",
                             (identity["sid"], sam, sam))
                conn.commit()
            finally:
                conn.close()
            max_age = max(0, expires - int(time.time()))
            cookie = f"{JWT_COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"
            payload = APP.tokens.verify(token)
            self.send_json({"user": identity["sub"], "sid": identity["sid"], "role": identity["role"], "expiresAt": expires, "token": token, "tokenType": "Bearer", 'csrfToken': APP.tokens.csrf(payload)}, cookie=cookie)
            return
        if parsed.path == "/api/logout":
            # Revoking a valid session must also work during an AD outage.
            user = self.require_user(refresh_identity=False)
            if user is None or not self.check_csrf(user):
                return
            APP.tokens.revoke(user)
            cookie = f"{JWT_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
            self.send_json({"ok": True}, cookie=cookie)
            return
        if not parsed.path.startswith("/admin/api/"):
            self.send_error_json(HTTPStatus.NOT_FOUND, "Nicht gefunden")
            return
        user = self.require_user()
        if user is None or not self.check_csrf(user):
            return
        administrator = self.require_admin(user)
        if administrator is None:
            return
        if parsed.path in {'/admin/api/agent-tokens', '/admin/api/agent-tokens/revoke'}:
            self.manage_agent_tokens(parsed.path, administrator)
            return
        parsed = parsed._replace(path=parsed.path[len("/admin"):])
        if parsed.path == '/api/settings' or parsed.path.startswith('/api/settings/'):
            self.settings_write(parsed.path, administrator)
            return
        if parsed.path == "/api/documents/control":
            conn = documents.connect()
            try:
                documents.ensure_schema(conn)
                body = self.read_json_body()
                self.send_json(documents.control_worker(conn, body.get("action"), str(administrator["sub"])))
            except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            finally:
                conn.close()
            return
        if parsed.path == "/api/access":
            user = self.require_user()
            if user is None:
                return
            try:
                body = self.read_json_body(1024 * 1024)
                with access_control.mutation_lock():
                    conn = directory.open_db()
                    try:
                        access_control.migrate(conn)
                        users, _ = access_control.read_directory()
                        result = access_control.apply_change(conn, body, str(user["sub"]), users)
                    finally:
                        conn.close()
                with APP.directory.lock:
                    APP.directory.cached_at = 0
                log(f"{user['sub']} changed folder access: {body.get('action')}")
                self.send_json(result)
            except access_control.AccessConflict as exc:
                self.send_error_json(HTTPStatus.CONFLICT, str(exc))
            except (ValueError, sqlite3.IntegrityError) as exc:
                self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
            except (OSError, RuntimeError) as exc:
                log(f"Access management failed: {exc}")
                self.send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
            return

        if parsed.path == "/api/trash/restore":
            user = self.require_user()
            if user is None:
                return
            try:
                body = self.read_json_body()
                item_id = str(body.get("id", ""))
                share, _ = trash.decode_item_id(item_id)
                if share == "Data":
                    with access_control.mutation_lock():
                        conn = directory.open_db()
                        try:
                            result = trash.restore_item(item_id, prepare=lambda path, fd: access_control.prepare_data_restore(conn, path, fd))
                        finally:
                            conn.close()
                else:
                    result = trash.restore_item(item_id)
            except access_control.AccessConflict as exc:
                self.send_error_json(HTTPStatus.CONFLICT, str(exc))
                return
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
        self.reload_configuration()
        path = parsed.path
        if path.startswith('/api/bootstrap/'):
            self.bootstrap(path)
            return
        if path == "/healthz":
            if CONFIG is not None and CONFIG.snapshot()['phase'] == 'configured' and not os.path.exists('/run/domainshare-services-ready'):
                self.send_json({'status': 'starting', 'message': 'Dateidienste werden gestartet'}, HTTPStatus.SERVICE_UNAVAILABLE)
                return
            self.send_json({"status": "ok"})
            return
        if CONFIG is not None and CONFIG.snapshot()['phase'] != 'configured' and not path.startswith('/assets/'):
            if path.startswith('/api/') or path.startswith('/admin/api/'):
                self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, 'Ersteinrichtung erforderlich')
            else:
                self.serve_static('/setup')
            return
        if path == '/admin/api/agent-tokens':
            administrator = self.require_admin()
            if administrator is not None:
                self.manage_agent_tokens(path, administrator, inventory=True)
            return
        if path.startswith('/api/agent/'):
            self.agent_request(path, parsed.query)
            return
        if path.startswith("/api/"):
            user = self.require_user()
            if user is None:
                return
            params = urllib.parse.parse_qs(parsed.query)
            if path == "/api/session":
                self.send_json({"user": user["sub"], "sid": user["sid"], "role": user["role"], "expiresAt": user["exp"], 'csrfToken': APP.tokens.csrf(user)})
            elif path == "/api/documents" or path.startswith("/api/documents/"):
                self.document_request(path, params, user)
            else:
                self.send_error_json(HTTPStatus.NOT_FOUND, "Nicht gefunden")
            return
        if path.startswith("/admin/api/"):
            user = self.require_admin()
            if user is None:
                return
            path = path[len("/admin"):]
            params = urllib.parse.parse_qs(parsed.query)
            try:
                if path == "/api/session":
                    self.send_json({"user": user["sub"], "expiresAt": user["exp"]})
                elif path == "/api/documents/status":
                    conn = documents.connect()
                    try:
                        documents.ensure_schema(conn)
                        self.send_json(documents.worker_snapshot(conn))
                    finally:
                        conn.close()
                elif path == "/api/overview":
                    self.send_json(APP.overview())
                elif path == '/api/settings':
                    if CONFIG is None:
                        raise ValueError('Einstellungen nicht verfügbar')
                    self.send_json(CONFIG.public(params.get('section', [''])[0] or None))
                elif path == '/api/settings/groups':
                    self.send_json({'groups': self.domain_groups()})
                elif path == "/api/access":
                    conn = directory.open_db()
                    try:
                        access_control.ensure_schema(conn)
                        users, _ = access_control.read_directory()
                        access_control.cache_users(conn, users)
                        conn.commit()
                        self.send_json(access_control.snapshot(conn, users))
                    finally:
                        conn.close()
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
        legacy = {"/overview", "/access", "/reconciliation", "/storage/data", "/storage/users",
                  "/activity", "/activity/fslogix", "/trash", "/backup", "/report", "/system", "/shares"}
        if path in legacy:
            self.send_response(HTTPStatus.TEMPORARY_REDIRECT)
            self.security_headers()
            self.send_header("Location", "/admin/access" if path == "/shares" else "/admin" + path)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.serve_static(path)

    def manage_agent_tokens(self, path, administrator, *, inventory=False):
        store = APP.agent_tokens if APP else None
        if store is None:
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, 'Tokenverwaltung nicht verfügbar')
            return

        try:
            if inventory:
                self.send_json({'tokens': store.inventory()})
                return

            body = self.read_json_body()
            if path.endswith('/revoke'):
                identifier = body.get('id')
                if not store.revoke(identifier):
                    self.send_error_json(HTTPStatus.NOT_FOUND, 'Token nicht gefunden')
                    return
                log(f'Agent token {identifier} revoked by {administrator["sub"]!r}')
                self.send_json({'ok': True})
                return

            label = body.get('label')
            if not isinstance(label, str) or not 1 <= len(label.strip()) <= 100:
                raise ValueError('Eine Bezeichnung mit 1 bis 100 Zeichen ist erforderlich')

            days = body.get('expiresInDays', 30)
            if type(days) is not int or not 1 <= days <= 365:
                raise ValueError('Die Laufzeit muss zwischen 1 und 365 Tagen liegen')

            usernames = body.get('usernames')
            if not isinstance(usernames, list) or not 1 <= len(usernames) <= 10:
                raise ValueError('Ein bis zehn AD-Benutzernamen sind erforderlich')

            accounts = {}
            for username in usernames:
                sam = agent_api.account_login(username)
                sid = agent_api.resolve_account(sam)
                if sid is None:
                    raise ValueError(f'AD-Benutzer nicht verfügbar: {sam}')
                accounts[sid] = sam

            issued = store.issue(label.strip(), accounts, days, administrator['sub'])
            log(f'Agent token {issued["id"]} issued by {administrator["sub"]!r}')
            self.send_json(issued, HTTPStatus.CREATED)
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
        except (OSError, RuntimeError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
            log(f'Agent token management failed: {exc}')
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, 'Tokenverwaltung nicht verfügbar')

    def agent_request(self, path, query):
        prefix = '/api/agent/v1/'
        if not path.startswith(prefix):
            self.send_error_json(HTTPStatus.NOT_FOUND, 'Agenten-Endpunkt nicht gefunden')
            return

        operation = path[len(prefix) - 1:]
        indexed_file = re.fullmatch(r'/documents/[a-f0-9]{32}(?:/(?:download|preview|content))?', operation)
        if operation not in {'/search', '/list', '/file'} and not indexed_file:
            self.send_error_json(HTTPStatus.NOT_FOUND, 'Agenten-Endpunkt nicht gefunden')
            return

        headers = self.headers.get_all('Authorization', [])
        bearer = re.fullmatch(r'Bearer (\S+)', headers[0], re.ASCII | re.IGNORECASE) if len(headers) == 1 else None
        store = APP.agent_tokens if APP else None
        if not bearer or store is None:
            self.send_error_json(HTTPStatus.UNAUTHORIZED, 'Agenten-Token erforderlich')
            return

        try:
            token = store.authenticate(bearer[1])
            if not token:
                self.send_error_json(HTTPStatus.UNAUTHORIZED, 'Agenten-Token ungültig oder abgelaufen')
                return

            params = urllib.parse.parse_qs(query, keep_blank_values=True, max_num_fields=24, errors='strict')
            if any(len(values) != 1 for values in params.values()):
                raise ValueError('Anfrageparameter dürfen nur einmal vorkommen')

            sam = agent_api.account_login(params.get('username', [''])[0])
            token_id, accounts = token
            sid = agent_api.resolve_account(sam)
            identity = current_identity(sid) if sid in accounts else None
            if identity is None:
                self.send_error_json(HTTPStatus.FORBIDDEN, 'Benutzer ist für diesen Token nicht freigegeben')
                return

            log(f'Agent token {token_id} acting as {identity["sub"]!r}: {operation}')
            if operation == '/search':
                self.document_request('/api/documents', params, identity)
            elif indexed_file:
                self.document_request('/api' + operation, params, identity)
            else:
                self.agent_browse(operation, params, identity)
        except ValueError as exc:
            self.send_error_json(HTTPStatus.BAD_REQUEST, str(exc))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except (OSError, RuntimeError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
            log(f'Agent request failed: {exc}')
            self.send_error_json(HTTPStatus.SERVICE_UNAVAILABLE, 'Agenten-API nicht verfügbar')

    def agent_browse(self, operation, params, identity):
        source = params.get('source', [''])[0]
        relative = params.get('path', [''])[0]
        if len(source) > 300 or len(relative) > 4096:
            raise ValueError('Dateipfad oder Ordnerkennung zu lang')

        conn = documents.connect()
        try:
            documents.ensure_schema(conn)
            if operation == '/file':
                if not source or not relative:
                    raise ValueError('source und path sind für Dateiabrufe erforderlich')
                with documents.download_path(conn, identity, source, relative) as (handle, info):
                    self.send_document_file(handle, info.st_size, 'application/octet-stream',
                                            relative.rsplit('/', 1)[-1], range_support=True)
            elif source:
                after = params.get('after', [''])[0]
                limit = int(params.get('limit', ['100'])[0])
                if not 1 <= limit <= 200 or len(after) > 255:
                    raise ValueError('Ungültiger Seitenzeiger oder Seitenumfang')
                self.send_json(documents.browse_directory(conn, identity, source, relative, after, limit))
            else:
                if relative or 'after' in params:
                    raise ValueError('source ist für Ordnerpfade erforderlich')
                self.send_json({'sources': documents.browse_sources(conn, identity)})
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            self.send_error_json(HTTPStatus.NOT_FOUND, 'Datei oder Ordner nicht verfügbar')
        except OSError as exc:
            if exc.errno != errno.ELOOP:
                raise
            self.send_error_json(HTTPStatus.NOT_FOUND, 'Datei oder Ordner nicht verfügbar')
        finally:
            conn.close()

    def document_request(self, path, params, identity):
        conn = documents.connect()
        try:
            documents.ensure_schema(conn)
            if path == "/api/documents":
                self.send_json(documents.search(conn, identity, params))
                return
            parts = path.split("/")
            if len(parts) not in {4, 5} or not re.fullmatch(r"[a-f0-9]{32}", parts[3]):
                raise FileNotFoundError()
            if len(parts) == 4:
                self.send_json(documents.detail(conn, identity, parts[3]))
                return
            if parts[4] == "download":
                with documents.download(conn, identity, parts[3]) as (handle, row):
                    self.send_document_file(handle, row["size"], "application/octet-stream", row["name"])
            elif parts[4] == "content":
                with documents.download(conn, identity, parts[3]) as (handle, row):
                    if row['extension'] != '.pdf':
                        raise FileNotFoundError()
                    self.send_document_file(handle, row['size'], 'application/pdf', row['name'], range_support=True, disposition='inline')
            elif parts[4] == "preview":
                with documents.preview(conn, identity, parts[3]) as (handle, size):
                    self.send_document_file(handle, size, "image/jpeg")
            else:
                raise FileNotFoundError()
        except FileNotFoundError:
            self.send_error_json(HTTPStatus.NOT_FOUND, "Datei nicht verfügbar")
        except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
            log(f"Document request failed: {exc}")
            self.send_error_json(HTTPStatus.BAD_REQUEST, "Dateien konnten nicht geladen werden")
        finally:
            conn.close()

    def send_document_file(self, handle, size, mime, filename=None, *, range_support=False, disposition='attachment'):
        start, end = 0, size - 1
        ranged = range_support and self.headers.get('Range') is not None
        if ranged:
            value = self.headers.get('Range', '')
            match = re.fullmatch(r'bytes=(\d*)-(\d*)', value) if len(value) <= 128 else None
            valid = bool(match and size > 0 and (match[1] or match[2]))
            if valid:
                if match[1]:
                    start = int(match[1])
                    end = min(size - 1, int(match[2])) if match[2] else size - 1
                else:
                    length = int(match[2])
                    start = max(0, size - length)
                    valid = length > 0
                valid = valid and 0 <= start <= end < size
            if not valid:
                self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                self.security_headers()
                self.send_header('Content-Range', f'bytes */{size}')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        length = max(0, end - start + 1)
        self.send_response(HTTPStatus.PARTIAL_CONTENT if ranged else HTTPStatus.OK)
        self.security_headers()
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(length))
        if range_support:
            self.send_header('Accept-Ranges', 'bytes')
        if ranged:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        if filename:
            encoded = urllib.parse.quote(filename, safe="")
            self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8{chr(39)*2}{encoded}")
        self.end_headers()
        try:
            handle.seek(start)
            while length:
                chunk = handle.read(min(length, 1024 * 1024))
                if not chunk:
                    break
                self.wfile.write(chunk)
                length -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def serve_static(self, path: str) -> None:
        pdf_prefix = '/assets/vendor/pdfjs/6.3.289-app1/'
        if path.startswith(pdf_prefix):
            relative = urllib.parse.unquote(path[len(pdf_prefix):])
            if any(part in {'', '.', '..'} or '\\' in part or '\x00' in part for part in relative.split('/')):
                self.send_error_json(HTTPStatus.NOT_FOUND, 'Statische Datei nicht gefunden')
                return
            mime = {'.html':'text/html; charset=utf-8', '.mjs':'text/javascript; charset=utf-8',
                    '.css':'text/css; charset=utf-8', '.svg':'image/svg+xml', '.png':'image/png',
                    '.json':'application/json', '.ftl':'text/plain; charset=utf-8', '.wasm':'application/wasm',
                    '.ttf':'font/ttf', '.woff':'font/woff', '.woff2':'font/woff2'}.get(os.path.splitext(relative)[1], 'application/octet-stream')
            try:
                with documents.open_file(os.path.join(STATIC_ROOT, 'vendor/pdfjs/6.3.289-app1'), relative) as (handle, _):
                    body = handle.read()
            except (ValueError, OSError):
                self.send_error_json(HTTPStatus.NOT_FOUND, 'Statische Datei nicht gefunden')
                return
            self.send_response(HTTPStatus.OK)
            self.security_headers('public, max-age=31536000, immutable', pdf_viewer=relative == 'web/viewer.html')
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        files = {
            '/setup': ('setup.html', 'text/html; charset=utf-8'),
            '/assets/setup.js': ('setup.js', 'text/javascript; charset=utf-8'),
            '/assets/settings.js': ('settings.js', 'text/javascript; charset=utf-8'),
            "/assets/portal.js": ("portal.js", "text/javascript; charset=utf-8"),
            "/assets/pdf-viewer.js": ("pdf-viewer.js", "text/javascript; charset=utf-8"),
            "/assets/pdf-viewer.css": ("pdf-viewer.css", "text/css; charset=utf-8"),
            "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/assets/report.mjs": ("report.mjs", "text/javascript; charset=utf-8"),
            "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/assets/vendor/typst/0.6.0-csp1/typst.mjs": ("vendor/typst/typst.mjs", "text/javascript; charset=utf-8"),
            "/assets/vendor/typst/0.6.0-csp1/compiler.wasm": ("vendor/typst/compiler.wasm", "application/wasm"),
            "/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Regular.otf": ("vendor/typst/LibertinusSerif-Regular.otf", "font/otf"),
            "/assets/vendor/typst/0.6.0-csp1/LibertinusSerif-Semibold.otf": ("vendor/typst/LibertinusSerif-Semibold.otf", "font/otf"),
        }
        if path in files:
            filename, content_type = files[path]
        else:
            filename, content_type = ("index.html" if path == "/admin" or path.startswith("/admin/") else "portal.html"), "text/html; charset=utf-8"
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

    def __init__(self, address, handler, tls_context=None):
        self.tls_context = tls_context
        self.connections = threading.BoundedSemaphore(env_int('WEB_MAX_CONNECTIONS', 64, 4, 512))
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        # Never wait for TLS or a free worker in the accept loop.
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        connection = request
        try:
            if self.tls_context is not None:
                request.settimeout(env_int('WEB_TLS_HANDSHAKE_TIMEOUT_SECONDS', 5, 1, 30))
                connection = self.tls_context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                connection.do_handshake()
            connection.settimeout(env_int('WEB_REQUEST_TIMEOUT_SECONDS', 30, 1, 300))
            super().process_request_thread(connection, client_address)
        except OSError:
            self.shutdown_request(connection)
        finally:
            self.connections.release()


def serve_https() -> None:
    address = os.getenv("WEB_BIND_ADDRESS", "0.0.0.0")
    port = env_int("WEB_BIND_PORT", 8443, 1, 65535)
    cert_mtime = -1.0
    log(f"Serving https://{os.getenv('WEB_HOSTNAME', address)}:{port}")
    while True:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
        server = ReusableHTTPServer((address, port), Handler, tls_context=context)
        server.timeout = 1
        cert_mtime = os.path.getmtime(TLS_CERT_FILE)
        try:
            while os.path.getmtime(TLS_CERT_FILE) == cert_mtime:
                server.handle_request()
        finally:
            server.server_close()
        log("TLS certificate changed; reloading HTTPS listener")


def main() -> int:
    global APP, CONFIG
    CONFIG = configuration.Store()
    os.environ.update(CONFIG.environment())
    if not os.path.isfile(TLS_CERT_FILE) or not os.path.isfile(TLS_KEY_FILE):
        raise RuntimeError("TLS certificate or key is missing")
    APP = App(agent_api.TokenStore(CONFIG.root))
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
