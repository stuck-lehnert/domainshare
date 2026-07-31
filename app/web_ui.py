#!/usr/bin/env python3
"""Read-only HTTPS administration UI for the AD-integrated file server."""

import base64
import datetime as dt
import gzip
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
from typing import Dict, Iterable, List, Optional, Tuple

try:
    from app import reconcile_shares as directory
except ImportError:  # Container execution uses /app as the import root.
    import reconcile_shares as directory


STATE_ROOT = os.getenv("WEB_STATE_DIR", "/state/web")
AUDIT_ROOT = os.getenv("AUDIT_ARCHIVE_DIR", "/state/audit")
STATIC_ROOT = os.getenv("WEB_STATIC_DIR", "/app/web")
SHARE_DB = os.getenv("SHARE_DB_PATH", "/state/shares.db")
BACKUP_STATUS_FILE = os.getenv("BACKUP_STATUS_FILE", "/state/backup-status.json")
BACKUP_LOG_FILE = os.getenv("BACKUP_LOG_FILE", "/var/log/backup.log")
TLS_CERT_FILE = os.getenv("WEB_TLS_CERT_FILE", "/state/tls/web.crt")
TLS_KEY_FILE = os.getenv("WEB_TLS_KEY_FILE", "/state/tls/web.key")
USAGE_CACHE_FILE = os.path.join(STATE_ROOT, "usage.json")
JWT_COOKIE = "adfs_session"
JWT_ISSUER = "ad-file-server-web"
JWT_AUDIENCE = "domain-admins"
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SID_RE = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
LOGIN_LIMIT: Dict[str, deque] = {}
LOGIN_LIMIT_LOCK = threading.Lock()


def log(message: str) -> None:
    print(f"[web] {message}", flush=True)


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(os.getenv(name, str(default)))))
    except ValueError:
        return default


def atomic_json(path: str, value: object) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp = f"{path}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(value, handle, separators=(",", ":"), sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


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
        try:
            if not entry.is_dir(follow_symlinks=False):
                continue
            rows.append({"name": entry.name, "bytes": path_size(entry.path)})
        except OSError:
            continue
    return rows


class UsageScanner:
    def __init__(self):
        self.interval = env_int("WEB_USAGE_SCAN_INTERVAL_SECONDS", 900, 60, 86400)
        self.lock = threading.Lock()
        self.data = read_json(USAGE_CACHE_FILE, {})
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
        atomic_json(USAGE_CACHE_FILE, value)
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
        "objectGUID", "distinguishedName", "sAMAccountName", "displayName", "cn",
        "objectClass", "member",
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

        folder_map = {}
        try:
            conn = sqlite3.connect(f"file:{SHARE_DB}?mode=ro", uri=True)
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
                    for child in directory.ldap_values(entry, "member")
                ]
            return node

        group_rows = []
        for root in sorted(roots, key=lambda item: str(item["shareName"]).casefold()):
            members = [make_node(str(dn), set()) for dn in root.get("memberDns", [])]
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
            "truncated": bool(pending),
        }


def iter_audit_file(path: str) -> Iterable[Dict[str, object]]:
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        yield value
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def iter_audit_file_reverse(path: str) -> Iterable[Dict[str, object]]:
    if path.endswith(".gz"):
        yield from reversed(list(iter_audit_file(path)))
        return
    try:
        with open(path, "rb") as handle:
            position = handle.seek(0, os.SEEK_END)
            remainder = b""
            while position > 0:
                size = min(1024 * 1024, position)
                position -= size
                handle.seek(position)
                parts = (handle.read(size) + remainder).split(b"\n")
                remainder = parts[0]
                for line in reversed(parts[1:]):
                    if not line:
                        continue
                    try:
                        value = json.loads(line.decode("utf-8", errors="replace"))
                        if isinstance(value, dict):
                            yield value
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
            if remainder:
                try:
                    value = json.loads(remainder.decode("utf-8", errors="replace"))
                    if isinstance(value, dict):
                        yield value
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
    except OSError:
        return


def date_range(start: dt.date, end: dt.date):
    day = start
    while day <= end:
        yield day.isoformat()
        day += dt.timedelta(days=1)


def query_audit(params: Dict[str, List[str]]) -> Dict[str, object]:
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
    limit = min(500, max(1, int(params.get("limit", ["100"])[0])))
    offset = max(0, int(params.get("cursor", ["0"])[0]))
    filters = {
        key: params.get(key, [""])[0].casefold().strip()
        for key in ("user", "share", "operation", "action", "path", "result")
    }
    page = []
    matched = 0
    facets = {"users": set(), "shares": set(), "operations": set(), "actions": set()}
    for day in reversed(list(date_range(start, end))):
        candidates = [os.path.join(AUDIT_ROOT, f"{day}.jsonl"), os.path.join(AUDIT_ROOT, f"{day}.jsonl.gz")]
        for path in candidates:
            if not os.path.isfile(path):
                continue
            for event in iter_audit_file_reverse(path):
                facets["users"].add(str(event.get("user", "")))
                facets["shares"].add(str(event.get("share", "")))
                facets["operations"].add(str(event.get("operation", "")))
                facets["actions"].add(str(event.get("action", "")))
                failed_filter = filters["result"] == "fail"
                if failed_filter and bool(event.get("success", False)):
                    continue
                if (
                    filters["result"]
                    and not failed_filter
                    and filters["result"]
                    not in str(event.get("result", "")).casefold()
                ):
                    continue
                if any(
                    value and value not in str(event.get(key, "")).casefold()
                    for key, value in filters.items()
                    if key != "result"
                ):
                    continue
                if matched >= offset and len(page) < limit:
                    page.append(event)
                matched += 1
    page.sort(key=lambda event: str(event.get("timestamp", "")), reverse=True)
    next_cursor = offset + limit if offset + limit < matched else None
    return {
        "events": page,
        "nextCursor": next_cursor,
        "matched": matched,
        "facets": {key: sorted(value, key=str.casefold) for key, value in facets.items()},
    }


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


def backup_payload() -> Dict[str, object]:
    value = read_json(BACKUP_STATUS_FILE, {})
    value["enabled"] = bool(os.getenv("BACKUP_DESTINATION", "").strip())
    value["scheduledHour"] = env_int("BACKUP_START_HOUR", 2, 0, 23)
    value["log"] = tail_lines(BACKUP_LOG_FILE, 100)
    return value


def share_count() -> int:
    try:
        conn = sqlite3.connect(f"file:{SHARE_DB}?mode=ro", uri=True)
        try:
            return int(conn.execute("SELECT count(*) FROM shares WHERE isActive = 1").fetchone()[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return 0


def audit_archive_summary() -> Dict[str, object]:
    files = []
    total_bytes = 0
    try:
        names = os.listdir(AUDIT_ROOT)
    except OSError:
        names = []
    for name in names:
        if re.match(r"^\d{4}-\d{2}-\d{2}\.jsonl(?:\.gz)?$", name):
            path = os.path.join(AUDIT_ROOT, name)
            try:
                total_bytes += os.path.getsize(path)
                files.append(name)
            except OSError:
                continue
    return {"days": len(files), "bytes": total_bytes, "oldest": min(files)[:10] if files else None, "newest": max(files)[:10] if files else None}


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
        self.usage = UsageScanner()
        self.directory = DirectoryCache()
        threading.Thread(target=self.usage.run, name="usage-scanner", daemon=True).start()

    def overview(self) -> Dict[str, object]:
        usage = self.usage.snapshot()
        recent = query_audit({"limit": ["12"]})
        return {"usage": usage, "activeGroups": share_count(), "recentEvents": recent["events"], "eventCount": recent["matched"], "backup": backup_payload(), "audit": audit_archive_summary()}

    def system(self) -> Dict[str, object]:
        checks = {}
        for name, command in {"domainTrust": ["wbinfo", "-t"], "sambaConfig": ["testparm", "-s"]}.items():
            try:
                result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                checks[name] = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                checks[name] = False
        return {"hostname": os.getenv("WEB_HOSTNAME", ""), "checks": checks, "tls": tls_summary(), "audit": audit_archive_summary(), "usage": self.usage.snapshot(), "serverTime": now_utc().isoformat(timespec="seconds")}


APP: Optional[App] = None


class Handler(BaseHTTPRequestHandler):
    server_version = "ADFileServerUI/1"

    def log_message(self, fmt: str, *args) -> None:
        log(f"{self.client_address[0]} {fmt % args}")

    def security_headers(self) -> None:
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")

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
                elif path == "/api/backup":
                    self.send_json(backup_payload())
                elif path == "/api/system":
                    self.send_json(APP.system())
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
            "/assets/styles.css": ("styles.css", "text/css; charset=utf-8"),
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
        self.security_headers()
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
    os.makedirs(STATE_ROOT, mode=0o750, exist_ok=True)
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
