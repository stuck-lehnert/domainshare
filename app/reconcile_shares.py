#!/usr/bin/env python3

import base64
import datetime as dt
import fcntl
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

try:
    from .state_db import STATE_DB_PATH, connect_state_db
except ImportError:
    from state_db import STATE_DB_PATH, connect_state_db


DB_PATH = STATE_DB_PATH
LOCK_PATH = "/state/reconcile.lock"
GROUP_ROOT = "/data/groups/data"
GROUP_ARCHIVE_ROOT = "/data/groups/archive"
PRIVATE_ROOT = "/data/private"
FSLOGIX_ROOT = "/data/fslogix"

LDAP_FILTER = "(&(objectClass=group)(sAMAccountName=FS_*))"
GROUP_PREFIXES = ("FS_",)
GROUP_TITLE_ATTRS = ("displayname", "name", "cn")
USER_STATUS_FILTER = "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName=*))"
GROUP_SEARCH_ATTRS = [
    "objectGUID",
    "sAMAccountName",
    "displayName",
    "name",
    "cn",
    "distinguishedName",
    "member",
    "memberOf",
    "objectClass",
]
NESTED_GROUP_SEARCH_ATTRS = [
    "objectGUID",
    "sAMAccountName",
    "distinguishedName",
    "memberOf",
    "objectClass",
]
LDAP_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
SETFACL_ENTRY_CHUNK_SIZE = 40
SETFACL_PATH_CHUNK_SIZE = 100
DATA_ACL_SIGNATURE_VERSION = 1
DATA_ACL_REPAIR_ENV = "REPAIR_DATA_ACLS"
SLOW_COMMAND_LOG_SECONDS = 5.0
AD_COMMAND_TIMEOUT_SECONDS = 120
WINBIND_COMMAND_TIMEOUT_SECONDS = 30
NSS_COMMAND_TIMEOUT_SECONDS = 30
TRUE_ENV_VALUES = {"1", "true", "yes", "on"}

REQUIRED_ENV = ["REALM", "WORKGROUP", "DOMAIN"]
ATTR_RE = re.compile(r"^([^:]+)(::?)\s*(.*)$")
GROUP_FOLDER_INVALID_RE = re.compile(r"[\\/:*?\"<>|]")
PRIVATE_SKIP_EXACT = {
    "krbtgt",
    "administrator",
    "guest",
    "gast",
    "defaultaccount",
    "wdagutilityaccount",
    "fileshare_serviceacc",
    "fileshare_serviceaccount",
}
PRIVATE_SKIP_PREFIXES = ("msol_", "fileshare_service", "aad_")
UAC_ACCOUNTDISABLE = 0x0002
UAC_LOCKOUT = 0x0010
AD_NEVER_EXPIRES_VALUES = {0, 9223372036854775807}
MAX_GROUP_FOLDER_NAME = 120

LdapValue = Tuple[str, bool]
LdapEntry = Dict[str, List[LdapValue]]
Principal = Dict[str, object]
NestedGroupLookup = Callable[[str], Dict[str, Principal]]


@dataclass
class MembershipExpansion:
    group_sams: List[str] = field(default_factory=list)
    unresolved_dns: List[str] = field(default_factory=list)
    cycle_paths: List[List[str]] = field(default_factory=list)


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def log(message: str) -> None:
    print(f"[reconcile] {message}", flush=True)


def ensure_required_env() -> None:
    missing = [key for key in REQUIRED_ENV if not os.getenv(key)]
    if missing:
        raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")


def realm_to_base_dn(realm: str) -> str:
    parts = [part for part in realm.split(".") if part]
    if not parts:
        raise RuntimeError("REALM is invalid and cannot be converted to base DN")
    return ",".join(f"DC={part}" for part in parts)


def parse_guid(raw_value: str, is_b64: bool) -> str:
    if is_b64:
        raw = base64.b64decode(raw_value)
        if len(raw) != 16:
            raise ValueError("objectGUID has invalid binary length")
        return str(uuid.UUID(bytes_le=raw))

    candidate = raw_value.strip().strip("{}")
    return str(uuid.UUID(candidate))


def format_duration(seconds: float) -> str:
    if seconds >= 1:
        return f"{seconds:.1f}s"
    return f"{seconds * 1000:.0f}ms"


def command_text(command: List[str]) -> str:
    return " ".join(command)


def completed_timeout(
    command: List[str], exc: subprocess.TimeoutExpired
) -> subprocess.CompletedProcess:
    stdout = exc.stdout or ""
    stderr = exc.stderr or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    if not stderr:
        stderr = f"Command timed out after {exc.timeout}s"
    return subprocess.CompletedProcess(command, 124, stdout, stderr)


def run_command(
    command: List[str], check: bool = True, timeout: Optional[int] = None
) -> subprocess.CompletedProcess:
    started = time.monotonic()
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        log(
            f"Command timed out after {format_duration(elapsed)}: "
            f"{command_text(command)}"
        )
        result = completed_timeout(command, exc)
        if check:
            raise RuntimeError(
                f"Command timed out ({command_text(command)}): {result.stderr.strip()}"
            ) from exc
        return result

    elapsed = time.monotonic() - started
    if elapsed >= SLOW_COMMAND_LOG_SECONDS:
        log(f"Slow command took {format_duration(elapsed)}: {command_text(command)}")

    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({command_text(command)}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result


def unfold_ldap_lines(output: str) -> List[str]:
    lines: List[str] = []
    for raw_line in output.splitlines():
        if raw_line.startswith(" ") and lines:
            lines[-1] += raw_line[1:]
            continue
        lines.append(raw_line)
    return lines


def parse_ldap_entries(output: str) -> List[LdapEntry]:
    entries: List[LdapEntry] = []
    current: LdapEntry = {}

    for line in unfold_ldap_lines(output):
        stripped = line.strip()
        if not stripped:
            if current:
                entries.append(current)
                current = {}
            continue
        if stripped.startswith("#"):
            continue

        match = ATTR_RE.match(stripped)
        if not match:
            continue

        key, delimiter, value = match.groups()
        current.setdefault(key.lower(), []).append((value, delimiter == "::"))

    if current:
        entries.append(current)

    return entries


def decode_ldap_text(value: str, is_b64: bool) -> str:
    if not is_b64:
        return value.strip()
    try:
        return base64.b64decode(value).decode("utf-8").strip()
    except (ValueError, UnicodeDecodeError):
        return value.strip()


def ldap_values(entry: LdapEntry, attr: str) -> List[str]:
    attr_key = attr.lower()
    values: List[str] = []
    for entry_key, entry_values in entry.items():
        if entry_key != attr_key and not entry_key.startswith(f"{attr_key};"):
            continue
        values.extend(
            decode_ldap_text(value, is_b64) for value, is_b64 in entry_values
        )
    return values


def ldap_first(entry: LdapEntry, attr: str) -> Optional[str]:
    values = ldap_values(entry, attr)
    for value in values:
        if value:
            return value
    return None


def ldap_first_raw(entry: LdapEntry, attr: str) -> Optional[LdapValue]:
    values = entry.get(attr.lower(), [])
    return values[0] if values else None


def derive_share_name(sam_account_name: str) -> Optional[str]:
    for prefix in GROUP_PREFIXES:
        if sam_account_name.startswith(prefix):
            share_name = sam_account_name[len(prefix) :]
            return share_name if share_name else None
    return None


def derive_group_title(entry: LdapEntry) -> Optional[str]:
    for attr in GROUP_TITLE_ATTRS:
        value = ldap_first(entry, attr)
        if value:
            return value
    return None


def entry_dn(entry: LdapEntry) -> str:
    return ldap_first(entry, "distinguishedName") or ldap_first(entry, "dn") or ""


def parse_principal_from_entry(entry: LdapEntry) -> Optional[Principal]:
    dn = entry_dn(entry)
    if not dn:
        return None

    guid = ""
    guid_raw = ldap_first_raw(entry, "objectGUID")
    if guid_raw is not None:
        try:
            guid = parse_guid(guid_raw[0].strip(), guid_raw[1])
        except ValueError:
            guid = ""

    object_classes = {value.lower() for value in ldap_values(entry, "objectClass")}
    return {
        "dn": dn,
        "objectGUID": guid,
        "samAccountName": ldap_first(entry, "sAMAccountName") or "",
        "memberDns": ldap_values(entry, "member"),
        "memberOfDns": ldap_values(entry, "memberOf"),
        "objectClasses": object_classes,
    }


def parse_groups_from_ldap_entries(entries: List[LdapEntry]) -> List[Dict[str, object]]:
    groups: List[Dict[str, object]] = []
    for entry in entries:
        guid_raw = ldap_first_raw(entry, "objectGUID")
        sam = ldap_first(entry, "sAMAccountName")
        if guid_raw is None or not sam:
            continue

        share_name = derive_group_title(entry) or derive_share_name(sam)
        if not share_name:
            continue

        guid = parse_guid(guid_raw[0].strip(), guid_raw[1])
        object_classes = {value.lower() for value in ldap_values(entry, "objectClass")}
        if not object_classes:
            object_classes = {"group"}

        groups.append(
            {
                "objectGUID": guid,
                "samAccountName": sam,
                "shareName": share_name,
                "distinguishedName": entry_dn(entry),
                "memberDns": ldap_values(entry, "member"),
                "memberOfDns": ldap_values(entry, "memberOf"),
                "objectClasses": object_classes,
            }
        )

    deduped: Dict[str, Dict[str, object]] = {}
    for group in groups:
        deduped[str(group["objectGUID"])] = group

    return list(deduped.values())


def parse_groups_from_ldap_output(output: str) -> List[Dict[str, object]]:
    return parse_groups_from_ldap_entries(parse_ldap_entries(output))


def sanitize_group_folder_name(raw_name: str) -> str:
    candidate = GROUP_FOLDER_INVALID_RE.sub("_", raw_name.strip())
    candidate = candidate.strip().rstrip(".")
    candidate = re.sub(r"\s+", " ", candidate)
    if not candidate:
        return ""
    return candidate[:MAX_GROUP_FOLDER_NAME]


def with_suffix_limited(base_name: str, suffix: str) -> str:
    limit = MAX_GROUP_FOLDER_NAME - len(suffix)
    if limit <= 0:
        return suffix[-MAX_GROUP_FOLDER_NAME:]
    trimmed = base_name[:limit].rstrip(" ._")
    if not trimmed:
        trimmed = "group"
    return f"{trimmed}{suffix}"


def choose_group_folder_name(
    preferred_name: str,
    sam_account_name: str,
    guid: str,
    used_names: set,
    existing_name: str = "",
) -> str:
    base_name = sanitize_group_folder_name(preferred_name)
    if not base_name:
        base_name = sanitize_group_folder_name(
            derive_share_name(sam_account_name) or ""
        )
    if not base_name:
        base_name = sanitize_group_folder_name(sam_account_name)
    if not base_name:
        base_name = f"group_{guid[:8]}"

    if existing_name:
        existing_folded = existing_name.casefold()
        if existing_folded not in used_names:
            sanitized_existing = sanitize_group_folder_name(existing_name)
            if sanitized_existing.casefold() == base_name.casefold():
                used_names.add(existing_folded)
                return existing_name

    candidate = base_name
    index = 0
    while candidate.casefold() in used_names:
        index += 1
        suffix = f"_{guid[:8]}" if index == 1 else f"_{guid[:8]}_{index}"
        candidate = with_suffix_limited(base_name, suffix)

    used_names.add(candidate.casefold())
    return candidate


def next_available_path(path: str) -> str:
    if not os.path.exists(path):
        return path

    index = 1
    while True:
        candidate = f"{path}_{index}"
        if not os.path.exists(candidate):
            return candidate
        index += 1


def chunked(values: List[str], size: int) -> Iterable[List[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def escape_ldap_filter_value(value: str) -> str:
    replacements = {
        "\\": "\\5c",
        "*": "\\2a",
        "(": "\\28",
        ")": "\\29",
        "\x00": "\\00",
    }
    return "".join(replacements.get(char, char) for char in value)


def build_distinguished_name_filter(dns: List[str]) -> str:
    clauses = [f"(distinguishedName={escape_ldap_filter_value(dn)})" for dn in dns]
    if len(clauses) == 1:
        return clauses[0]
    return f"(|{''.join(clauses)})"


def search_entries_via_net_ads(
    filter_expr: str, attributes: List[str]
) -> List[LdapEntry]:
    result = run_command(
        ["net", "ads", "search", "-P", filter_expr, *attributes],
        check=False,
        timeout=AD_COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or "net ads search failed"
        )
    return parse_ldap_entries(result.stdout)


def search_entries_via_ldap_bind(
    filter_expr: str, attributes: List[str]
) -> List[LdapEntry]:
    realm = os.environ["REALM"]
    join_user = os.getenv("JOIN_USER", "")
    join_password = os.getenv("JOIN_PASSWORD", "")
    if not join_user or not join_password:
        raise RuntimeError(
            "JOIN_USER/JOIN_PASSWORD are required for LDAP credential fallback"
        )

    bind_dn = f"{join_user}@{realm}"
    ldap_uri = os.getenv("LDAP_URI", f"ldaps://{os.environ['DOMAIN']}")
    base_dn = os.getenv("LDAP_BASE_DN", realm_to_base_dn(realm))

    pw_file = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            pw_file = handle.name
            handle.write(join_password)
            handle.write("\n")
        os.chmod(pw_file, 0o600)

        result = run_command(
            [
                "ldapsearch",
                "-LLL",
                "-x",
                "-H",
                ldap_uri,
                "-D",
                bind_dn,
                "-y",
                pw_file,
                "-b",
                base_dn,
                filter_expr,
                *attributes,
            ],
            timeout=AD_COMMAND_TIMEOUT_SECONDS,
        )
        return parse_ldap_entries(result.stdout)
    finally:
        if pw_file and os.path.exists(pw_file):
            os.remove(pw_file)


def search_directory_entries(filter_expr: str, attributes: List[str]) -> List[LdapEntry]:
    try:
        return search_entries_via_net_ads(filter_expr, attributes)
    except Exception as net_exc:  # pylint: disable=broad-except
        log(f"net ads search failed, falling back to LDAP bind: {net_exc}")
    return search_entries_via_ldap_bind(filter_expr, attributes)


def fetch_fileshare_groups() -> List[Dict[str, object]]:
    entries = search_directory_entries(LDAP_FILTER, GROUP_SEARCH_ATTRS)
    return parse_groups_from_ldap_entries(entries)


def normalize_dn(dn: str) -> str:
    return dn.strip().casefold()


def group_to_principal(group: Dict[str, object]) -> Principal:
    object_classes = group.get("objectClasses") or {"group"}
    return {
        "dn": str(group.get("distinguishedName") or ""),
        "objectGUID": str(group.get("objectGUID") or ""),
        "samAccountName": str(group.get("samAccountName") or ""),
        "memberDns": [str(dn) for dn in group.get("memberDns", []) if str(dn).strip()],
        "memberOfDns": [
            str(dn) for dn in group.get("memberOfDns", []) if str(dn).strip()
        ],
        "objectClasses": {str(value).lower() for value in object_classes},
    }


def principal_display_name(principal: Principal) -> str:
    sam = str(principal.get("samAccountName") or "").strip()
    if sam:
        return sam
    return str(principal.get("dn") or "<unknown>")


def is_group_principal(principal: Principal) -> bool:
    return "group" in principal.get("objectClasses", set())


def is_computer_principal(principal: Principal) -> bool:
    return "computer" in principal.get("objectClasses", set())


def is_user_principal(principal: Principal) -> bool:
    return "user" in principal.get("objectClasses", set()) and not is_computer_principal(
        principal
    )


def build_nested_groups_filter(root_dn: str) -> str:
    escaped_root_dn = escape_ldap_filter_value(root_dn)
    return (
        "(&(objectClass=group)"
        f"(memberOf:{LDAP_MATCHING_RULE_IN_CHAIN}:={escaped_root_dn}))"
    )


def lookup_nested_group_principals(root_dn: str) -> Dict[str, Principal]:
    if not root_dn.strip():
        return {}

    entries = search_directory_entries(
        build_nested_groups_filter(root_dn), NESTED_GROUP_SEARCH_ATTRS
    )
    principals: Dict[str, Principal] = {}
    for entry in entries:
        principal = parse_principal_from_entry(entry)
        if principal is None or not is_group_principal(principal):
            continue
        key = normalize_dn(str(principal.get("dn") or ""))
        if key:
            principals[key] = principal
    return principals


def find_group_cycle_paths(principals: Dict[str, Principal]) -> List[List[str]]:
    graph: Dict[str, List[str]] = {}
    for key, principal in principals.items():
        parent_keys = []
        for parent_dn in principal.get("memberOfDns", []):
            parent_key = normalize_dn(str(parent_dn))
            if parent_key in principals:
                parent_keys.append(parent_key)
        graph[key] = sorted(set(parent_keys))

    cycle_paths: List[List[str]] = []
    cycle_keys_seen: Set[str] = set()
    visited: Set[str] = set()
    visiting: Set[str] = set()
    stack: List[str] = []

    def add_cycle(cycle: List[str]) -> None:
        labels = [principal_display_name(principals[key]) for key in cycle]
        cycle_key = " -> ".join(labels).casefold()
        if cycle_key not in cycle_keys_seen:
            cycle_keys_seen.add(cycle_key)
            cycle_paths.append(labels)

    def visit(key: str) -> None:
        visiting.add(key)
        stack.append(key)
        for parent_key in graph.get(key, []):
            if parent_key in visiting:
                start_index = stack.index(parent_key)
                add_cycle(stack[start_index:] + [parent_key])
                continue
            if parent_key not in visited:
                visit(parent_key)
        stack.pop()
        visiting.discard(key)
        visited.add(key)

    for key in sorted(principals):
        if key not in visited:
            visit(key)

    return cycle_paths


def expand_group_membership(
    root_group: Dict[str, object],
    nested_group_cache: Optional[Dict[str, Dict[str, Principal]]] = None,
    lookup_func: NestedGroupLookup = lookup_nested_group_principals,
) -> MembershipExpansion:
    root_principal = group_to_principal(root_group)
    root_dn = str(root_principal.get("dn") or "")
    root_key = normalize_dn(root_dn)

    expansion = MembershipExpansion()
    if not root_key:
        expansion.unresolved_dns.append("<missing root group distinguishedName>")
        return expansion

    cache = nested_group_cache if nested_group_cache is not None else {}
    if root_key in cache:
        nested_groups = cache[root_key]
    else:
        nested_groups = lookup_func(root_dn)
        cache[root_key] = nested_groups

    all_groups = {root_key: root_principal}
    all_groups.update(nested_groups)

    seen_sams: Set[str] = set()
    for key, principal in sorted(
        nested_groups.items(),
        key=lambda item: principal_display_name(item[1]).casefold(),
    ):
        if key == root_key:
            continue
        sam = str(principal.get("samAccountName") or "").strip()
        if not sam:
            dn = str(principal.get("dn") or key)
            if dn not in expansion.unresolved_dns:
                expansion.unresolved_dns.append(dn)
            continue
        sam_key = sam.casefold()
        if sam_key not in seen_sams:
            seen_sams.add(sam_key)
            expansion.group_sams.append(sam)

    expansion.cycle_paths = find_group_cycle_paths(all_groups)
    return expansion


def windows_filetime_now() -> int:
    unix_epoch_seconds = int(dt.datetime.now(dt.timezone.utc).timestamp())
    return (unix_epoch_seconds + 11644473600) * 10000000


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


def fetch_non_login_users() -> set:
    command = [
        "net",
        "ads",
        "search",
        "-P",
        USER_STATUS_FILTER,
        "sAMAccountName",
        "userAccountControl",
        "accountExpires",
        "lockoutTime",
    ]
    result = run_command(command, check=False, timeout=AD_COMMAND_TIMEOUT_SECONDS)
    if result.returncode != 0:
        log(
            "net ads search for account status failed; private folder filtering will use static skip rules only"
        )
        return set()

    blocked = set()
    now_filetime = windows_filetime_now()

    for entry in parse_ldap_entries(result.stdout):
        username = (ldap_first(entry, "sAMAccountName") or "").lower()
        if not username:
            continue

        uac = parse_int(ldap_first(entry, "userAccountControl") or "0", 0)
        account_expires = parse_int(ldap_first(entry, "accountExpires") or "0", 0)
        lockout_time = parse_int(ldap_first(entry, "lockoutTime") or "0", 0)

        is_disabled = bool(uac & UAC_ACCOUNTDISABLE)
        is_locked = bool(uac & UAC_LOCKOUT) or lockout_time > 0
        is_expired = (
            account_expires not in AD_NEVER_EXPIRES_VALUES
            and account_expires <= now_filetime
        )

        if is_disabled or is_locked or is_expired:
            blocked.add(username)

    return blocked


def ensure_share_db_schema(conn: sqlite3.Connection) -> None:
    columns = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(shares)").fetchall()
    }
    if "aclSignature" not in columns:
        conn.execute(
            "ALTER TABLE shares ADD COLUMN aclSignature TEXT NOT NULL DEFAULT ''"
        )


def open_db() -> sqlite3.Connection:
    conn = connect_state_db(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shares (
            objectGUID TEXT PRIMARY KEY,
            samAccountName TEXT NOT NULL,
            shareName TEXT NOT NULL,
            path TEXT NOT NULL,
            createdAt TIMESTAMP NOT NULL,
            lastSeenAt TIMESTAMP NOT NULL,
            isActive INTEGER NOT NULL,
            aclSignature TEXT NOT NULL DEFAULT ''
        )
        """
    )
    ensure_share_db_schema(conn)
    conn.commit()
    return conn


def ensure_group_path(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o2770)


def reconcile_db(conn: sqlite3.Connection, ad_groups: List[Dict[str, object]]) -> None:
    timestamp = now_utc()
    seen = set()

    os.makedirs(GROUP_ROOT, exist_ok=True)
    os.makedirs(GROUP_ARCHIVE_ROOT, exist_ok=True)

    rows = conn.execute(
        "SELECT objectGUID, samAccountName, shareName, path, isActive FROM shares"
    ).fetchall()
    existing_by_guid = {row["objectGUID"]: row for row in rows}
    used_names = set()

    for group in ad_groups:
        guid = group["objectGUID"]
        sam = group["samAccountName"]
        row = existing_by_guid.get(guid)
        existing_name = ""
        if (
            row is not None
            and row["isActive"]
            and row["path"].startswith(f"{GROUP_ROOT}/")
        ):
            existing_name = os.path.basename(row["path"])

        folder_name = choose_group_folder_name(
            group["shareName"], sam, guid, used_names, existing_name
        )
        path = os.path.join(GROUP_ROOT, folder_name)
        seen.add(guid)

        if row is None:
            ensure_group_path(path)
            conn.execute(
                """
                INSERT INTO shares (objectGUID, samAccountName, shareName, path, createdAt, lastSeenAt, isActive)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (guid, sam, folder_name, path, timestamp, timestamp),
            )
            log(f"Discovered new data folder group {sam} ({guid})")
            continue

        existing_path = row["path"]
        reset_acl_signature = not row["isActive"] or existing_path != path
        if existing_path != path:
            if os.path.exists(existing_path):
                final_path = next_available_path(path)
                os.rename(existing_path, final_path)
                path = final_path
            else:
                ensure_group_path(path)

        ensure_group_path(path)
        conn.execute(
            """
            UPDATE shares
            SET samAccountName = ?,
                shareName = ?,
                path = ?,
                lastSeenAt = ?,
                isActive = 1,
                aclSignature = CASE WHEN ? THEN '' ELSE aclSignature END
            WHERE objectGUID = ?
            """,
            (sam, folder_name, path, timestamp, 1 if reset_acl_signature else 0, guid),
        )

    active_rows = conn.execute(
        "SELECT objectGUID, samAccountName, shareName, path FROM shares WHERE isActive = 1"
    ).fetchall()
    for row in active_rows:
        guid = row["objectGUID"]
        if guid in seen:
            continue

        old_path = row["path"]
        archive_name = choose_group_folder_name(
            row["shareName"],
            row["samAccountName"],
            guid,
            set(),
        )
        archive_path = os.path.join(GROUP_ARCHIVE_ROOT, archive_name)
        if os.path.exists(old_path):
            final_archive_path = next_available_path(archive_path)
            os.rename(old_path, final_archive_path)
            archive_path = final_archive_path

        conn.execute(
            """
            UPDATE shares
            SET isActive = 0,
                path = ?,
                lastSeenAt = ?,
                aclSignature = ''
            WHERE objectGUID = ?
            """,
            (archive_path, timestamp, guid),
        )

    conn.commit()


def reload_samba() -> None:
    result = run_command(["smbcontrol", "all", "reload-config"], check=False)
    if result.returncode != 0:
        log("smbcontrol reload-config failed; will retry on next run")


def refresh_winbind_cache() -> None:
    result = run_command(
        ["net", "cache", "flush"],
        check=False,
        timeout=WINBIND_COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        log("net cache flush failed; group membership updates may be delayed")


def resolve_user_uid(qualified_user: str) -> Optional[int]:
    result = run_command(
        ["getent", "passwd", qualified_user],
        check=False,
        timeout=NSS_COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    fields = result.stdout.strip().split(":")
    if len(fields) < 3:
        return None
    try:
        return int(fields[2])
    except ValueError:
        return None


def resolve_group_gid(qualified_group: str) -> Optional[int]:
    result = run_command(
        ["getent", "group", qualified_group],
        check=False,
        timeout=NSS_COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    fields = result.stdout.strip().split(":")
    if len(fields) < 3:
        return None
    try:
        return int(fields[2])
    except ValueError:
        return None


def resolve_user_uid_flexible(workgroup: str, username: str) -> Optional[int]:
    candidates: List[str] = []
    if "\\" in username:
        candidates.append(username)
        candidates.append(username.split("\\", 1)[1])
    else:
        candidates.append(f"{workgroup}\\{username}")
        candidates.append(username)

    for candidate in candidates:
        uid = resolve_user_uid(candidate)
        if uid is not None:
            return uid
    return None


def resolve_group_gid_flexible(workgroup: str, group_name: str) -> Optional[int]:
    candidates: List[str] = []
    if "\\" in group_name:
        candidates.append(group_name)
        candidates.append(group_name.split("\\", 1)[1])
    else:
        candidates.append(f"{workgroup}\\{group_name}")
        candidates.append(group_name)

    for candidate in candidates:
        gid = resolve_group_gid(candidate)
        if gid is not None:
            return gid
    return None


def resolve_gid_from_sid(sid: str) -> Optional[int]:
    if not sid:
        return None
    result = run_command(
        ["wbinfo", "--sid-to-gid", sid],
        check=False,
        timeout=WINBIND_COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def resolve_group_gids_for_acl(
    workgroup: str,
    group_names: List[str],
    resolver: Callable[[str, str], Optional[int]] = resolve_group_gid_flexible,
) -> Tuple[List[int], List[str]]:
    gids: List[int] = []
    unresolved: List[str] = []
    seen_gids: Set[int] = set()
    seen_names: Set[str] = set()

    for group_name in group_names:
        name = group_name.strip()
        name_key = name.casefold()
        if not name or name_key in seen_names:
            continue
        seen_names.add(name_key)

        gid = resolver(workgroup, name)
        if gid is None:
            unresolved.append(name)
            continue
        if gid not in seen_gids:
            seen_gids.add(gid)
            gids.append(gid)

    return gids, unresolved


def group_acl_gids(
    owner_group_gid: int, acl_group_gids: List[int], admin_gid: Optional[int]
) -> List[int]:
    acl_gids: List[int] = []
    seen_gids: Set[int] = set()
    for gid in [owner_group_gid, *acl_group_gids]:
        if gid not in seen_gids:
            seen_gids.add(gid)
            acl_gids.append(gid)
    if admin_gid is not None and admin_gid not in seen_gids:
        acl_gids.append(admin_gid)
    return acl_gids


def group_acl_entries(
    owner_group_gid: int,
    acl_group_gids: List[int],
    admin_gid: Optional[int],
    is_dir: bool,
) -> List[str]:
    group_perms = "rwx" if is_dir else "rw-"
    acl_gids = group_acl_gids(owner_group_gid, acl_group_gids, admin_gid)

    acl_entries = [f"g:{gid}:{group_perms}" for gid in acl_gids]
    acl_entries.append(f"m:{group_perms}")

    if is_dir:
        acl_entries.extend(f"d:g:{gid}:rwx" for gid in acl_gids)
        acl_entries.append("d:m:rwx")

    return acl_entries


def apply_setfacl_to_paths(paths: List[str], args: List[str]) -> bool:
    if not paths:
        return True

    ok = True
    for path_chunk in chunked(paths, SETFACL_PATH_CHUNK_SIZE):
        result = run_command(["setfacl", *args, *path_chunk], check=False)
        if result.returncode != 0:
            ok = False
            log(
                f"setfacl failed for {len(path_chunk)} path(s) starting at "
                f"{path_chunk[0]}: {result.stderr.strip() or result.stdout.strip()}"
            )
    return ok


def clear_setfacl_entries(paths: List[str]) -> bool:
    return apply_setfacl_to_paths(paths, ["-b"])


def apply_setfacl_entries_to_paths(paths: List[str], acl_entries: List[str]) -> bool:
    ok = True
    for acl_chunk in chunked(acl_entries, SETFACL_ENTRY_CHUNK_SIZE):
        if not apply_setfacl_to_paths(paths, ["-m", ",".join(acl_chunk)]):
            ok = False
    return ok


def apply_setfacl_entries(path: str, acl_entries: List[str]) -> bool:
    return apply_setfacl_entries_to_paths([path], acl_entries)


def set_group_ownership_and_mode(
    paths: List[str], owner_group_gid: int, is_dir: bool
) -> int:
    mode = 0o2770 if is_dir else 0o660
    changed = 0
    for path in paths:
        if os.path.islink(path):
            continue
        os.chown(path, 0, owner_group_gid)
        os.chmod(path, mode)
        changed += 1
    return changed


def apply_group_permissions(
    path: str,
    owner_group_gid: int,
    acl_group_gids: List[int],
    admin_gid: Optional[int],
    is_dir: bool,
) -> bool:
    if os.path.islink(path):
        return True

    set_group_ownership_and_mode([path], owner_group_gid, is_dir)
    ok = clear_setfacl_entries([path])
    if not apply_setfacl_entries(
        path, group_acl_entries(owner_group_gid, acl_group_gids, admin_gid, is_dir)
    ):
        ok = False
    return ok


def apply_private_permissions(
    path: str, user_uid: int, user_gid: int, admin_gid: Optional[int], is_dir: bool
) -> None:
    if os.path.islink(path):
        return

    mode = 0o700 if is_dir else 0o600
    user_perms = "rwx" if is_dir else "rw-"

    os.chown(path, user_uid, user_gid)
    os.chmod(path, mode)
    run_command(["setfacl", "-b", path], check=False)

    acl_entries = [f"u:{user_uid}:{user_perms}"]
    if admin_gid is not None:
        acl_entries.append(f"g:{admin_gid}:{user_perms}")

    if is_dir:
        acl_entries.append(f"d:u:{user_uid}:rwx")
        if admin_gid is not None:
            acl_entries.append(f"d:g:{admin_gid}:rwx")

    result = run_command(["setfacl", "-m", ",".join(acl_entries), path], check=False)
    if result.returncode != 0:
        log(
            f"setfacl failed for {path}: {result.stderr.strip() or result.stdout.strip()}"
        )


def collect_group_tree_paths(root_path: str) -> Tuple[List[str], List[str]]:
    dir_paths = [] if os.path.islink(root_path) else [root_path]
    file_paths: List[str] = []

    for current_root, dirnames, filenames in os.walk(root_path):
        for dirname in dirnames:
            path = os.path.join(current_root, dirname)
            if not os.path.islink(path):
                dir_paths.append(path)
        for filename in filenames:
            path = os.path.join(current_root, filename)
            if not os.path.islink(path):
                file_paths.append(path)

    return dir_paths, file_paths


def enforce_group_tree_permissions(
    root_path: str,
    owner_group_gid: int,
    acl_group_gids: List[int],
    admin_gid: Optional[int],
) -> Tuple[int, int, bool]:
    dir_paths, file_paths = collect_group_tree_paths(root_path)

    set_group_ownership_and_mode(dir_paths, owner_group_gid, is_dir=True)
    set_group_ownership_and_mode(file_paths, owner_group_gid, is_dir=False)

    ok = clear_setfacl_entries([*dir_paths, *file_paths])
    if not apply_setfacl_entries_to_paths(
        dir_paths, group_acl_entries(owner_group_gid, acl_group_gids, admin_gid, True)
    ):
        ok = False
    if not apply_setfacl_entries_to_paths(
        file_paths, group_acl_entries(owner_group_gid, acl_group_gids, admin_gid, False)
    ):
        ok = False

    return len(dir_paths), len(file_paths), ok


def resolve_user_primary_gid(uid: int) -> Optional[int]:
    result = run_command(
        ["getent", "passwd", str(uid)],
        check=False,
        timeout=NSS_COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    fields = result.stdout.strip().split(":")
    if len(fields) < 4:
        return None
    try:
        return int(fields[3])
    except ValueError:
        return None


def enforce_private_tree_permissions(
    root_path: str, user_uid: int, user_gid: int, admin_gid: Optional[int]
) -> None:
    apply_private_permissions(root_path, user_uid, user_gid, admin_gid, is_dir=True)
    for current_root, dirnames, filenames in os.walk(root_path):
        for dirname in dirnames:
            apply_private_permissions(
                os.path.join(current_root, dirname),
                user_uid,
                user_gid,
                admin_gid,
                is_dir=True,
            )
        for filename in filenames:
            apply_private_permissions(
                os.path.join(current_root, filename),
                user_uid,
                user_gid,
                admin_gid,
                is_dir=False,
            )


def list_domain_users(non_login_users: set) -> List[str]:
    result = run_command(
        ["wbinfo", "-u"], check=False, timeout=WINBIND_COMMAND_TIMEOUT_SECONDS
    )
    if result.returncode != 0:
        log("wbinfo -u failed; skipping private directory sync")
        return []

    users = []
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if "\\" in candidate:
            candidate = candidate.split("\\", 1)[1]
        if not candidate or candidate.endswith("$"):
            continue
        if should_skip_private_user(candidate):
            continue
        if candidate.lower() in non_login_users:
            continue
        users.append(candidate)
    return sorted(set(users))


def should_skip_private_user(username: str) -> bool:
    normalized = username.strip().lower()
    if not normalized:
        return True
    if normalized in PRIVATE_SKIP_EXACT:
        return True
    if any(normalized.startswith(prefix) for prefix in PRIVATE_SKIP_PREFIXES):
        return True

    extra_skip_users = {
        value.strip().lower()
        for value in os.getenv("PRIVATE_SKIP_USERS", "").split(",")
        if value.strip()
    }
    if normalized in extra_skip_users:
        return True

    extra_skip_prefixes = [
        value.strip().lower()
        for value in os.getenv("PRIVATE_SKIP_PREFIXES", "").split(",")
        if value.strip()
    ]
    if any(normalized.startswith(prefix) for prefix in extra_skip_prefixes):
        return True

    return False


def sync_fslogix_directory() -> None:
    workgroup = os.environ["WORKGROUP"]
    fslogix_group = os.getenv("FSLOGIX_GROUP", "")
    fslogix_group_sid = os.getenv("FSLOGIX_GROUP_SID", "")
    qualified_group = fslogix_group

    os.makedirs(FSLOGIX_ROOT, exist_ok=True)

    gid = None
    if qualified_group:
        gid = resolve_group_gid_flexible(workgroup, qualified_group)
    if gid is None and fslogix_group_sid:
        gid = resolve_gid_from_sid(fslogix_group_sid)

    if gid is None:
        group_display = qualified_group or fslogix_group_sid or "<unset>"
        log(f"Unable to resolve GID for {group_display}; fslogix ACLs unchanged")
        return

    admin_group = os.getenv("DOMAIN_ADMINS_GROUP", "")
    admin_gid = None
    if admin_group:
        admin_gid = resolve_group_gid_flexible(workgroup, admin_group)
    if admin_gid is None:
        admin_gid = resolve_gid_from_sid(os.getenv("DOMAIN_ADMINS_SID", ""))

    os.chown(FSLOGIX_ROOT, 0, gid)
    os.chmod(FSLOGIX_ROOT, 0o3770)
    run_command(["setfacl", "-b", FSLOGIX_ROOT], check=False)

    acl_entries = [f"g:{gid}:rwx", f"d:g:{gid}:rwx"]
    if admin_gid is not None and admin_gid != gid:
        acl_entries.append(f"g:{admin_gid}:rwx")
        acl_entries.append(f"d:g:{admin_gid}:rwx")

    result = run_command(
        ["setfacl", "-m", ",".join(acl_entries), FSLOGIX_ROOT], check=False
    )
    if result.returncode != 0:
        log(
            "setfacl failed for fslogix root: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def sync_private_directories() -> None:
    workgroup = os.environ["WORKGROUP"]
    admin_group = os.getenv("DOMAIN_ADMINS_GROUP", "")
    admin_gid = None
    if admin_group:
        admin_gid = resolve_group_gid_flexible(workgroup, admin_group)
    if admin_gid is None:
        admin_gid = resolve_gid_from_sid(os.getenv("DOMAIN_ADMINS_SID", ""))

    os.makedirs(PRIVATE_ROOT, exist_ok=True)
    os.chown(PRIVATE_ROOT, 0, 0)
    run_command(["setfacl", "-b", PRIVATE_ROOT], check=False)
    os.chmod(PRIVATE_ROOT, 0o555)

    non_login_users = fetch_non_login_users()
    users = list_domain_users(non_login_users)
    for username in users:
        uid = resolve_user_uid_flexible(workgroup, username)
        if uid is None:
            log(f"Unable to resolve UID for {username}, skipping private folder")
            continue

        user_gid = resolve_user_primary_gid(uid)
        if user_gid is None:
            log(
                f"Unable to resolve primary GID for {username}, skipping private folder"
            )
            continue

        user_path = os.path.join(PRIVATE_ROOT, username)
        os.makedirs(user_path, exist_ok=True)
        enforce_private_tree_permissions(user_path, uid, user_gid, admin_gid)


def format_dn_list(dns: List[str], limit: int = 3) -> str:
    shown = dns[:limit]
    suffix = "" if len(dns) <= limit else f", ... +{len(dns) - limit} more"
    return ", ".join(shown) + suffix


def should_repair_data_acls() -> bool:
    return os.getenv(DATA_ACL_REPAIR_ENV, "").strip().lower() in TRUE_ENV_VALUES


def build_data_acl_signature(
    owner_group_gid: int, acl_group_gids: List[int], admin_gid: Optional[int]
) -> str:
    payload = {
        "version": DATA_ACL_SIGNATURE_VERSION,
        "ownerGroupGid": owner_group_gid,
        "aclGroupGids": sorted(group_acl_gids(owner_group_gid, acl_group_gids, admin_gid)),
        "adminGid": admin_gid,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def update_data_acl_signature(
    conn: sqlite3.Connection, object_guid: str, acl_signature: str
) -> None:
    conn.execute(
        "UPDATE shares SET aclSignature = ? WHERE objectGUID = ?",
        (acl_signature, object_guid),
    )


def sync_dynamic_directory_permissions(
    conn: sqlite3.Connection, ad_groups: List[Dict[str, object]]
) -> None:
    workgroup = os.environ["WORKGROUP"]
    admin_group = os.getenv("DOMAIN_ADMINS_GROUP", "")
    admin_gid = None
    if admin_group:
        admin_gid = resolve_group_gid_flexible(workgroup, admin_group)
    if admin_gid is None:
        admin_gid = resolve_gid_from_sid(os.getenv("DOMAIN_ADMINS_SID", ""))

    ad_groups_by_guid = {str(group["objectGUID"]): group for group in ad_groups}
    nested_group_cache: Dict[str, Dict[str, Principal]] = {}
    force_recursive_repair = should_repair_data_acls()

    rows = conn.execute(
        "SELECT objectGUID, samAccountName, path, aclSignature FROM shares WHERE isActive = 1"
    ).fetchall()
    log(f"Syncing permissions for {len(rows)} active data folder group(s)")
    if force_recursive_repair:
        log(f"Data ACL recursive repair is forced by {DATA_ACL_REPAIR_ENV}")

    for row in rows:
        share_started = time.monotonic()
        guid = row["objectGUID"]
        sam = row["samAccountName"]
        path = row["path"]
        ad_group = ad_groups_by_guid.get(guid)
        if ad_group is None:
            log(f"No AD data available for {sam}; leaving existing ACLs")
            continue

        log(f"Syncing data folder {sam}")
        expand_started = time.monotonic()
        try:
            expansion = expand_group_membership(ad_group, nested_group_cache)
        except Exception as exc:  # pylint: disable=broad-except
            log(
                f"Unable to expand nested members for {sam}: "
                f"{exc}; leaving existing ACLs"
            )
            continue
        expand_elapsed = time.monotonic() - expand_started

        for cycle_path in expansion.cycle_paths:
            log(f"Detected nested group cycle for {sam}: {' -> '.join(cycle_path)}")

        if expansion.unresolved_dns:
            log(
                f"Unable to resolve nested group(s) for {sam}: "
                f"{format_dn_list(expansion.unresolved_dns)}; leaving existing ACLs"
            )
            continue

        acl_group_names = [sam, *expansion.group_sams]
        gid_started = time.monotonic()
        acl_group_gids, unresolved_groups = resolve_group_gids_for_acl(
            workgroup, acl_group_names
        )
        gid_elapsed = time.monotonic() - gid_started
        if unresolved_groups or not acl_group_gids:
            missing = ", ".join(unresolved_groups) or sam
            log(f"Unable to resolve GID(s) for {sam}: {missing}; leaving existing ACLs")
            continue

        owner_group_gid = acl_group_gids[0]
        acl_signature = build_data_acl_signature(
            owner_group_gid, acl_group_gids, admin_gid
        )
        stored_acl_signature = row["aclSignature"] or ""
        if force_recursive_repair:
            sync_mode = "forced-repair"
        elif stored_acl_signature != acl_signature:
            sync_mode = "changed-acl-repair"
        else:
            sync_mode = "root-only"

        os.makedirs(path, exist_ok=True)
        acl_started = time.monotonic()
        if sync_mode == "root-only":
            dir_count = 1
            file_count = 0
            acl_ok = apply_group_permissions(
                path, owner_group_gid, acl_group_gids, admin_gid, is_dir=True
            )
        else:
            dir_count, file_count, acl_ok = enforce_group_tree_permissions(
                path, owner_group_gid, acl_group_gids, admin_gid
            )
            if acl_ok:
                update_data_acl_signature(conn, guid, acl_signature)
            else:
                log(
                    f"ACL repair for {sam} did not complete; "
                    "stored ACL signature left unchanged"
                )
        acl_elapsed = time.monotonic() - acl_started

        if sync_mode == "root-only" and not acl_ok:
            log(f"Root ACL refresh for {sam} did not complete")

        total_elapsed = time.monotonic() - share_started
        status = "ok" if acl_ok else "incomplete"
        log(
            f"Synced {sam}: mode={sync_mode}, status={status}, "
            f"nested_groups={len(expansion.group_sams)}, "
            f"acl_groups={len(acl_group_gids)}, dirs={dir_count}, files={file_count}, "
            f"expand={format_duration(expand_elapsed)}, "
            f"gids={format_duration(gid_elapsed)}, "
            f"acl={format_duration(acl_elapsed)}, "
            f"total={format_duration(total_elapsed)}"
        )

    conn.commit()
    os.makedirs(GROUP_ROOT, exist_ok=True)
    os.chown(GROUP_ROOT, 0, 0)
    run_command(["setfacl", "-b", GROUP_ROOT], check=False)
    os.chmod(GROUP_ROOT, 0o555)


def with_lock() -> bool:
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    lock_file = open(LOCK_PATH, "w", encoding="utf-8")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("Another reconciliation instance is running; skipping this cycle")
        lock_file.close()
        return False

    try:
        ensure_required_env()
        os.makedirs(GROUP_ROOT, exist_ok=True)
        os.makedirs(GROUP_ARCHIVE_ROOT, exist_ok=True)

        reconcile_started = time.monotonic()
        log("Refreshing winbind cache")
        phase_started = time.monotonic()
        refresh_winbind_cache()
        log(
            f"Refreshed winbind cache in "
            f"{format_duration(time.monotonic() - phase_started)}"
        )

        conn = open_db()
        try:
            phase_started = time.monotonic()
            groups = fetch_fileshare_groups()
            log(
                f"Discovered {len(groups)} data folder group(s) from AD "
                f"in {format_duration(time.monotonic() - phase_started)}"
            )

            log("Reconciling data folder DB")
            phase_started = time.monotonic()
            reconcile_db(conn, groups)
            log(
                f"Reconciled data folder DB in "
                f"{format_duration(time.monotonic() - phase_started)}"
            )

            log("Syncing data folder permissions")
            phase_started = time.monotonic()
            sync_dynamic_directory_permissions(conn, groups)
            log(
                f"Synced data folder permissions in "
                f"{format_duration(time.monotonic() - phase_started)}"
            )
        finally:
            conn.close()

        log("Syncing FSLogix root")
        phase_started = time.monotonic()
        sync_fslogix_directory()
        log(
            f"Synced FSLogix root in "
            f"{format_duration(time.monotonic() - phase_started)}"
        )

        log("Syncing private directories")
        phase_started = time.monotonic()
        sync_private_directories()
        log(
            f"Synced private directories in "
            f"{format_duration(time.monotonic() - phase_started)}"
        )

        log("Reloading Samba config")
        phase_started = time.monotonic()
        reload_samba()
        log(
            f"Reloaded Samba config in "
            f"{format_duration(time.monotonic() - phase_started)}"
        )
        log(
            f"Reconciliation completed in "
            f"{format_duration(time.monotonic() - reconcile_started)}"
        )
        return True
    finally:
        lock_file.close()


def main() -> int:
    try:
        ok = with_lock()
        return 0 if ok else 0
    except Exception as exc:  # pylint: disable=broad-except
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
