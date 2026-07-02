#!/usr/bin/env python3

import base64
import datetime as dt
import fcntl
import grp
import os
import pwd
import re
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple


DB_PATH = "/state/shares.db"
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
    "objectClass",
]
PRINCIPAL_SEARCH_ATTRS = [
    "objectGUID",
    "sAMAccountName",
    "distinguishedName",
    "member",
    "objectClass",
]
LDAP_DN_LOOKUP_BATCH_SIZE = 25
SETFACL_ENTRY_CHUNK_SIZE = 40

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
PrincipalLookup = Callable[[List[str]], Dict[str, Principal]]


@dataclass
class MembershipExpansion:
    group_sams: List[str] = field(default_factory=list)
    terminal_user_count: int = 0
    unresolved_dns: List[str] = field(default_factory=list)
    ignored_dns: List[str] = field(default_factory=list)
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


def run_command(command: List[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(command, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({' '.join(command)}): {result.stderr.strip() or result.stdout.strip()}"
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
            ]
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


def lookup_principals_by_dns(dns: List[str]) -> Dict[str, Principal]:
    unique_dns: List[str] = []
    seen_dns: Set[str] = set()
    for dn in dns:
        key = normalize_dn(dn)
        if not key or key in seen_dns:
            continue
        seen_dns.add(key)
        unique_dns.append(dn)

    principals: Dict[str, Principal] = {}
    for dn_chunk in chunked(unique_dns, LDAP_DN_LOOKUP_BATCH_SIZE):
        entries = search_directory_entries(
            build_distinguished_name_filter(dn_chunk), PRINCIPAL_SEARCH_ATTRS
        )
        for entry in entries:
            principal = parse_principal_from_entry(entry)
            if principal is None:
                continue
            key = normalize_dn(str(principal.get("dn") or ""))
            if key:
                principals[key] = principal

    return principals


def load_principals_for_dns(
    dns: List[str], cache: Dict[str, Principal], lookup_func: PrincipalLookup
) -> None:
    missing_dns: List[str] = []
    seen_dns: Set[str] = set()
    for dn in dns:
        key = normalize_dn(dn)
        if not key or key in cache or key in seen_dns:
            continue
        seen_dns.add(key)
        missing_dns.append(dn)

    if not missing_dns:
        return

    for lookup_key, principal in lookup_func(missing_dns).items():
        principal_key = normalize_dn(str(principal.get("dn") or lookup_key))
        if principal_key:
            cache[principal_key] = principal


def expand_group_membership(
    root_group: Dict[str, object],
    principal_cache: Optional[Dict[str, Principal]] = None,
    lookup_func: PrincipalLookup = lookup_principals_by_dns,
) -> MembershipExpansion:
    cache = principal_cache if principal_cache is not None else {}
    root_principal = group_to_principal(root_group)
    root_key = normalize_dn(str(root_principal.get("dn") or ""))
    if root_key:
        cache[root_key] = root_principal

    expansion = MembershipExpansion()
    group_sams_seen: Set[str] = set()
    unresolved_seen: Set[str] = set()
    ignored_seen: Set[str] = set()
    user_dns_seen: Set[str] = set()
    cycle_paths_seen: Set[str] = set()
    visiting: Set[str] = set()
    visited: Set[str] = set()

    def add_unresolved(dn: str) -> None:
        key = normalize_dn(dn)
        if key and key not in unresolved_seen:
            unresolved_seen.add(key)
            expansion.unresolved_dns.append(dn)

    def add_ignored(dn: str) -> None:
        key = normalize_dn(dn)
        if key and key not in ignored_seen:
            ignored_seen.add(key)
            expansion.ignored_dns.append(dn)

    def add_cycle(path: List[str]) -> None:
        key = " -> ".join(path).casefold()
        if key not in cycle_paths_seen:
            cycle_paths_seen.add(key)
            expansion.cycle_paths.append(path)

    def visit_group(principal: Principal, path: List[str]) -> None:
        current_key = normalize_dn(str(principal.get("dn") or ""))
        if current_key:
            visiting.add(current_key)

        member_dns = [
            str(dn) for dn in principal.get("memberDns", []) if str(dn).strip()
        ]
        load_principals_for_dns(member_dns, cache, lookup_func)

        for member_dn in member_dns:
            member_key = normalize_dn(member_dn)
            if not member_key:
                continue

            member = cache.get(member_key)
            if member is None:
                add_unresolved(member_dn)
                continue

            member_label = principal_display_name(member)
            if member_key in visiting:
                add_cycle(path + [member_label])
                continue

            if is_group_principal(member):
                member_sam = str(member.get("samAccountName") or "").strip()
                if not member_sam:
                    add_unresolved(str(member.get("dn") or member_dn))
                else:
                    sam_key = member_sam.casefold()
                    if sam_key not in group_sams_seen:
                        group_sams_seen.add(sam_key)
                        expansion.group_sams.append(member_sam)

                if member_key not in visited:
                    visit_group(member, path + [member_label])
                continue

            if is_computer_principal(member):
                add_ignored(str(member.get("dn") or member_dn))
                continue

            if is_user_principal(member):
                if member_key not in user_dns_seen:
                    user_dns_seen.add(member_key)
                    expansion.terminal_user_count += 1
                continue

            add_ignored(str(member.get("dn") or member_dn))

        if current_key:
            visiting.discard(current_key)
            visited.add(current_key)

    visit_group(root_principal, [principal_display_name(root_principal)])
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
    result = run_command(command, check=False)
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


def open_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shares (
            objectGUID TEXT PRIMARY KEY,
            samAccountName TEXT NOT NULL,
            shareName TEXT NOT NULL,
            path TEXT NOT NULL,
            createdAt TIMESTAMP NOT NULL,
            lastSeenAt TIMESTAMP NOT NULL,
            isActive INTEGER NOT NULL
        )
        """
    )
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
                isActive = 1
            WHERE objectGUID = ?
            """,
            (sam, folder_name, path, timestamp, guid),
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
                lastSeenAt = ?
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
    result = run_command(["net", "cache", "flush"], check=False)
    if result.returncode != 0:
        log("net cache flush failed; group membership updates may be delayed")


def resolve_user_uid(qualified_user: str) -> Optional[int]:
    try:
        return pwd.getpwnam(qualified_user).pw_uid
    except KeyError:
        return None


def resolve_group_gid(qualified_group: str) -> Optional[int]:
    try:
        return grp.getgrnam(qualified_group).gr_gid
    except KeyError:
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
    result = run_command(["wbinfo", "--sid-to-gid", sid], check=False)
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


def apply_setfacl_entries(path: str, acl_entries: List[str]) -> None:
    for acl_chunk in chunked(acl_entries, SETFACL_ENTRY_CHUNK_SIZE):
        result = run_command(["setfacl", "-m", ",".join(acl_chunk), path], check=False)
        if result.returncode != 0:
            log(
                f"setfacl failed for {path}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
            return


def apply_group_permissions(
    path: str,
    owner_group_gid: int,
    acl_group_gids: List[int],
    admin_gid: Optional[int],
    is_dir: bool,
) -> None:
    if os.path.islink(path):
        return

    mode = 0o2770 if is_dir else 0o660
    group_perms = "rwx" if is_dir else "rw-"
    acl_gids: List[int] = []
    seen_gids: Set[int] = set()
    for gid in [owner_group_gid, *acl_group_gids]:
        if gid not in seen_gids:
            seen_gids.add(gid)
            acl_gids.append(gid)
    if admin_gid is not None and admin_gid not in seen_gids:
        acl_gids.append(admin_gid)

    os.chown(path, 0, owner_group_gid)
    os.chmod(path, mode)
    run_command(["setfacl", "-b", path], check=False)

    acl_entries = [f"g:{gid}:{group_perms}" for gid in acl_gids]
    acl_entries.append(f"m:{group_perms}")

    if is_dir:
        acl_entries.extend(f"d:g:{gid}:rwx" for gid in acl_gids)
        acl_entries.append("d:m:rwx")

    apply_setfacl_entries(path, acl_entries)


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


def enforce_group_tree_permissions(
    root_path: str,
    owner_group_gid: int,
    acl_group_gids: List[int],
    admin_gid: Optional[int],
) -> None:
    apply_group_permissions(
        root_path, owner_group_gid, acl_group_gids, admin_gid, is_dir=True
    )
    for current_root, dirnames, filenames in os.walk(root_path):
        for dirname in dirnames:
            apply_group_permissions(
                os.path.join(current_root, dirname),
                owner_group_gid,
                acl_group_gids,
                admin_gid,
                is_dir=True,
            )
        for filename in filenames:
            apply_group_permissions(
                os.path.join(current_root, filename),
                owner_group_gid,
                acl_group_gids,
                admin_gid,
                is_dir=False,
            )


def resolve_user_primary_gid(uid: int) -> Optional[int]:
    try:
        return pwd.getpwuid(uid).pw_gid
    except KeyError:
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
    result = run_command(["wbinfo", "-u"], check=False)
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
    principal_cache: Dict[str, Principal] = {}

    rows = conn.execute(
        "SELECT objectGUID, samAccountName, path FROM shares WHERE isActive = 1"
    ).fetchall()
    for row in rows:
        guid = row["objectGUID"]
        sam = row["samAccountName"]
        path = row["path"]
        ad_group = ad_groups_by_guid.get(guid)
        if ad_group is None:
            log(f"No AD data available for {sam}; leaving existing ACLs")
            continue

        try:
            expansion = expand_group_membership(ad_group, principal_cache)
        except Exception as exc:  # pylint: disable=broad-except
            log(
                f"Unable to expand nested members for {sam}: "
                f"{exc}; leaving existing ACLs"
            )
            continue

        for cycle_path in expansion.cycle_paths:
            log(f"Detected nested group cycle for {sam}: {' -> '.join(cycle_path)}")

        if expansion.ignored_dns:
            log(
                f"Ignoring computer/unsupported nested member(s) for {sam}: "
                f"{format_dn_list(expansion.ignored_dns)}"
            )

        if expansion.unresolved_dns:
            log(
                f"Unable to resolve nested member(s) for {sam}: "
                f"{format_dn_list(expansion.unresolved_dns)}; leaving existing ACLs"
            )
            continue

        acl_group_names = [sam, *expansion.group_sams]
        acl_group_gids, unresolved_groups = resolve_group_gids_for_acl(
            workgroup, acl_group_names
        )
        if unresolved_groups:
            log(
                f"Unable to resolve GID(s) for {sam}: "
                f"{', '.join(unresolved_groups)}; leaving existing ACLs"
            )
            continue

        owner_group_gid = acl_group_gids[0]
        if expansion.group_sams or expansion.cycle_paths:
            log(
                f"Expanded {sam}: {len(expansion.group_sams)} nested group(s), "
                f"{expansion.terminal_user_count} terminal user(s)"
            )

        os.makedirs(path, exist_ok=True)
        enforce_group_tree_permissions(path, owner_group_gid, acl_group_gids, admin_gid)

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

        conn = open_db()
        try:
            groups = fetch_fileshare_groups()
            log(f"Discovered {len(groups)} data folder group(s) from AD")
            reconcile_db(conn, groups)
            sync_dynamic_directory_permissions(conn, groups)
        finally:
            conn.close()

        sync_fslogix_directory()
        sync_private_directories()
        reload_samba()
        log("Reconciliation completed")
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
