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
from typing import Dict, List, Optional, Tuple


DB_PATH = "/state/shares.db"
LOCK_PATH = "/state/reconcile.lock"
GROUP_ROOT = "/data/groups"
PRIVATE_ROOT = "/data/private"
PUBLIC_ROOT = "/data/public"
GENERATED_CONF = "/etc/samba/generated/shares.conf"

LDAP_FILTER = "(&(objectClass=group)(sAMAccountName=FileShare_*))"
GROUP_PREFIX = "FileShare_"

REQUIRED_ENV = ["REALM", "WORKGROUP", "DOMAIN"]
ATTR_RE = re.compile(r"^([^:]+)(::?):\s*(.*)$")
SHARE_NAME_INVALID_RE = re.compile(r"[\\/:*?\"<>|;\[\],+=]")


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


def parse_groups_from_ldap_output(output: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, Tuple[str, bool]]] = []
    current: Dict[str, Tuple[str, bool]] = {}

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            if current:
                entries.append(current)
                current = {}
            continue
        if stripped.startswith("#") or stripped.startswith("dn:"):
            continue

        match = ATTR_RE.match(stripped)
        if not match:
            continue

        key, delimiter, value = match.groups()
        current[key] = (value, delimiter == "::")

    if current:
        entries.append(current)

    groups: List[Dict[str, str]] = []
    for entry in entries:
        if "objectGUID" not in entry or "sAMAccountName" not in entry:
            continue

        sam_value, _ = entry["sAMAccountName"]
        sam = sam_value.strip()
        if not sam.startswith(GROUP_PREFIX):
            continue

        share_name = sam[len(GROUP_PREFIX) :]
        if not share_name:
            continue

        guid_value, is_b64 = entry["objectGUID"]
        guid = parse_guid(guid_value.strip(), is_b64)

        groups.append(
            {
                "objectGUID": guid,
                "samAccountName": sam,
                "shareName": share_name,
            }
        )

    deduped: Dict[str, Dict[str, str]] = {}
    for group in groups:
        deduped[group["objectGUID"]] = group

    return list(deduped.values())


def fetch_groups_via_net_ads() -> List[Dict[str, str]]:
    result = run_command(
        ["net", "ads", "search", "-P", LDAP_FILTER, "objectGUID", "sAMAccountName"],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or "net ads search failed"
        )
    return parse_groups_from_ldap_output(result.stdout)


def fetch_groups_via_ldap_bind() -> List[Dict[str, str]]:
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
                LDAP_FILTER,
                "objectGUID",
                "sAMAccountName",
            ]
        )
        return parse_groups_from_ldap_output(result.stdout)
    finally:
        if pw_file and os.path.exists(pw_file):
            os.remove(pw_file)


def fetch_fileshare_groups() -> List[Dict[str, str]]:
    try:
        return fetch_groups_via_net_ads()
    except Exception as net_exc:  # pylint: disable=broad-except
        log(f"net ads search failed, falling back to LDAP bind: {net_exc}")
    return fetch_groups_via_ldap_bind()


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


def reconcile_db(conn: sqlite3.Connection, ad_groups: List[Dict[str, str]]) -> None:
    timestamp = now_utc()
    seen = set()

    for group in ad_groups:
        guid = group["objectGUID"]
        sam = group["samAccountName"]
        share_name = group["shareName"]
        seen.add(guid)

        row = conn.execute(
            "SELECT objectGUID, path FROM shares WHERE objectGUID = ?", (guid,)
        ).fetchone()

        if row is None:
            path = os.path.join(GROUP_ROOT, guid)
            ensure_group_path(path)
            conn.execute(
                """
                INSERT INTO shares (objectGUID, samAccountName, shareName, path, createdAt, lastSeenAt, isActive)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (guid, sam, share_name, path, timestamp, timestamp),
            )
            log(f"Discovered new share group {sam} ({guid})")
            continue

        path = row["path"]
        ensure_group_path(path)
        conn.execute(
            """
            UPDATE shares
            SET samAccountName = ?,
                shareName = ?,
                lastSeenAt = ?,
                isActive = 1
            WHERE objectGUID = ?
            """,
            (sam, share_name, timestamp, guid),
        )

    if seen:
        placeholders = ",".join("?" for _ in seen)
        conn.execute(
            f"UPDATE shares SET isActive = 0, lastSeenAt = ? WHERE isActive = 1 AND objectGUID NOT IN ({placeholders})",
            (timestamp, *seen),
        )
    else:
        conn.execute(
            "UPDATE shares SET isActive = 0, lastSeenAt = ? WHERE isActive = 1",
            (timestamp,),
        )

    conn.commit()


def qualify_group(group_name: str) -> str:
    return f'+"{group_name}"'


def is_valid_share_name(share_name: str) -> bool:
    if not share_name or share_name.casefold() in {"global", "homes", "printers"}:
        return False
    if SHARE_NAME_INVALID_RE.search(share_name):
        return False
    return True


def render_dynamic_shares(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT objectGUID, samAccountName, shareName, path
        FROM shares
        WHERE isActive = 1
        ORDER BY shareName COLLATE NOCASE
        """
    ).fetchall()

    stanzas: List[str] = [
        "# This file is generated by /app/reconcile_shares.py.",
        "# Manual changes will be overwritten.",
        "",
    ]
    used_share_names = set()

    for row in rows:
        share_name = row["shareName"].strip()
        if not share_name:
            continue
        folded_name = share_name.casefold()
        if folded_name in used_share_names:
            log(
                f"Skipping duplicate share name '{share_name}' for objectGUID {row['objectGUID']}"
            )
            continue

        if not is_valid_share_name(share_name):
            log(
                f"Skipping invalid SMB share name '{share_name}' for objectGUID {row['objectGUID']}"
            )
            continue

        used_share_names.add(folded_name)
        valid_users = qualify_group(row["samAccountName"])
        stanzas.extend(
            [
                f"[{share_name}]",
                f"path = {row['path']}",
                "read only = no",
                "browseable = yes",
                "guest ok = no",
                "vfs objects = acl_xattr full_audit",
                "full_audit:prefix = %T|%u|%I|%m|%S",
                "full_audit:success = connect disconnect opendir readdir mkdir rmdir open close read pread write pwrite unlink rename",
                "full_audit:failure = connect opendir readdir mkdir rmdir open read pread write pwrite unlink rename",
                "full_audit:syslog = false",
                f"valid users = {valid_users}",
                "create mask = 0660",
                "directory mask = 2770",
                "inherit permissions = yes",
                "access based share enum = yes",
                "",
            ]
        )

    content = "\n".join(stanzas).rstrip() + "\n"
    os.makedirs(os.path.dirname(GENERATED_CONF), exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=os.path.dirname(GENERATED_CONF), delete=False
    ) as tmp_file:
        tmp_file.write(content)
        temp_path = tmp_file.name

    os.replace(temp_path, GENERATED_CONF)


def reload_samba() -> None:
    result = run_command(["smbcontrol", "all", "reload-config"], check=False)
    if result.returncode != 0:
        log("smbcontrol reload-config failed; will retry on next run")


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


def set_acl(path: str, user_uid: int, admin_gid: Optional[int]) -> None:
    run_command(["setfacl", "-b", path], check=False)
    acl_entries = [f"u:{user_uid}:rwx", f"d:u:{user_uid}:rwx"]
    if admin_gid is not None:
        acl_entries.extend([f"g:{admin_gid}:rwx", f"d:g:{admin_gid}:rwx"])

    result = run_command(
        ["setfacl", "-m", ",".join(acl_entries), path],
        check=False,
    )
    if result.returncode != 0:
        log(
            f"setfacl failed for {path}: {result.stderr.strip() or result.stdout.strip()}"
        )


def set_group_acl(path: str, group_gid: int) -> None:
    acl_entries = [f"g:{group_gid}:rwx", f"d:g:{group_gid}:rwx"]
    result = run_command(["setfacl", "-m", ",".join(acl_entries), path], check=False)
    if result.returncode != 0:
        log(
            f"setfacl failed for {path}: {result.stderr.strip() or result.stdout.strip()}"
        )


def set_group_acl_with_admin(
    path: str, group_gid: int, admin_gid: Optional[int]
) -> None:
    run_command(["setfacl", "-b", path], check=False)
    acl_entries = [f"g:{group_gid}:rwx", f"d:g:{group_gid}:rwx"]
    if admin_gid is not None:
        acl_entries.extend([f"g:{admin_gid}:rwx", f"d:g:{admin_gid}:rwx"])
    result = run_command(["setfacl", "-m", ",".join(acl_entries), path], check=False)
    if result.returncode != 0:
        log(
            f"setfacl failed for {path}: {result.stderr.strip() or result.stdout.strip()}"
        )


def list_domain_users() -> List[str]:
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
        users.append(candidate)
    return sorted(set(users))


def sync_public_directory() -> None:
    workgroup = os.environ["WORKGROUP"]
    public_group = os.getenv("PUBLIC_GROUP", "Domain Users")
    qualified_group = public_group

    os.makedirs(PUBLIC_ROOT, exist_ok=True)
    gid = resolve_group_gid_flexible(workgroup, qualified_group)

    if gid is not None:
        os.chown(PUBLIC_ROOT, 0, gid)
        run_command(["setfacl", "-b", PUBLIC_ROOT], check=False)
        set_group_acl(PUBLIC_ROOT, gid)
    else:
        log(f"Unable to resolve GID for {qualified_group}; public ACLs unchanged")

    os.chmod(PUBLIC_ROOT, 0o2770)


def sync_private_directories() -> None:
    workgroup = os.environ["WORKGROUP"]
    admin_group = os.getenv("DOMAIN_ADMINS_GROUP", "Domain Admins")
    admin_gid = resolve_group_gid_flexible(workgroup, admin_group)

    os.makedirs(PRIVATE_ROOT, exist_ok=True)
    os.chmod(PRIVATE_ROOT, 0o755)

    users = list_domain_users()
    for username in users:
        uid = resolve_user_uid_flexible(workgroup, username)
        if uid is None:
            log(f"Unable to resolve UID for {username}, skipping private folder")
            continue

        user_path = os.path.join(PRIVATE_ROOT, username)
        os.makedirs(user_path, exist_ok=True)
        os.chown(user_path, uid, -1)
        os.chmod(user_path, 0o700)
        set_acl(user_path, uid, admin_gid)


def sync_dynamic_directory_permissions(conn: sqlite3.Connection) -> None:
    workgroup = os.environ["WORKGROUP"]
    admin_group = os.getenv("DOMAIN_ADMINS_GROUP", "Domain Admins")
    admin_gid = resolve_group_gid_flexible(workgroup, admin_group)

    rows = conn.execute(
        "SELECT samAccountName, path FROM shares WHERE isActive = 1"
    ).fetchall()
    for row in rows:
        sam = row["samAccountName"]
        path = row["path"]
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o2770)

        gid = resolve_group_gid_flexible(workgroup, sam)
        if gid is None:
            log(f"Unable to resolve GID for {sam}; leaving existing ACLs")
            continue

        os.chown(path, 0, gid)
        set_group_acl_with_admin(path, gid, admin_gid)


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

        conn = open_db()
        try:
            groups = fetch_fileshare_groups()
            reconcile_db(conn, groups)
            sync_dynamic_directory_permissions(conn)
            render_dynamic_shares(conn)
        finally:
            conn.close()

        sync_public_directory()
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
