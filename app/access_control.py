"""Admin-managed Data folders and individual user permissions, enforced by Samba Windows ACLs."""

import contextlib
import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import uuid

try:
    from . import reconcile_shares as directory
except ImportError:
    import reconcile_shares as directory

SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+\Z")
READ = 0x1200A9
MODIFY = 0x1201BF  # No DELETE, DELETE_CHILD, WRITE_DAC or WRITE_OWNER.
DELETE = 0x10000
DELETE_CHILD = 0x40
MASKS = {1: READ, 2: MODIFY, 3: MODIFY | DELETE | DELETE_CHILD}
ATTRS = ["objectGUID", "objectSid", "distinguishedName", "sAMAccountName",
         "displayName", "cn", "objectClass", "member", "primaryGroupID"]


class AccessConflict(RuntimeError):
    pass


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def ensure_schema(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS access_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS access_users (
            sid TEXT PRIMARY KEY, sam TEXT NOT NULL, name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS folder_permissions (
            folderId TEXT NOT NULL REFERENCES shares(objectGUID) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind = 'user'),
            principalId TEXT NOT NULL,
            level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3),
            PRIMARY KEY(folderId, kind, principalId)
        );
        CREATE TABLE IF NOT EXISTS access_changes (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL
        );
    """)

    upgrade_individual_permissions(conn)


def upgrade_individual_permissions(conn):
    """Flatten the previous local-group model without changing effective access."""
    schema = conn.execute("SELECT sql FROM sqlite_master WHERE name='folder_permissions'").fetchone()[0]
    if "'group'" not in schema:
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Recheck after obtaining the write lock: another worker may have upgraded.
        schema = conn.execute("SELECT sql FROM sqlite_master WHERE name='folder_permissions'").fetchone()[0]
        if "'group'" not in schema:
            conn.commit()
            return
        if conn.execute("SELECT 1 FROM folder_permissions p LEFT JOIN access_groups g "
                        "ON p.principalId=g.id WHERE p.kind='group' AND g.id IS NULL").fetchone():
            raise RuntimeError("Cannot migrate unresolved stored group permission")
        conn.execute("CREATE TABLE individual_permissions ("
                     "folderId TEXT NOT NULL REFERENCES shares(objectGUID) ON DELETE CASCADE,"
                     "kind TEXT NOT NULL CHECK(kind = 'user'), principalId TEXT NOT NULL,"
                     "level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3),"
                     "PRIMARY KEY(folderId, kind, principalId))")
        # Existing direct assignments take precedence, including explicit level 0.
        conn.execute("INSERT INTO individual_permissions SELECT * FROM folder_permissions WHERE kind='user'")
        conn.execute("INSERT OR IGNORE INTO individual_permissions "
                     "SELECT p.folderId,'user',m.userSid,MAX(p.level) FROM folder_permissions p "
                     "JOIN access_members m ON p.kind='group' AND p.principalId=m.groupId "
                     "GROUP BY p.folderId,m.userSid")
        conn.execute("DROP TABLE folder_permissions")
        conn.execute("ALTER TABLE individual_permissions RENAME TO folder_permissions")
        conn.execute("DROP TABLE access_members")
        conn.execute("DROP TABLE access_groups")
        conn.execute("INSERT INTO access_changes(timestamp,actor,action,details) VALUES(?,?,?,?)",
                     (timestamp(), "system", "migrate-individual-permissions", "{}"))
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def initialized(conn):
    return conn.execute("SELECT 1 FROM access_settings WHERE key='managed'").fetchone() is not None


def read_directory(include_groups=False):
    entries = directory.search_directory_entries(
        "(|(&(objectClass=user)(!(objectClass=computer)))(objectClass=group))"
        if include_groups else "(&(objectClass=user)(!(objectClass=computer)))", ATTRS)
    users, groups = {}, {}
    for entry in entries:
        principal = directory.parse_principal_from_entry(entry)
        if not principal:
            continue
        sid = str(principal.get("objectSid") or "")
        if not SID_RE.fullmatch(sid):
            continue
        row = {"sid": sid, "sam": str(principal.get("samAccountName") or ""),
               "name": directory.ldap_first(entry, "displayName") or
                       str(principal.get("samAccountName") or sid),
               "dn": directory.normalize_dn(directory.entry_dn(entry)),
               "primaryRid": directory.parse_int(directory.ldap_first(entry, "primaryGroupID") or "", -1),
               "members": [directory.normalize_dn(dn) for dn in directory.ldap_values(entry, "member")]}
        if directory.is_group_principal(principal):
            groups[row["dn"]] = row
        elif directory.is_user_principal(principal):
            users[sid] = row
    return users, groups


def cache_users(conn, users):
    conn.executemany("INSERT INTO access_users(sid,sam,name) VALUES(?,?,?) "
                     "ON CONFLICT(sid) DO UPDATE SET sam=excluded.sam,name=excluded.name",
                     [(sid, row["sam"], row["name"]) for sid, row in users.items()])


def migrate(conn):
    """Snapshot existing assignments once; never discover new FS_* groups."""
    ensure_schema(conn)
    if initialized(conn):
        migrate_folder_layout(conn)
        return
    rows = conn.execute("SELECT * FROM shares WHERE isActive=1").fetchall()
    users, groups = read_directory(include_groups=True) if rows else ({}, {})
    by_sam = {g["sam"].casefold(): g for g in groups.values()}
    by_dn = {u["dn"]: sid for sid, u in users.items()}

    def members(group, seen):
        if group["dn"] in seen:
            return set()
        seen = {*seen, group["dn"]}
        rid = directory.sid_rid(group["sid"])
        result = {sid for sid, user in users.items()
                  if user["primaryRid"] == rid and sid.rsplit("-", 1)[0] == group["sid"].rsplit("-", 1)[0]}
        for dn in group["members"]:
            if dn in groups:
                result.update(members(groups[dn], seen))
            elif dn in by_dn:
                result.add(by_dn[dn])
            else:
                raise RuntimeError(f"Cannot import unresolved member {dn}; migration will retry")
        return result

    # Resolve all memberships before mutating persistent state.
    imports = []
    for row in rows:
        group = by_sam.get(row["samAccountName"].casefold())
        if group is None:
            raise RuntimeError(f"Cannot import group {row['samAccountName']}; migration will retry")
        imports.append((row, members(group, set())))
    try:
        cache_users(conn, users)
        for row, sids in imports:
            conn.executemany("INSERT INTO folder_permissions VALUES(?,?,?,3)",
                             [(row["objectGUID"], "user", sid) for sid in sorted(sids)])
        # Adopt any existing untracked folder without granting user access.
        root = directory.GROUP_ROOT
        if os.path.isdir(root):
            known = {os.path.abspath(row[0]) for row in conn.execute("SELECT path FROM shares")}
            for entry in os.scandir(root):
                if entry.name != ".trash" and entry.is_dir(follow_symlinks=False) and os.path.abspath(entry.path) not in known:
                    create_folder_record(conn, entry.name, entry.path)
        conn.execute("INSERT INTO access_settings VALUES('managed','1')")
        conn.execute("UPDATE shares SET aclSignature=''")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    migrate_folder_layout(conn)


def rename_without_overwrite(source, destination):
    """Atomically move a directory on Linux, refusing any existing destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise RuntimeError("Atomic no-overwrite folder migration is unavailable")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # AT_FDCWD=-100, RENAME_NOREPLACE=1. Never fall back to copy/remove or replace.
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), source, None, destination)


def legacy_folder_path(row, source):
    """Only accept the old /data/groups/<objectGUID> layout, never arbitrary paths."""
    base = os.path.dirname(os.path.abspath(directory.GROUP_ROOT))
    try:
        same_guid = uuid.UUID(os.path.basename(source)) == uuid.UUID(row["objectGUID"])
    except (ValueError, AttributeError):
        same_guid = False
    if os.path.dirname(source) != base or not same_guid or os.path.islink(base) or os.path.islink(source):
        raise RuntimeError(f"Unsafe legacy folder path: {source}")


def finish_folder_layout(conn, move):
    row = conn.execute("SELECT * FROM shares WHERE objectGUID=?", (move["folderId"],)).fetchone()
    if row is None or os.path.abspath(row["path"]) != move["source"]:
        raise RuntimeError("Folder layout recovery does not match stored folder; all paths retained")
    source, destination = move["source"], move["destination"]
    legacy_folder_path(row, source)
    root = os.path.abspath(directory.GROUP_ROOT if row["isActive"] else directory.GROUP_ARCHIVE_ROOT)
    if os.path.islink(root) or os.path.dirname(destination) != root or os.path.basename(destination) != valid_name(move["name"]) or os.path.islink(destination):
        raise RuntimeError("Unsafe folder layout recovery destination")
    if os.path.lexists(source):
        if not os.path.isdir(source):
            raise RuntimeError(f"Legacy folder is not a directory: {source}")
        if os.path.lexists(destination):
            raise RuntimeError(f"Folder layout conflict; both paths retained: {source} -> {destination}")
        rename_without_overwrite(source, destination)
    elif not os.path.isdir(destination):
        raise RuntimeError(f"Folder layout recovery cannot find source or destination; no empty folder created: {source} -> {destination}")
    # The move intent was committed before rename. If startup died after rename,
    # the retained destination is adopted here without repeating the AD import.
    try:
        conn.execute("UPDATE shares SET path=?,shareName=?,aclSignature='' WHERE objectGUID=?",
                     (destination, move["name"], row["objectGUID"]))
        conn.execute("INSERT INTO access_changes(timestamp,actor,action,details) VALUES(?,?,?,?)",
                     (timestamp(), "system", "migrate-folder-layout", json.dumps(move)))
        conn.execute("DELETE FROM access_settings WHERE key='pendingFolderLayout'")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    directory.log(f"Migrated legacy folder without overwriting data: {source} -> {destination}")


def migrate_folder_layout(conn):
    """Repair old GUID paths even after the access migration has been committed."""
    pending = conn.execute("SELECT value FROM access_settings WHERE key='pendingFolderLayout'").fetchone()
    if pending:
        finish_folder_layout(conn, json.loads(pending[0]))
    rows = conn.execute("SELECT * FROM shares ORDER BY objectGUID").fetchall()
    legacy = []
    for row in rows:
        root = os.path.abspath(directory.GROUP_ROOT if row["isActive"] else directory.GROUP_ARCHIVE_ROOT)
        if os.path.islink(root):
            raise RuntimeError(f"Unsafe managed folder root: {root}")
        source = os.path.abspath(row["path"])
        if os.path.dirname(source) == root:
            safe_folder_path(row)
            continue
        legacy_folder_path(row, source)
        if not os.path.isdir(source):
            raise RuntimeError(f"Legacy folder is missing; no empty folder created: {source}")
        legacy.append(row)
    # Validate every legacy path before moving any of them.
    for row in legacy:
        root = os.path.abspath(directory.GROUP_ROOT if row["isActive"] else directory.GROUP_ARCHIVE_ROOT)
        os.makedirs(root, exist_ok=True)
        used = {entry.name.casefold() for entry in os.scandir(root)}
        used.update(other["shareName"].casefold() for other in conn.execute("SELECT shareName FROM shares WHERE objectGUID<>?", (row["objectGUID"],)))
        preferred = directory.sanitize_group_folder_name(row["shareName"])
        try:
            valid_name(preferred)
        except ValueError:
            preferred = row["objectGUID"]
        name = directory.choose_group_folder_name(preferred, row["samAccountName"], row["objectGUID"], used)
        move = {"folderId": row["objectGUID"], "source": os.path.abspath(row["path"]),
                "destination": os.path.join(root, name), "name": name}
        conn.execute("INSERT INTO access_settings VALUES('pendingFolderLayout',?)", (json.dumps(move),))
        conn.commit()
        finish_folder_layout(conn, move)


def valid_name(value):
    if not isinstance(value, str):
        raise ValueError("Ein Name ist erforderlich")
    name = value.strip()
    if not name or len(name) > 120 or name in {".", ".."} or name.casefold() == ".trash" or name.endswith((".", " ")) or re.search(r'[\\/:*?"<>|\x00-\x1f\x7f]', name):
        raise ValueError("Ungültiger Name")
    if name.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)]}:
        raise ValueError("Reservierter Name")
    return name


def create_folder_record(conn, name, path):
    folder_id = str(uuid.uuid4())
    conn.execute("INSERT INTO shares(objectGUID,samAccountName,shareName,path,createdAt,lastSeenAt,isActive,aclSignature) VALUES(?,?,?,?,?,?,1,'')",
                 (folder_id, name, name, path, timestamp(), timestamp()))
    return folder_id


def snapshot(conn, users=None):
    user_rows = [dict(row) for row in conn.execute("SELECT * FROM access_users ORDER BY sam COLLATE NOCASE")]
    if users is not None:
        for user in user_rows:
            user["available"] = user["sid"] in users
    folders = []
    for row in conn.execute("SELECT * FROM shares ORDER BY shareName COLLATE NOCASE"):
        folders.append({"id": row["objectGUID"], "name": row["shareName"], "active": bool(row["isActive"]),
                        "permissions": [dict(p) for p in conn.execute("SELECT kind,principalId,level FROM folder_permissions WHERE folderId=? ORDER BY kind,principalId", (row["objectGUID"],))]})
    return {"users": user_rows, "folders": folders,
            "fetchedAt": timestamp(), "initialized": initialized(conn)}


def effective_levels(conn, folder_id):
    return {row["principalId"]: row["level"] for row in conn.execute(
        "SELECT principalId,level FROM folder_permissions WHERE folderId=?", (folder_id,))}


def descriptor(levels, admin_sid, is_dir=True, top_level=False):
    if not SID_RE.fullmatch(admin_sid):
        raise RuntimeError("DOMAIN_ADMINS_SID is required for managed folder ACLs")
    flags = "OICI" if is_dir else ""
    # OWNER RIGHTS suppresses implicit WRITE_DAC for files created by users.
    aces = [f"(A;{flags};RC;;;OW)", f"(A;{flags};FA;;;SY)", f"(A;{flags};FA;;;{admin_sid})"]
    for sid, level in sorted(levels.items()):
        if not SID_RE.fullmatch(sid) or type(level) is not int or level not in range(4):
            raise RuntimeError("Invalid stored folder permission")
        if level:
            mask = MASKS[level]
            if top_level:
                # Only admins can rename/delete a managed top-level folder.
                aces.append(f"(A;;0x{mask & ~DELETE:08x};;;{sid})")
                aces.append(f"(A;OICIIO;0x{mask:08x};;;{sid})")
            else:
                aces.append(f"(A;{flags};0x{mask:08x};;;{sid})")
    return f"O:{admin_sid}G:{admin_sid}D:P" + "".join(aces)


def pack_descriptor(sddl):
    # Samba's own NDR serializer matches the installed server version.
    from samba.dcerpc import security, xattr
    from samba.ndr import ndr_pack
    acl = xattr.NTACL()
    acl.version = 1
    acl.info = security.descriptor.from_sddl(sddl, security.dom_sid(os.environ["DOMAIN_ADMINS_SID"].rsplit("-", 1)[0]))
    return ndr_pack(acl)


def set_acl_fd(fd, blob, is_dir):
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode)):
        raise RuntimeError("Unsupported managed data entry")
    from samba import xattr_tdb
    os.makedirs("/state", exist_ok=True)
    os.fchown(fd, 0, 0)
    xattr_tdb.wrap_setxattr("/state/data-xattrs.tdb", f"/proc/self/fd/{fd}", "security.NTACL", blob)
    os.chmod("/state/data-xattrs.tdb", 0o600)
    # SMB checks Windows ACLs. Local data volumes must stay container-private.
    os.fchmod(fd, 0o777 if is_dir else 0o666)


def set_acl(path, blob, is_dir):
    # Open without following symlinks; set ACLs/mode through the pinned inode.
    flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if is_dir else 0)
    fd = os.open(path, flags)
    try:
        set_acl_fd(fd, blob, is_dir)
    finally:
        os.close(fd)


def prepare_data_restore(conn, relative_path, source_fd):
    parts = relative_path.split("/")
    row = conn.execute("SELECT * FROM shares WHERE shareName=? AND isActive=1", (parts[0],)).fetchone()
    if row is None or len(parts) < 2:
        raise ValueError("Wiederherstellung erfordert einen aktiven verwalteten Datenordner")
    path = safe_folder_path(row)
    admin_sid = os.getenv("DOMAIN_ADMINS_SID", "")
    levels = effective_levels(conn, row["objectGUID"])
    set_acl(path, pack_descriptor(descriptor(levels, admin_sid, top_level=True)), True)
    for name in parts[1:-1]:
        path = os.path.join(path, name)
        set_acl(path, pack_descriptor(descriptor(levels, admin_sid)), True)
    # Replace the retained ACL before the file is visible at its restored path.
    set_acl_fd(source_fd, pack_descriptor(descriptor(levels, admin_sid, False)), False)


def safe_folder_path(row):
    root = os.path.abspath(directory.GROUP_ROOT if row["isActive"] else directory.GROUP_ARCHIVE_ROOT)
    path = os.path.abspath(row["path"])
    if os.path.dirname(path) != root or os.path.islink(path):
        raise RuntimeError(f"Unsafe managed folder path: {path}")
    return path


def recover_pending(conn):
    pending = conn.execute("SELECT value FROM access_settings WHERE key='pendingRepair'").fetchone()
    if pending is None:
        return
    details = json.loads(pending[0])
    if details.get("move"):
        source, destination = details["move"]
        if not os.path.lexists(source) and os.path.lexists(destination):
            os.rename(destination, source)
    created = details.get("create")
    if created and os.path.isdir(created) and not conn.execute("SELECT 1 FROM shares WHERE path=?", (created,)).fetchone():
        # Preserve files from an interrupted creation with admin-only access.
        create_folder_record(conn, os.path.basename(created), created)
    sync_permissions(conn, force=True)
    conn.execute("DELETE FROM access_settings WHERE key='pendingRepair'")
    conn.commit()
    directory.log("Recovered interrupted admin access update")


def sync_permissions(conn, force=False):
    admin_sid = os.getenv("DOMAIN_ADMINS_SID", "")
    root = directory.GROUP_ROOT
    os.makedirs(root, exist_ok=True)
    force = force or not os.path.exists("/state/data-xattrs.tdb")
    # Read/list only at the share root; no inheritance or top-level creation.
    root_sddl = descriptor({}, admin_sid) + "(A;;0x001200a9;;;AU)"
    set_acl(root, pack_descriptor(root_sddl), True)
    for row in conn.execute("SELECT * FROM shares").fetchall():
        path = safe_folder_path(row)
        levels = effective_levels(conn, row["objectGUID"]) if row["isActive"] else {}
        top = descriptor(levels, admin_sid, top_level=True)
        signature = hashlib.sha256(top.encode()).hexdigest()
        os.makedirs(path, exist_ok=True)
        set_acl(path, pack_descriptor(top), True)
        if force or directory.should_repair_data_acls() or row["aclSignature"] != signature:
            blobs = {True: pack_descriptor(descriptor(levels, admin_sid)), False: pack_descriptor(descriptor(levels, admin_sid, False))}
            # Never follow symlinks or cross mount boundaries.
            root_device = os.stat(path, follow_symlinks=False).st_dev
            for current, dirs, files in os.walk(path, followlinks=False):
                for name in list(dirs):
                    child = os.path.join(current, name)
                    if os.path.islink(child) or os.stat(child, follow_symlinks=False).st_dev != root_device:
                        raise RuntimeError(f"Unsupported link or mount in managed folder: {child}")
                    set_acl(child, blobs[True], True)
                for name in files:
                    set_acl(os.path.join(current, name), blobs[False], False)
            conn.execute("UPDATE shares SET aclSignature=? WHERE objectGUID=?", (signature, row["objectGUID"]))


@contextlib.contextmanager
def mutation_lock():
    os.makedirs(os.path.dirname(directory.LOCK_PATH), exist_ok=True)
    with open(directory.LOCK_PATH, "a", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AccessConflict("Freigabenabgleich läuft; bitte erneut versuchen") from exc
        yield


def apply_change(conn, body, actor, users):
    action = body.get("action")
    if not isinstance(action, str) or action not in {"create-folder", "set-permissions", "archive-folder", "restore-folder"}:
        raise ValueError("Unbekannte Verwaltungsaktion")
    if body.get("id") is not None and (not isinstance(body["id"], str) or not body["id"] or len(body["id"]) > 120):
        raise ValueError("Ungültige ID")
    cache_users(conn, users)
    conn.commit()
    recover_pending(conn)
    pending = {}
    if action == "create-folder":
        pending["create"] = os.path.join(directory.GROUP_ROOT, valid_name(body.get("name")))
    elif action in {"archive-folder", "restore-folder"}:
        row = conn.execute("SELECT * FROM shares WHERE objectGUID=?", (body.get("id"),)).fetchone()
        if row is not None:
            target = directory.GROUP_ROOT if action == "restore-folder" else directory.GROUP_ARCHIVE_ROOT
            pending["move"] = [safe_folder_path(row), os.path.join(target, valid_name(row["shareName"]))]
    # Persist recovery intent separately from the policy transaction. A process
    # crash cannot leave partially updated ACLs with an unchanged signature.
    conn.execute("INSERT INTO access_settings VALUES('pendingRepair',?)", (json.dumps(pending),))
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    created_path = None
    moved_paths = None
    acl_started = False
    try:
        if action == "create-folder":
            name = valid_name(body.get("name"))
            if conn.execute("SELECT 1 FROM shares WHERE shareName=? COLLATE NOCASE", (name,)).fetchone():
                raise ValueError("Ordnername ist bereits vergeben")
            path = os.path.join(directory.GROUP_ROOT, name)
            os.mkdir(path, 0o700)
            created_path = path
            create_folder_record(conn, name, path)
        elif action in {"set-permissions", "archive-folder", "restore-folder"}:
            folder_id = body.get("id")
            row = conn.execute("SELECT * FROM shares WHERE objectGUID=?", (folder_id,)).fetchone()
            if row is None:
                raise ValueError("Ordner nicht gefunden")
            if action == "set-permissions":
                rules = body.get("permissions")
                if not isinstance(rules, list):
                    raise ValueError("Berechtigungen müssen eine Liste sein")
                old_users = {r[0] for r in conn.execute("SELECT principalId FROM folder_permissions WHERE folderId=? AND kind='user'", (folder_id,))}
                checked = []
                seen = set()
                for rule in rules:
                    if not isinstance(rule, dict):
                        raise ValueError("Ungültige Berechtigung")
                    kind, principal, level = rule.get("kind"), rule.get("principalId"), rule.get("level")
                    if not isinstance(kind, str) or kind != "user" or not isinstance(principal, str) or type(level) is not int or level not in range(4):
                        raise ValueError("Ungültige Berechtigung")
                    if (kind, principal) in seen:
                        raise ValueError("Doppelte Berechtigung")
                    seen.add((kind, principal))
                    if principal not in users and principal not in old_users:
                        raise ValueError("Unbekannter AD-Benutzer")
                    checked.append((folder_id, kind, principal, level))
                conn.execute("DELETE FROM folder_permissions WHERE folderId=?", (folder_id,))
                conn.executemany("INSERT INTO folder_permissions VALUES(?,?,?,?)", checked)
            else:
                active = action == "restore-folder"
                if bool(row["isActive"]) == active:
                    raise ValueError("Ordner hat diesen Status bereits")
                source = safe_folder_path(row)
                root = directory.GROUP_ROOT if active else directory.GROUP_ARCHIVE_ROOT
                os.makedirs(root, exist_ok=True)
                destination = os.path.join(root, row["shareName"])
                if os.path.lexists(destination):
                    raise AccessConflict("Zielordner existiert bereits")
                os.rename(source, destination)
                moved_paths = (source, destination)
                conn.execute("UPDATE shares SET path=?,isActive=?,aclSignature='' WHERE objectGUID=?", (destination, int(active), folder_id))
        else:
            raise ValueError("Unbekannte Verwaltungsaktion")
        acl_started = True
        sync_permissions(conn)
        conn.execute("DELETE FROM access_settings WHERE key='pendingRepair'")
        conn.execute("INSERT INTO access_changes(timestamp,actor,action,details) VALUES(?,?,?,?)", (timestamp(), actor, action, json.dumps(body, ensure_ascii=False)))
        conn.commit()
    except Exception:
        conn.rollback()
        if moved_paths:
            os.rename(moved_paths[1], moved_paths[0])
        if created_path:
            os.rmdir(created_path)
        # A failed recursive update may have changed some ACLs: restore the old policy.
        try:
            if acl_started:
                sync_permissions(conn, force=True)
            conn.execute("DELETE FROM access_settings WHERE key='pendingRepair'")
            conn.commit()
        except Exception as exc:
            directory.log(f"ERROR: Access rollback repair failed: {exc}")
            conn.execute("UPDATE shares SET aclSignature=''")
            conn.commit()
        raise
    # Existing handles carry cached access masks; disconnect Data clients.
    result = directory.run_command(["smbcontrol", "all", "close-share", "Data"], check=False)
    if result.returncode:
        raise RuntimeError("Berechtigungen gespeichert; SMB-Verbindungen konnten nicht geschlossen werden. Samba neu starten.")
    return snapshot(conn, users)


def report_folders(conn):
    data = snapshot(conn)
    users = {u["sid"]: u for u in data["users"]}
    rows = []
    for folder in data["folders"]:
        if not folder["active"]:
            continue
        levels = effective_levels(conn, folder["id"])
        members = []
        for rule in folder["permissions"]:
            if rule["kind"] == "user" and rule["level"]:
                sid = rule["principalId"]
                members.append({"id": sid, "name": users.get(sid, {}).get("name", sid), "sam": users.get(sid, {}).get("sam", sid), "type": "user", "level": rule["level"], "members": []})
        rows.append({"guid": folder["id"], "name": folder["name"], "sam": folder["name"], "folder": folder["name"], "active": True,
                     "userCount": sum(bool(level) for level in levels.values()), "groupCount": 0, "members": members})
    return {"groups": rows, "fetchedAt": data["fetchedAt"], "truncated": False}
