"""Expiring, user-scoped credentials for the read-only agent API."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

try:
    from . import reconcile_shares as directory
    from .account_policy import is_excluded_user
except ImportError:
    import reconcile_shares as directory
    from account_policy import is_excluded_user


DATABASE_NAME = 'agent-tokens.db'
TOKEN_RE = re.compile(r'dsat_[A-Za-z0-9_-]{43}')
ID_RE = re.compile(r'[a-f0-9]{24}')
SID_RE = re.compile(r'S-1-(?:[0-9]+-)*[0-9]+')
ACCOUNT_DISABLED = 0x02
ACCOUNT_LOCKED = 0x10


def account_login(username):
    """Accept only sAMAccountName in the configured domain, never infer a user."""
    if not isinstance(username, str) or len(username) > 256 or not username.strip():
        raise ValueError('Benutzername ist erforderlich')

    workgroup = os.environ['WORKGROUP']
    name = username.strip()
    if '\\' in name:
        domain_name, name = name.split('\\', 1)
        if domain_name.casefold() != workgroup.casefold():
            raise ValueError('Benutzername gehört nicht zur konfigurierten Domäne')

    if not name or any(ch in '\\/@' or ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ValueError('Ungültiger Benutzername')
    return name


def resolve_account(username):
    """Get the current AD account status directly; directory errors fail closed."""
    sam = account_login(username)
    if is_excluded_user(sam) or sam.endswith('$'):
        return None

    escaped = directory.escape_ldap_filter_value(sam)
    entries = directory.search_directory_entries(
        f'(&(objectClass=user)(!(objectClass=computer))(sAMAccountName={escaped}))',
        ['distinguishedName', 'sAMAccountName', 'objectSid', 'userAccountControl', 'accountExpires',
         'msDS-User-Account-Control-Computed', 'lockoutTime'],
    )
    if len(entries) != 1:
        return None

    entry = entries[0]
    if (directory.ldap_first(entry, 'sAMAccountName') or '').casefold() != sam.casefold():
        return None
    principal = directory.parse_principal_from_entry(entry)
    sid = str(principal.get('objectSid', '')) if principal else ''
    if not SID_RE.fullmatch(sid):
        return None

    try:
        flags = int(directory.ldap_first(entry, 'userAccountControl') or '-1')
        expires = int(directory.ldap_first(entry, 'accountExpires') or '0')
        computed = directory.ldap_first(entry, 'msDS-User-Account-Control-Computed')
        locked = (bool(int(computed) & ACCOUNT_LOCKED) if computed is not None
                  else int(directory.ldap_first(entry, 'lockoutTime') or '0') > 0)
    except ValueError:
        return None

    if flags < 0 or flags & (ACCOUNT_DISABLED | ACCOUNT_LOCKED) or locked:
        return None
    if expires not in directory.AD_NEVER_EXPIRES_VALUES and expires <= directory.windows_filetime_now():
        return None
    return sid


def token_hash(raw):
    return hashlib.sha256(raw.encode('ascii')).hexdigest()


class TokenStore:
    def __init__(self, root):
        self.path = Path(root) / DATABASE_NAME
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

        with self.connect() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('''CREATE TABLE IF NOT EXISTS agent_tokens (
                id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE,
                label TEXT NOT NULL, accounts TEXT NOT NULL, created_by TEXT NOT NULL,
                created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
            )''')

    @contextlib.contextmanager
    def connect(self):
        with contextlib.closing(sqlite3.connect(self.path, timeout=5)) as conn:
            conn.row_factory = sqlite3.Row
            with conn:
                yield conn

    def issue(self, label, accounts, days, actor):
        now = int(time.time())
        identifier = secrets.token_hex(12)
        raw = 'dsat_' + secrets.token_urlsafe(32)

        with self.connect() as conn:
            conn.execute(
                'INSERT INTO agent_tokens VALUES (?, ?, ?, ?, ?, ?, ?)',
                (identifier, token_hash(raw), label, json.dumps(accounts), actor, now, now + days * 86400),
            )
        return {'id': identifier, 'token': raw, 'expiresAt': now + days * 86400}

    def inventory(self):
        with self.connect() as conn:
            rows = conn.execute('''SELECT id, label, accounts, created_by, created_at, expires_at
                                   FROM agent_tokens ORDER BY created_at DESC, id''').fetchall()

        return [{
            'id': row['id'], 'label': row['label'], 'usernames': list(json.loads(row['accounts']).values()),
            'createdBy': row['created_by'], 'createdAt': row['created_at'], 'expiresAt': row['expires_at'],
        } for row in rows]

    def authenticate(self, raw):
        if not TOKEN_RE.fullmatch(raw):
            return None

        with self.connect() as conn:
            row = conn.execute(
                'SELECT id, accounts FROM agent_tokens WHERE digest=? AND expires_at>?',
                (token_hash(raw), int(time.time())),
            ).fetchone()
        return (row['id'], json.loads(row['accounts'])) if row is not None else None

    def revoke(self, identifier):
        if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
            raise ValueError('Ungültige Token-ID')

        with self.connect() as conn:
            return conn.execute('DELETE FROM agent_tokens WHERE id=?', (identifier,)).rowcount == 1
