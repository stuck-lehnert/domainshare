"""Persistent, revocable web sessions and strict browser-origin validation."""

import contextlib
import hashlib
import sqlite3
import threading
import urllib.parse

try:
    from .state_db import connect_state_db
except ImportError:
    from state_db import connect_state_db


class Sessions:
    def __init__(self, path=None):
        # Tests can use an isolated in-memory registry. Production passes the
        # persistent state database so logout survives a process restart.
        self.memory = sqlite3.connect(':memory:', check_same_thread=False) if path is None else None
        if self.memory:
            self.memory.row_factory = sqlite3.Row
        self.path = path
        self.lock = threading.RLock()
        with self.connection() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS web_sessions (
                id TEXT PRIMARY KEY, sid TEXT NOT NULL, expires INTEGER NOT NULL,
                username TEXT NOT NULL, uid INTEGER, role TEXT NOT NULL, checked REAL NOT NULL)''')
            conn.execute('CREATE INDEX IF NOT EXISTS web_sessions_expiry ON web_sessions(expires)')
            conn.commit()

    @contextlib.contextmanager
    def connection(self):
        with self.lock:
            if self.memory is None and self.path is None:
                raise RuntimeError('Session registry is closed')
            conn = self.memory if self.memory is not None else connect_state_db(self.path)
            try:
                yield conn
            finally:
                if self.memory is None:
                    conn.close()

    @staticmethod
    def key(jti):
        return hashlib.sha256(jti.encode()).hexdigest()

    def issue(self, payload):
        with self.connection() as conn, conn:
            conn.execute('DELETE FROM web_sessions WHERE expires<=?', (payload['iat'],))
            conn.execute('INSERT INTO web_sessions VALUES(?,?,?,?,?,?,?)',
                         (self.key(payload['jti']), payload['sid'], payload['exp'], payload['sub'],
                          payload['uid'], payload['role'], payload['iat']))

    def get(self, jti, now):
        with self.connection() as conn:
            row = conn.execute('SELECT * FROM web_sessions WHERE id=? AND expires>?',
                               (self.key(jti), now)).fetchone()
            return dict(row) if row else None

    def refresh(self, jti, identity, now):
        # UPDATE cannot resurrect a session logged out during the AD lookup.
        with self.connection() as conn, conn:
            conn.execute('UPDATE web_sessions SET username=?,uid=?,role=?,checked=? WHERE id=?',
                         (identity['sub'], identity['uid'], identity['role'], now, self.key(jti)))

    def revoke(self, jti):
        with self.connection() as conn, conn:
            conn.execute('DELETE FROM web_sessions WHERE id=?', (self.key(jti),))

    def recheck_all(self):
        with self.connection() as conn, conn:
            conn.execute('UPDATE web_sessions SET checked=0')

    def close(self):
        with self.lock:
            if self.memory is not None:
                self.memory.close()
                self.memory = None

    def __del__(self):
        if getattr(self, 'memory', None) is not None:
            self.memory.close()


def origin(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError()
        if parsed.path or parsed.query or parsed.fragment or any(char.isspace() for char in value):
            raise ValueError()
        port = 443 if parsed.port is None else parsed.port
        if port == 0 or parsed.netloc.endswith(':'):
            raise ValueError()
        host = parsed.hostname.casefold()
        return host, port
    except ValueError as exc:
        raise ValueError('Invalid HTTPS origin') from exc
