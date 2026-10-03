"""Permission-filtered document catalog. Originals are only ever opened for reading."""

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import uuid

try:
    from . import access_control, reconcile_shares as directory
    from .account_policy import account_name, is_excluded_user
    from .state_db import connect_state_db
    from .document_types import CONTENT_SUFFIXES, OFFICE_SUFFIXES, IMAGE_SUFFIXES
except ImportError:
    import access_control
    import reconcile_shares as directory
    from account_policy import account_name, is_excluded_user
    from state_db import connect_state_db
    from document_types import CONTENT_SUFFIXES, OFFICE_SUFFIXES, IMAGE_SUFFIXES

SEARCH_ROOT = os.getenv('DOCUMENT_STATE_ROOT', os.path.join(os.getenv('STATE_ROOT', '/state'), 'documents'))
SEARCH_DB = os.path.join(SEARCH_ROOT, 'search.db')
MAX_TEXT = 2 * 1024 * 1024



def connect():
    os.makedirs(SEARCH_ROOT, mode=0o700, exist_ok=True)
    os.chmod(SEARCH_ROOT, 0o700)
    return connect_state_db(SEARCH_DB)


def ensure_schema(conn):
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS document_sources (
            id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL,
            root TEXT NOT NULL, owner_sid TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS documents (
            rowid INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE,
            source_id TEXT NOT NULL REFERENCES document_sources(id) ON DELETE CASCADE,
            path TEXT NOT NULL, name TEXT NOT NULL, extension TEXT NOT NULL,
            size INTEGER NOT NULL, modified REAL NOT NULL, fingerprint TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'pending',
            preview TEXT NOT NULL DEFAULT '', pages INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0,
            indexed_at REAL NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0,
            UNIQUE(source_id,path)
        );
        CREATE INDEX IF NOT EXISTS document_queue ON documents(state,retry_at);
        CREATE INDEX IF NOT EXISTS document_source ON documents(source_id,modified);
        CREATE TABLE IF NOT EXISTS document_worker (
            id INTEGER PRIMARY KEY CHECK(id=1), paused INTEGER NOT NULL DEFAULT 0,
            heartbeat REAL NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'idle',
            current_id TEXT NOT NULL DEFAULT '', processed INTEGER NOT NULL DEFAULT 0,
            scanning INTEGER NOT NULL DEFAULT 0, last_scan REAL NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO document_worker(id) VALUES(1);
        CREATE TABLE IF NOT EXISTS document_activity (
            id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, action TEXT NOT NULL,
            path TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT ''
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS document_fts USING fts5(
            name,path,body,content='documents',content_rowid='rowid',
            tokenize='unicode61 remove_diacritics 2',prefix='2 3 4'
        );
        CREATE TRIGGER IF NOT EXISTS document_insert AFTER INSERT ON documents BEGIN
            INSERT INTO document_fts(rowid,name,path,body) VALUES(new.rowid,new.name,new.path,new.body);
        END;
        CREATE TRIGGER IF NOT EXISTS document_delete AFTER DELETE ON documents BEGIN
            INSERT INTO document_fts(document_fts,rowid,name,path,body) VALUES('delete',old.rowid,old.name,old.path,old.body);
        END;
        CREATE TRIGGER IF NOT EXISTS document_update AFTER UPDATE OF name,path,body ON documents BEGIN
            INSERT INTO document_fts(document_fts,rowid,name,path,body) VALUES('delete',old.rowid,old.name,old.path,old.body);
            INSERT INTO document_fts(rowid,name,path,body) VALUES(new.rowid,new.name,new.path,new.body);
        END;
    ''')

    # Upgrade the derived index only: keep catalog IDs, permissions, previews
    # and originals, but remove content and jobs for excluded file types.
    if conn.execute('PRAGMA user_version').fetchone()[0] < 1:
        with conn:
            conn.execute('BEGIN IMMEDIATE')
            if conn.execute('PRAGMA user_version').fetchone()[0] < 1:
                content = sorted(CONTENT_SUFFIXES)
                images = sorted(IMAGE_SUFFIXES)
                conn.execute(f"""UPDATE documents SET body='',pages=0,attempts=0,retry_at=0,
                                state=CASE WHEN extension IN ({','.join('?' for _ in images)}) AND preview=''
                                           THEN 'pending' ELSE 'name-only' END
                                WHERE extension NOT IN ({','.join('?' for _ in content)})""", [*images,*content])
                conn.execute('PRAGMA user_version=1')


def worker_paused(conn):
    return bool(conn.execute('SELECT paused FROM document_worker WHERE id=1').fetchone()[0])


def worker_event(conn, action, path='', source='', actor='', message=''):
    conn.execute('INSERT INTO document_activity(timestamp,action,path,source,actor,message) VALUES(?,?,?,?,?,?)',
                 (time.time(), action, path, source, actor, str(message)[:200]))


def control_worker(conn, action, actor):
    if action not in {'pause', 'resume'}:
        raise ValueError('Ungültige Aktion')
    conn.execute('BEGIN IMMEDIATE')
    try:
        paused = action == 'pause'
        if worker_paused(conn) != paused:
            conn.execute('UPDATE document_worker SET paused=? WHERE id=1', (int(paused),))
            worker_event(conn, action, actor=actor)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return worker_snapshot(conn)


def worker_snapshot(conn):
    result = dict(conn.execute('SELECT * FROM document_worker WHERE id=1').fetchone())
    result['paused'] = bool(result['paused'])
    result['online'] = result['heartbeat'] > time.time() - 15
    counts = dict(conn.execute('SELECT state,count(*) FROM documents GROUP BY state').fetchall())
    total = sum(counts.values())
    ready = counts.get('ready', 0) + counts.get('name-only', 0)
    result['counts'] = {'total': total, 'complete': ready, 'pending': counts.get('pending', 0),
                        'ocr': counts.get('ocr', 0), 'nameOnly': counts.get('name-only', 0),
                        'errors': conn.execute("SELECT count(*) FROM documents WHERE state='failed' OR attempts>0").fetchone()[0]}
    result['progress'] = round(100 * ready / total) if total else 0
    row = conn.execute('''SELECT d.name,d.path,d.pages,CASE WHEN s.kind='private' THEN s.label || ' / ' || substr(s.id,9) ELSE s.label END AS source,s.kind FROM documents d
                          JOIN document_sources s ON s.id=d.source_id WHERE d.id=?''', (result['current_id'],)).fetchone()
    result['current'] = dict(row) if row else None
    result['activity'] = [dict(row) for row in conn.execute('SELECT * FROM document_activity ORDER BY id DESC LIMIT 100')]
    result['failures'] = [dict(row) for row in conn.execute('''SELECT d.name,d.path,CASE WHEN s.kind='private' THEN s.label || ' / ' || substr(s.id,9) ELSE s.label END AS source,d.state,d.attempts,d.retry_at
                         FROM documents d JOIN document_sources s ON s.id=d.source_id
                         WHERE d.state='failed' OR d.attempts>0 ORDER BY d.retry_at LIMIT 50''')]
    return result


def fingerprint(info):
    return ':'.join(str(value) for value in (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))


def valid_parts(path):
    parts = path.split('/')
    if not path or any(part in {'', '.', '..', '.trash'} or '\x00' in part for part in parts):
        raise FileNotFoundError('Invalid document path')
    return parts


@contextlib.contextmanager
def open_file(root, path):
    """Pin every path component; reject links, special files and nested mounts."""
    parts = valid_parts(path)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    handle = None
    try:
        device = os.fstat(fd).st_dev
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            if os.fstat(fd).st_dev != device:
                raise FileNotFoundError('Mount boundary')
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        handle = os.fdopen(child, 'rb')
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_dev != device:
            raise FileNotFoundError('Not a regular document')
        yield handle, info
    finally:
        if handle is not None:
            handle.close()
        os.close(fd)


def source_inventory():
    conn = directory.open_db()
    try:
        # Reconciliation and login populate these identities. Never import groups here.
        sources = []
        for row in conn.execute('SELECT * FROM shares WHERE isActive=1'):
            root = access_control.safe_folder_path(row)
            if os.path.isdir(root):
                sources.append({'id': 'data:' + row['objectGUID'], 'kind': 'data', 'label': row['shareName'], 'root': root, 'owner_sid': ''})
        users = {row['sam'].casefold(): row['sid'] for row in conn.execute('SELECT sid,sam FROM access_users')
                 if not is_excluded_user(row['sam'])}
        if os.path.isdir(directory.PRIVATE_ROOT):
            for entry in os.scandir(directory.PRIVATE_ROOT):
                sid = users.get(entry.name.casefold())
                if sid and entry.is_dir(follow_symlinks=False):
                    sources.append({'id': 'private:' + entry.name.casefold(), 'kind': 'private',
                                    'label': 'Private', 'root': entry.path, 'owner_sid': sid})
        return sources
    finally:
        conn.close()


def allowed_sources(conn, identity):
    """Use current policy on every request, including previews and downloads."""
    if is_excluded_user(str(identity.get('sub', ''))):
        return {}
    policy = directory.open_db()
    try:
        excluded = access_control.excluded_user_sids(policy)
        sid = identity.get('sid')
        if not sid or sid in excluded:
            return {}
        folders = {row['objectGUID']: row for row in policy.execute('SELECT * FROM shares WHERE isActive=1')}
        levels = {row['folderId']: row['level'] for row in policy.execute(
            "SELECT folderId,level FROM folder_permissions WHERE kind='user' AND principalId=?", (sid,))}
        result = {}
        for source in conn.execute('SELECT * FROM document_sources'):
            if source['kind'] == 'data':
                folder_id = source['id'][5:]
                folder = folders.get(folder_id)
                if folder is None or (identity.get('role') != 'domain-admin' and levels.get(folder_id, 0) < 1):
                    continue
                root = access_control.safe_folder_path(folder)
                if source['root'] != root:
                    continue
            elif source['kind'] == 'private':
                # The user portal always shows only one's own home, even for admins.
                if source['owner_sid'] != sid or os.path.dirname(source['root']) != os.path.abspath(directory.PRIVATE_ROOT):
                    continue
                try:
                    if os.stat(source['root'], follow_symlinks=False).st_uid != identity.get('uid'):
                        continue
                except OSError:
                    continue
            else:
                continue
            if not os.path.islink(source['root']):
                result[source['id']] = dict(source)
        return result
    finally:
        policy.close()


def discover_file(conn, source, relative, seen=0):
    try:
        with open_file(source['root'], relative) as (_, info):
            stamp = fingerprint(info)
    except (OSError, ValueError):
        conn.execute('DELETE FROM documents WHERE source_id=? AND path=?', (source['id'], relative))
        return
    old = conn.execute('SELECT fingerprint FROM documents WHERE source_id=? AND path=?', (source['id'], relative)).fetchone()
    if old and old['fingerprint'] == stamp:
        if seen:
            conn.execute('UPDATE documents SET seen=? WHERE source_id=? AND path=?', (seen, source['id'], relative))
        return
    name = relative.rsplit('/', 1)[-1]
    extension = os.path.splitext(name)[1].lower()
    state = 'pending' if extension in CONTENT_SUFFIXES | IMAGE_SUFFIXES else 'name-only'
    conn.execute('''INSERT INTO documents(id,source_id,path,name,extension,size,modified,fingerprint,seen,state)
                    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(source_id,path) DO UPDATE SET
                    name=excluded.name,extension=excluded.extension,size=excluded.size,
                    modified=excluded.modified,fingerprint=excluded.fingerprint,seen=excluded.seen,
                    body='',state=excluded.state,preview='',pages=0,attempts=0,retry_at=0,indexed_at=0''',
                 (uuid.uuid4().hex, source['id'], relative, name, extension,
                  info.st_size, info.st_mtime, stamp, seen, state))


def walk_source(conn, source, watch=None, should_stop=None):
    """Deletion affects index records only. Original files are never removed."""
    seen = time.time_ns()
    completed = True
    visited = 0
    def scan(relative=''):
        nonlocal completed, visited
        if should_stop and should_stop():
            completed = False
            return
        path = os.path.join(source['root'], relative)
        try:
            with open_directory(source['root'], relative) as fd:
                if watch:
                    watch(path, source['id'], relative)
                device = os.fstat(fd).st_dev
                for entry in os.scandir(fd):
                    visited += 1
                    if visited % 100 == 0:
                        conn.commit()
                    if should_stop and should_stop():
                        completed = False
                        return
                    if entry.name == '.trash' or entry.is_symlink():
                        continue
                    child = '/'.join(filter(None, (relative, entry.name)))
                    info = entry.stat(follow_symlinks=False)
                    if info.st_dev != device:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        scan(child)
                    elif stat.S_ISREG(info.st_mode):
                        discover_file(conn, source, child, seen)
                conn.commit()
        except OSError:
            completed = False
    scan()
    if completed:
        conn.execute('DELETE FROM documents WHERE source_id=? AND seen<>?', (source['id'], seen))
    conn.commit()
    return completed


@contextlib.contextmanager
def open_directory(root, relative):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        device = os.fstat(fd).st_dev
        for part in valid_parts(relative) if relative else []:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            if os.fstat(fd).st_dev != device:
                raise FileNotFoundError('Mount boundary')
        yield fd
    finally:
        os.close(fd)


def private_readable(source, relative, uid):
    if source['kind'] != 'private':
        return True
    try:
        with open_directory(source['root'], '') as fd:
            info = os.fstat(fd)
            if info.st_uid != uid or info.st_mode & 0o500 != 0o500:
                return False
        parts = valid_parts(relative)
        for index in range(1, len(parts)):
            with open_directory(source['root'], '/'.join(parts[:index])) as fd:
                info = os.fstat(fd)
                if info.st_uid != uid or info.st_mode & 0o500 != 0o500:
                    return False
        with open_file(source['root'], relative) as (_, info):
            return info.st_uid == uid and bool(info.st_mode & 0o400)
    except OSError:
        return False


def current_document(conn, document_id, identity):
    sources = allowed_sources(conn, identity)
    row = conn.execute('SELECT * FROM documents WHERE id=?', (document_id,)).fetchone()
    if row is None or row['source_id'] not in sources:
        raise FileNotFoundError('Document not found')
    source = sources[row['source_id']]
    if not private_readable(source, row['path'], identity.get('uid')):
        raise FileNotFoundError('Document not readable')
    try:
        with open_file(source['root'], row['path']) as (_, info):
            if fingerprint(info) != row['fingerprint']:
                raise FileNotFoundError('Document changed')
    except OSError as exc:
        raise FileNotFoundError('Document unavailable') from exc
    return dict(row), source


def public_document(row, source, snippet=''):
    version = hashlib.sha256(row['fingerprint'].encode()).hexdigest()[:16]
    return {'id': row['id'], 'name': row['name'], 'path': row['path'], 'sourceId': row['source_id'],
            'source': source['label'], 'kind': source['kind'], 'extension': row['extension'].lstrip('.'),
            'size': row['size'], 'modified': row['modified'], 'state': row['state'], 'pages': row['pages'],
            'hasPreview': bool(row['preview']), 'version': version, 'snippet': snippet, 'attempts': row['attempts']}


def search(conn, identity, params):
    sources = allowed_sources(conn, identity)
    query = str(params.get('q', [''])[0]).strip()[:256]
    scope = params.get('scope', ['all'])[0]
    source_filter = params.get('source', [''])[0]
    extension = params.get('type', [''])[0].lower().lstrip('.')
    sort = params.get('sort', ['recent'])[0]
    try:
        limit = min(100, max(1, int(params.get('limit', ['40'])[0])))
        offset = max(0, int(params.get('offset', ['0'])[0]))
    except ValueError as exc:
        raise ValueError('Ungültige Seitennummer') from exc
    selected = {key: value for key, value in sources.items() if not source_filter or key == source_filter}
    base = {'items': [], 'total': 0, 'hasMore': False, 'sources': [{'id': key, 'label': value['label'], 'kind': value['kind']} for key, value in sources.items()], 'types': [], 'pending': 0}
    if not sources:
        return base
    # Filter before snippets, pagination, counts and facets. Hidden files
    # must never influence any user-visible result.
    ids = list(selected)
    if not ids:
        return base
    placeholders = ','.join('?' for _ in ids)
    conn.execute('CREATE TEMP TABLE IF NOT EXISTS readable_private(id TEXT PRIMARY KEY)')
    conn.execute('DELETE FROM readable_private')
    for row in conn.execute(f"SELECT id,source_id,path FROM documents WHERE source_id IN ({placeholders}) AND source_id LIKE 'private:%'", ids).fetchall():
        if private_readable(selected[row['source_id']], row['path'], identity.get('uid')):
            conn.execute('INSERT INTO readable_private VALUES(?)', (row['id'],))
    private_condition = "(d.source_id NOT LIKE 'private:%' OR EXISTS (SELECT 1 FROM readable_private r WHERE r.id=d.id))"
    conditions = [f'd.source_id IN ({placeholders})', private_condition]
    values = ids[:]
    from_sql = 'documents d'
    content_types = ','.join("'" + extension + "'" for extension in sorted(CONTENT_SUFFIXES))
    snippet_sql = f"CASE WHEN d.extension IN ({content_types}) THEN substr(d.body,1,220) ELSE '' END"
    if query:
        if scope == 'name':
            conditions.append("d.name LIKE ? ESCAPE '\\'")
            values.append('%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
        else:
            words = re.findall(r'\w+', query, flags=re.UNICODE)[:24]
            if not words:
                return base
            match = ' AND '.join('"' + word + '"*' for word in words)
            if scope == 'content':
                match = 'body : (' + match + ')'
            from_sql += ' JOIN document_fts ON document_fts.rowid=d.rowid'
            conditions.append('document_fts MATCH ?')
            values.append(match)
            if scope == 'content':
                conditions.append(f'd.extension IN ({content_types})')
            else:
                # A stale body from an older worker must never make other file
                # types appear in content search, even before index cleanup.
                conditions.append(f"(d.extension IN ({content_types}) OR d.rowid IN (SELECT rowid FROM document_fts WHERE document_fts MATCH ?))")
                values.append('{name path} : (' + ' AND '.join('"' + word + '"*' for word in words) + ')')
            snippet_sql = f"CASE WHEN d.extension IN ({content_types}) THEN snippet(document_fts,2,char(1),char(2),' … ',32) ELSE '' END"
    if extension:
        conditions.append('d.extension=?')
        values.append('.' + extension)
    where = ' AND '.join(conditions)
    order = {'name': 'd.name COLLATE NOCASE', 'oldest': 'd.modified', 'recent': 'd.modified DESC'}.get(sort, 'd.modified DESC')
    if query and scope != 'name' and sort == 'relevance':
        order = 'bm25(document_fts,6,2,1)'
    base['total'] = conn.execute(f'SELECT count(*) FROM {from_sql} WHERE {where}', values).fetchone()[0]
    base['hasMore'] = offset + limit < base['total']
    columns = 'd.id,d.source_id,d.path,d.name,d.extension,d.size,d.modified,d.fingerprint,d.state,d.preview,d.pages,d.attempts'
    rows = conn.execute(f'SELECT {columns}, {snippet_sql} AS excerpt FROM {from_sql} WHERE {where} ORDER BY {order},d.id LIMIT ? OFFSET ?', [*values,limit,offset])
    visible = []
    for row in rows:
        try:
            with open_file(selected[row['source_id']]['root'], row['path']) as (_, info):
                if fingerprint(info) == row['fingerprint'] and private_readable(selected[row['source_id']], row['path'], identity.get('uid')):
                    visible.append(row)
        except OSError:
            continue
    base['items'] = [public_document(row, selected[row['source_id']], row['excerpt']) for row in visible]
    base['types'] = sorted({row['extension'].lstrip('.') for row in conn.execute(f'SELECT DISTINCT extension FROM documents d WHERE source_id IN ({placeholders}) AND {private_condition}', ids) if row['extension']})
    base['pending'] = conn.execute(f"SELECT count(*) FROM documents d WHERE source_id IN ({placeholders}) AND {private_condition} AND state IN ('pending','ocr')", ids).fetchone()[0]
    return base


def detail(conn, identity, document_id):
    row, source = current_document(conn, document_id, identity)
    result = public_document(row, source)
    result['text'] = row['body'] if row['extension'] in CONTENT_SUFFIXES else ''
    return result


@contextlib.contextmanager
def download(conn, identity, document_id):
    row, source = current_document(conn, document_id, identity)
    with open_file(source['root'], row['path']) as (handle, info):
        if fingerprint(info) != row['fingerprint']:
            raise FileNotFoundError('Document changed')
        yield handle, row


@contextlib.contextmanager
def preview(conn, identity, document_id):
    row, _ = current_document(conn, document_id, identity)
    if not row['preview'] or not re.fullmatch(r'[a-f0-9]{32}\.jpg', row['preview']):
        raise FileNotFoundError('Preview unavailable')
    with open_file(os.path.join(SEARCH_ROOT, 'previews'), row['preview']) as (handle, info):
        yield handle, info.st_size
