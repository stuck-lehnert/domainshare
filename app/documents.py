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
    from . import access_control, document_search, reconcile_shares as directory
    from .account_policy import account_name, is_excluded_user
    from .state_db import connect_state_db
    from .document_types import CONTENT_SUFFIXES, OFFICE_SUFFIXES, IMAGE_SUFFIXES
except ImportError:
    import access_control
    import document_search
    import reconcile_shares as directory
    from account_policy import account_name, is_excluded_user
    from state_db import connect_state_db
    from document_types import CONTENT_SUFFIXES, OFFICE_SUFFIXES, IMAGE_SUFFIXES

SEARCH_ROOT = os.getenv('DOCUMENT_STATE_ROOT', os.path.join(os.getenv('STATE_ROOT', '/state'), 'documents'))
SEARCH_DB = os.path.join(SEARCH_ROOT, 'search.db')
MAX_TEXT = 2 * 1024 * 1024
SEARCHABLE_NAME_SQL = "lower({name}) <> 'thumbs.db' AND {name} NOT GLOB '~$*'"


def is_excluded_filename(name):
    return name.casefold() == 'thumbs.db' or name.startswith('~$')



def connect():
    os.makedirs(SEARCH_ROOT, mode=0o700, exist_ok=True)
    os.chmod(SEARCH_ROOT, 0o700)
    conn = connect_state_db(SEARCH_DB)
    document_search.register(conn)
    return conn


def ensure_schema(conn):
    document_search.register(conn)
    if conn.execute('PRAGMA user_version').fetchone()[0] >= document_search.VERSION:
        return
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
    if conn.execute('PRAGMA user_version').fetchone()[0] < 2:
        with conn:
            conn.execute('BEGIN IMMEDIATE')
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            if version < 1:
                content = sorted(CONTENT_SUFFIXES)
                images = sorted(IMAGE_SUFFIXES)
                conn.execute(f"""UPDATE documents SET body='',pages=0,attempts=0,retry_at=0,
                                state=CASE WHEN extension IN ({','.join('?' for _ in images)}) AND preview=''
                                           THEN 'pending' ELSE 'name-only' END
                                WHERE extension NOT IN ({','.join('?' for _ in content)})""", [*images,*content])
            if version < 2:
                conn.execute(f"DELETE FROM documents WHERE NOT ({SEARCHABLE_NAME_SQL.format(name='name')})")
                conn.execute('PRAGMA user_version=2')

    content_types = ','.join("'" + suffix + "'" for suffix in sorted(CONTENT_SUFFIXES))
    document_search.ensure_schema(conn, SEARCHABLE_NAME_SQL.format(name='name'), content_types)


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
    name = relative.rsplit('/', 1)[-1]
    if is_excluded_filename(name):
        conn.execute('DELETE FROM documents WHERE source_id=? AND path=?', (source['id'], relative))
        return
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
    if row is None or row['source_id'] not in sources or is_excluded_filename(row['name']):
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
    # Keep rollups, posting lists and page selection in one WAL snapshot.
    # The caller's transaction, if any, remains under its own control.
    own_transaction = not conn.in_transaction
    if own_transaction:
        conn.execute('BEGIN')
    try:
        return search_snapshot(conn, identity, params)
    finally:
        if own_transaction:
            conn.rollback()


def search_snapshot(conn, identity, params):
    sources = allowed_sources(conn, identity)
    query = str(params.get('q', [''])[0]).strip()[:256]
    scope = params.get('scope', ['all'])[0]
    source_filter = params.get('source', [''])[0]
    extension = params.get('type', [''])[0].lower().lstrip('.')
    sort = params.get('sort', ['recent'])[0]
    if sort not in {'name', 'oldest', 'recent', 'relevance'}:
        sort = 'recent'
    if sort == 'relevance' and (not query or scope == 'name'):
        sort = 'recent'
    try:
        limit = min(100, max(1, int(params.get('limit', ['40'])[0])))
        offset = max(0, int(params.get('offset', ['0'])[0]))
        if offset > 1000 and not params.get('cursor', [''])[0]:
            raise ValueError()
    except ValueError as exc:
        raise ValueError('Für weitere Seiten bitte den Seitenzeiger verwenden') from exc
    signature = document_search.cursor_scope(query, scope, source_filter, extension, sort)
    position, consumed = document_search.decode_cursor(params.get('cursor', [''])[0], signature)
    if position:
        offset = 0
    selected = {key: value for key, value in sources.items() if not source_filter or key == source_filter}
    base = {'items': [], 'total': 0, 'totalExact': True, 'hasMore': False, 'nextCursor': None,
            'sources': [{'id': key, 'label': value['label'], 'kind': value['kind']} for key, value in sources.items()],
            'types': [], 'pending': 0, 'pendingExact': True, 'searchIncomplete': False}
    if not selected:
        return base
    visible_sql = SEARCHABLE_NAME_SQL.format(name='d.name')
    readable = {}

    def permitted(row):
        if selected[row['source_id']]['kind'] != 'private':
            return True
        if row['id'] not in readable:
            readable[row['id']] = private_readable(selected[row['source_id']], row['path'], identity.get('uid'))
        return readable[row['id']]

    # Small, incrementally maintained rollups replace full scans for counts,
    # progress and dropdowns. Private facets are only published after a current
    # filesystem permission check. Large private folders get bounded samples;
    # their exact total is deliberately not inferred from unverified records.
    total = 0
    selected_count = 0
    metadata_exact = True
    types = set()
    for source_id, source in selected.items():
        groups = conn.execute('SELECT extension,state,amount FROM document_counts WHERE source_id=?', (source_id,)).fetchall()
        selected_count += sum(group['amount'] for group in groups)
        if source['kind'] == 'data':
            for group in groups:
                if group['extension']:
                    types.add(group['extension'].lstrip('.'))
                if not extension or group['extension'] == '.' + extension:
                    total += group['amount']
                if group['state'] in {'pending', 'ocr'}:
                    base['pending'] += group['amount']
            continue
        count = sum(group['amount'] for group in groups)
        small = count <= document_search.PRIVATE_FACET_LIMIT
        metadata_exact = metadata_exact and small
        base['pendingExact'] = base['pendingExact'] and small
        suffixes = sorted({group['extension'] for group in groups})
        budget = document_search.PRIVATE_FACET_LIMIT
        for number, suffix in enumerate(suffixes):
            if not small and budget <= 0:
                break
            sample = count if small else max(1, budget // (len(suffixes) - number))
            rows = conn.execute(f'''SELECT d.id,d.source_id,d.path,d.extension,d.state FROM documents d
                INDEXED BY document_search_recent_type WHERE d.source_id=? AND d.extension=? AND {visible_sql}
                ORDER BY d.modified DESC,d.id DESC LIMIT ?''', (source_id, suffix, sample)).fetchall()
            budget -= len(rows)
            for row in rows:
                if permitted(row):
                    if suffix:
                        types.add(suffix.lstrip('.'))
                    if not extension or suffix == '.' + extension:
                        total += 1
                    base['pending'] += int(row['state'] in {'pending', 'ocr'})

    table, match = None, None
    if query:
        if scope == 'name':
            table = 'document_names_fts'
            normalized = query.casefold()
            size = min(3, len(normalized))
            match = ' AND '.join(document_search.key(normalized[i:i + size], 'g')
                                 for i in range(len(normalized) - size + 1))
        else:
            words = re.findall(r'\w+', query, flags=re.UNICODE)[:24]
            if not words:
                base['types'] = sorted(types)
                return base
            table = 'document_fts'
            match = ' AND '.join('"' + word + '"*' for word in words)
            match = ('body' if scope == 'content' else '{name path body}') + ' : (' + match + ')'
    candidates = []
    complete = True
    boundaries = []
    combined = sort == 'relevance' or table and len(selected) > 1
    selections = [list(selected)] if combined else list(selected)
    catalog_count = conn.execute('SELECT coalesce(sum(amount),0) FROM document_counts').fetchone()[0] if combined else 0
    push_sources = selected_count < catalog_count * 0.5
    rank_offset = position[3] if position and len(position) == 4 else consumed
    if sort == 'relevance' and max(consumed, rank_offset) > selected_count:
        raise ValueError('Ungültiger Seitenzeiger')
    for source_id in selections:
        private = any(source['kind'] == 'private' for source in selected.values()) if combined else selected[source_id]['kind'] == 'private'
        amount = limit + offset + (document_search.PRIVATE_FACET_LIMIT if private else 0) + 1
        if sort == 'relevance':
            rows, exhaustive = document_search.ranked_rows(conn, source_id, '.' + extension if extension else '',
                                                          match, visible_sql, rank_offset, amount, selected_count != catalog_count)
        elif combined:
            rows, exhaustive = document_search.global_rows(conn, source_id, '.' + extension if extension else '', sort,
                table, match, query if scope == 'name' else '', visible_sql, position, amount, push_sources)
        else:
            rows, exhaustive = document_search.source_rows(conn, source_id, '.' + extension if extension else '', sort,
                table, match, query if scope == 'name' else '', visible_sql, position, amount)
        candidates.extend(rows)
        complete = complete and exhaustive
        if not exhaustive and len(rows) >= amount:
            boundaries.append(document_search.row_key(rows[-1], sort))
    candidates.sort(key=lambda row: document_search.row_key(row, sort))
    boundary = min(boundaries) if boundaries else None
    visible = []
    frontier = None
    exhausted = True
    for row in candidates:
        if boundary is not None and document_search.row_key(row, sort) > boundary:
            exhausted = False
            break
        frontier = row
        if not permitted(row):
            continue
        try:
            with open_file(selected[row['source_id']]['root'], row['path']) as (_, info):
                if fingerprint(info) != row['fingerprint']:
                    continue
        except OSError:
            continue
        visible.append(row)
        if len(visible) > offset + limit:
            exhausted = False
            break
    more = len(visible) > offset + limit
    page = visible[offset:offset + limit]
    incomplete = not more and boundary is not None and (not exhausted or frontier is not None and document_search.row_key(frontier, sort) >= boundary)
    base['hasMore'] = more or incomplete
    base['searchIncomplete'] = incomplete
    if query:
        if complete and not position:
            total = sum(1 for row in candidates if permitted(row))
            exact = True
        elif not base['hasMore']:
            total, exact = consumed + offset + len(page), True
        else:
            total, exact = consumed + offset + len(page) + int(more), False
    else:
        exact = metadata_exact
        if not exact:
            total = max(total, consumed + offset + len(page) + int(more))
    base['total'], base['totalExact'] = total, exact
    if base['hasMore'] and (page or frontier is not None):
        last = page[-1] if more else frontier
        base['nextCursor'] = document_search.encode_cursor(signature, document_search.row_position(last, sort),
                                                          consumed + offset + len(page))
    items = []
    for row in page:
        # The portal shows file metadata, never extracted text. Computing FTS
        # snippets here repeats a potentially broad MATCH once per result.
        items.append(public_document(row, selected[row['source_id']]))
        if row['extension']:
            types.add(row['extension'].lstrip('.'))
    base['items'], base['types'] = items, sorted(types)
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
