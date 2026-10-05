"""Indexes and bounded query plans for the permission-filtered document catalog."""

import base64
import hashlib
import json
import sqlite3
import time

VERSION = 3
PROBE_LIMIT = 512
PRIVATE_FACET_LIMIT = 128
ORDER_SCAN_SECONDS = 0.15
NOCASE = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
SORTS = {'recent': 'modified DESC,id DESC', 'oldest': 'modified,id', 'name': 'name COLLATE NOCASE,id'}


def key(value, prefix):
    return prefix + str(value).encode().hex()


def name_terms(name):
    # Include short searches too: a trigram-only index scans for one/two letters.
    name = name.casefold()
    return ' '.join(sorted({key(name[i:i + n], 'g')
                            for n in (1, 2, 3) for i in range(len(name) - n + 1)}))


def register(conn):
    conn.create_function('document_name_terms', 1, name_terms, deterministic=True)


def ensure_schema(conn, visible, content_types):
    register(conn)
    if conn.execute('PRAGMA user_version').fetchone()[0] >= VERSION:
        return
    # DDL, FTS rebuild, rollups and the version marker commit together. A second
    # process waits here and then sees the finished migration. Originals and
    # document IDs, previews and the OCR queue are untouched.
    with conn:
        conn.execute('BEGIN IMMEDIATE')
        if conn.execute('PRAGMA user_version').fetchone()[0] >= VERSION:
            return
        for name in ('document_insert', 'document_delete', 'document_update'):
            conn.execute(f'DROP TRIGGER IF EXISTS {name}')
        conn.execute('DROP TABLE document_fts')
        conn.execute('DROP VIEW IF EXISTS document_search_content')
        conn.execute(f'''CREATE VIEW document_search_content AS
            SELECT rowid,name,path,CASE WHEN extension IN ({content_types}) THEN body ELSE '' END body,
                   's'||lower(hex(source_id)) source_key, 't'||lower(hex(extension)) type_key
            FROM documents WHERE {visible}''')
        conn.execute('''CREATE VIRTUAL TABLE document_fts USING fts5(
            name,path,body,source_key,type_key,content='document_search_content',content_rowid='rowid',
            tokenize='unicode61 remove_diacritics 2',prefix='2 3 4')''')
        conn.execute('''CREATE VIRTUAL TABLE IF NOT EXISTS document_names_fts USING fts5(
            terms,source_key,type_key,content='',tokenize='ascii',detail='none',columnsize=0)''')
        conn.execute("INSERT INTO document_names_fts(document_names_fts) VALUES('delete-all')")
        conn.execute('''CREATE TABLE IF NOT EXISTS document_counts (
            source_id TEXT NOT NULL, extension TEXT NOT NULL, state TEXT NOT NULL,
            amount INTEGER NOT NULL, PRIMARY KEY(source_id,extension,state)) WITHOUT ROWID''')
        conn.execute('DELETE FROM document_counts')
        for sort, order in SORTS.items():
            for typed, prefix in ((False, 'source_id,'), (True, 'source_id,extension,')):
                suffix = '_type' if typed else ''
                conn.execute(f'''CREATE INDEX IF NOT EXISTS document_search_{sort}{suffix}
                                 ON documents({prefix}{order}) WHERE {visible}''')
        global_indexes(conn, visible)

        def change(alias, deleting, names=False):
            condition = visible.replace('name', alias + '.name')
            body = f"CASE WHEN {alias}.extension IN ({content_types}) THEN {alias}.body ELSE '' END"
            fields = f"{alias}.rowid,{alias}.name,{alias}.path,{body},'s'||lower(hex({alias}.source_id)),'t'||lower(hex({alias}.extension))"
            terms = f"{alias}.rowid,document_name_terms({alias}.name),'s'||lower(hex({alias}.source_id)),'t'||lower(hex({alias}.extension))"
            if deleting:
                return f'''
                    INSERT INTO document_names_fts(document_names_fts,rowid,terms,source_key,type_key)
                        SELECT 'delete',{terms} WHERE {condition};
                ''' if names else f'''
                    INSERT INTO document_fts(document_fts,rowid,name,path,body,source_key,type_key)
                        SELECT 'delete',{fields} WHERE {condition};
                '''
            return f'''
                INSERT INTO document_names_fts(rowid,terms,source_key,type_key) SELECT {terms} WHERE {condition};
            ''' if names else f'''
                INSERT INTO document_fts(rowid,name,path,body,source_key,type_key) SELECT {fields} WHERE {condition};
            '''

        for name, event, sql in (
            ('document_insert', 'INSERT', change('new', False)),
            ('document_delete', 'DELETE', change('old', True)),
            ('document_update', 'UPDATE OF name,path,body,source_id,extension', change('old', True) + change('new', False)),
        ):
            conn.execute(f'CREATE TRIGGER {name} AFTER {event} ON documents BEGIN {sql} END')
        for name, event, sql in (
            ('document_name_insert', 'INSERT', change('new', False, True)),
            ('document_name_delete', 'DELETE', change('old', True, True)),
            ('document_name_update', 'UPDATE OF name,source_id,extension', change('old', True, True) + change('new', False, True)),
        ):
            conn.execute(f'DROP TRIGGER IF EXISTS {name}')
            conn.execute(f'CREATE TRIGGER {name} AFTER {event} ON documents BEGIN {sql} END')
        for name, event, aliases in (
            ('document_count_insert', 'INSERT', (('new', 1),)),
            ('document_count_delete', 'DELETE', (('old', -1),)),
            ('document_count_update', 'UPDATE OF name,source_id,extension,state', (('old', -1), ('new', 1))),
        ):
            conn.execute(f'DROP TRIGGER IF EXISTS {name}')
            sql = ''
            for alias, delta in aliases:
                condition = visible.replace('name', alias + '.name')
                sql += f'''INSERT INTO document_counts(source_id,extension,state,amount)
                    SELECT {alias}.source_id,{alias}.extension,{alias}.state,{delta} WHERE {condition}
                    ON CONFLICT(source_id,extension,state) DO UPDATE SET amount=amount+excluded.amount;
                    DELETE FROM document_counts WHERE source_id={alias}.source_id
                        AND extension={alias}.extension AND state={alias}.state AND amount=0;'''
            conn.execute(f'CREATE TRIGGER {name} AFTER {event} ON documents BEGIN {sql} END')
        conn.execute("INSERT INTO document_fts(document_fts) VALUES('rebuild')")
        conn.execute("INSERT INTO document_fts(document_fts,rank) VALUES('rank','bm25(6,2,1,0,0)')")
        conn.execute(f'''INSERT INTO document_names_fts(rowid,terms,source_key,type_key)
            SELECT rowid,document_name_terms(name),'s'||lower(hex(source_id)),'t'||lower(hex(extension))
            FROM documents WHERE {visible}''')
        conn.execute(f'''INSERT INTO document_counts SELECT source_id,extension,state,count(*)
            FROM documents WHERE {visible} GROUP BY source_id,extension,state''')
        conn.execute(f'PRAGMA user_version={VERSION}')


def cursor_scope(query, scope, source, extension, sort):
    return hashlib.sha256(json.dumps([query, scope, source, extension, sort]).encode()).hexdigest()[:16]


def global_indexes(conn, visible):
    for sort, order in SORTS.items():
        for typed in (False, True):
            suffix = '_type' if typed else ''
            conn.execute(f'''CREATE INDEX IF NOT EXISTS document_global_{sort}{suffix}
                ON documents({'extension,' if typed else ''}{order}) WHERE {visible}''')


def encode_cursor(signature, values, consumed):
    return base64.urlsafe_b64encode(json.dumps([signature, values, consumed], separators=(',', ':')).encode()).decode().rstrip('=')


def decode_cursor(value, signature):
    if not value:
        return None, 0
    try:
        if len(value) > 2048:
            raise ValueError()
        actual, position, consumed = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
        if actual != signature or not isinstance(position, list) or len(position) not in (3, 4) or not isinstance(consumed, int) or consumed < 0:
            raise ValueError()
        if not isinstance(position[0], (str, int, float)) or not isinstance(position[1], int) or not isinstance(position[2], str):
            raise ValueError()
        if len(position) == 4 and (not isinstance(position[3], int) or position[3] < 0):
            raise ValueError()
        return position, consumed
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Ungültiger Seitenzeiger') from exc


def row_key(row, sort):
    if sort == 'relevance':
        return row['_rank'], row['rowid']
    if sort == 'name':
        return row['name'].translate(NOCASE), row['id']
    if sort == 'recent':
        return -row['modified'], -int(row['id'], 16)
    return row['modified'], row['id']


def row_position(row, sort):
    primary = row['_rank'] if sort == 'relevance' else row['name'] if sort == 'name' else row['modified']
    result = [primary, row['rowid'], row['id']]
    if sort == 'relevance':
        result.append(row['_stream_offset'])
    return result


def source_rows(conn, source_id, extension, sort, table, match, name_query, visible, position, amount):
    """Selective matches sort a bounded set; broad ones walk a sorted index.

    The latter has a work deadline: sparse matches near the end of a metadata
    index fall back to the FTS-driven plan rather than scanning the catalog.
    """
    conditions = ['d.source_id=?', visible]
    values = [source_id]
    if extension:
        conditions.append('d.extension=?')
        values.append(extension)
    if name_query:
        conditions.append("d.name LIKE ? ESCAPE '\\'")
        values.append('%' + name_query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    order = {'name': 'd.name COLLATE NOCASE,d.id', 'oldest': 'd.modified,d.id',
             'recent': 'd.modified DESC,d.id DESC'}[sort]
    columns = 'd.rowid,d.id,d.source_id,d.path,d.name,d.extension,d.size,d.modified,d.fingerprint,d.state,d.preview,d.pages,d.attempts'
    if position:
        primary = 'd.name COLLATE NOCASE' if sort == 'name' else 'd.modified'
        op = '<' if sort == 'recent' else '>'
        # id is the stable tie-breaker in the metadata indexes.
        conditions.append(f'({primary},d.id) {op} (?,?)')
        values.extend((position[0], position[2]))
        if sort == 'name':
            # SQLite does not always turn a collated row-value comparison into
            # an index range. The redundant scalar bound guarantees the seek.
            conditions.append('d.name COLLATE NOCASE>=?')
            values.append(position[0])
    where = ' AND '.join(conditions)
    index = f'document_search_{sort}' + ('_type' if extension else '')
    if not table:
        return conn.execute(f'SELECT {columns},0 _rank FROM documents d INDEXED BY {index} WHERE {where} ORDER BY {order} LIMIT ?', [*values, amount]).fetchall(), False
    source_term = key(source_id, 's')
    type_term = key(extension, 't')
    scoped = f'({match}) AND ' + (source_term if table == 'document_names_fts' else 'source_key:' + source_term)
    if extension:
        scoped += ' AND ' + (type_term if table == 'document_names_fts' else 'type_key:' + type_term)
    # The FTS cursor must drive the join. A metadata-first plan reinitializes
    # MATCH for each catalog row, even when SQL asks for only 40 results.
    joined = f'{table} CROSS JOIN documents d ON d.rowid={table}.rowid'
    fts_where = f'{table} MATCH ? AND {where}'
    fts_values = [scoped, *values]
    probe = conn.execute(f'SELECT d.rowid FROM {joined} WHERE {fts_where} LIMIT ?', [*fts_values, PROBE_LIMIT + 1]).fetchall()
    if not probe:
        return [], True
    if len(probe) <= PROBE_LIMIT:
        amount = max(amount, PROBE_LIMIT + 1)
    if len(probe) > PROBE_LIMIT:
        deadline = time.monotonic() + ORDER_SCAN_SECONDS
        conn.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
        try:
            rows = conn.execute(f'''SELECT {columns},0 _rank FROM documents d INDEXED BY {index}
                WHERE {where} AND d.rowid IN (SELECT rowid FROM {table} WHERE {table} MATCH ?)
                ORDER BY {order} LIMIT ?''', [*values, scoped, amount]).fetchall()
            return rows, False
        except sqlite3.OperationalError as exc:
            if 'interrupted' not in str(exc):
                raise
        finally:
            conn.set_progress_handler(None, 0)
    rows = conn.execute(f'SELECT {columns},0 _rank FROM {joined} WHERE {fts_where} ORDER BY {order} LIMIT ?', [*fts_values, amount]).fetchall()
    return rows, len(probe) <= PROBE_LIMIT


def ranked_rows(conn, source_ids, extension, match, visible, consumed, amount, push_sources=True):
    # Rank all allowed sources together. Ranking each source independently
    # repeats BM25 work and posting-list intersections once per folder.
    scoped = '(' + match + ')'
    if push_sources:
        scoped += ' AND source_key:(' + ' OR '.join(key(source, 's') for source in source_ids) + ')'
    if extension:
        scoped += ' AND type_key:' + key(extension, 't')
    where = f'document_fts MATCH ? AND d.source_id IN ({",".join("?" for _ in source_ids)}) AND {visible}'
    values = [scoped, *source_ids]
    if extension:
        where += ' AND d.extension=?'
        values.append(extension)
    joined = 'document_fts CROSS JOIN documents d ON d.rowid=document_fts.rowid'
    probe = conn.execute(f'SELECT d.rowid FROM {joined} WHERE {where} LIMIT ?', [*values, PROBE_LIMIT + 1]).fetchall()
    if len(probe) <= PROBE_LIMIT:
        amount = max(amount, PROBE_LIMIT + 1)
    # BM25 values move for unchanged files when OCR changes corpus statistics.
    # A saved score threshold can therefore skip an entire page. Page through
    # FTS5's native ranked stream instead, before fetching catalog rows. Source
    # and type terms filter this stream, not just its final catalog join.
    rows = conn.execute(f'''SELECT d.rowid,d.id,d.source_id,d.path,d.name,d.extension,d.size,d.modified,
             d.fingerprint,d.state,d.preview,d.pages,d.attempts,page.score _rank
             FROM (SELECT rowid,rank score FROM document_fts WHERE document_fts MATCH ?
                   ORDER BY rank LIMIT ? OFFSET ?) page
             JOIN documents d ON d.rowid=page.rowid
             WHERE d.source_id IN ({','.join('?' for _ in source_ids)}) AND {visible}
             ORDER BY page.score,page.rowid''', [scoped, amount, consumed, *source_ids]).fetchall()
    return [dict(row, _stream_offset=consumed + index + 1) for index, row in enumerate(rows)], len(probe) <= PROBE_LIMIT


def global_rows(conn, source_ids, extension, sort, table, match, name_query, visible, position, amount, push_sources):
    """One posting-list intersection for searches spanning multiple folders."""
    sources = ' OR '.join(key(source, 's') for source in source_ids)
    scoped = '(' + match + ')'
    if push_sources:
        scoped += ' AND ' + ('source_key:(' + sources + ')' if table == 'document_fts' else '(' + sources + ')')
    if extension:
        scoped += ' AND ' + ('type_key:' if table == 'document_fts' else '') + key(extension, 't')
    where = f'd.source_id IN ({",".join("?" for _ in source_ids)}) AND {visible}'
    values = list(source_ids)
    if extension:
        where += ' AND d.extension=?'
        values.append(extension)
    if name_query:
        where += " AND d.name LIKE ? ESCAPE '\\'"
        values.append('%' + name_query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    if position:
        primary = 'd.name COLLATE NOCASE' if sort == 'name' else 'd.modified'
        where += f' AND ({primary},d.id) {"<" if sort == "recent" else ">"} (?,?)'
        values += [position[0], position[2]]
        if sort == 'name':
            where += ' AND d.name COLLATE NOCASE>=?'
            values.append(position[0])
    joined = f'{table} CROSS JOIN documents d ON d.rowid={table}.rowid'
    probe = conn.execute(f'SELECT d.rowid FROM {joined} WHERE {table} MATCH ? AND {where} LIMIT ?',
                         [scoped, *values, PROBE_LIMIT + 1]).fetchall()
    if not probe:
        return [], True
    complete = len(probe) <= PROBE_LIMIT
    if complete:
        amount = max(amount, PROBE_LIMIT + 1)
    columns = 'd.rowid,d.id,d.source_id,d.path,d.name,d.extension,d.size,d.modified,d.fingerprint,d.state,d.preview,d.pages,d.attempts'
    order = ','.join('d.' + part for part in SORTS[sort].split(','))
    if not complete:
        index = 'document_global_' + sort + ('_type' if extension else '')
        deadline = time.monotonic() + 1
        conn.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
        try:
            rows = conn.execute(f'''SELECT {columns},0 _rank FROM documents d INDEXED BY {index}
                WHERE {where} AND d.rowid IN (SELECT rowid FROM {table} WHERE {table} MATCH ?)
                ORDER BY {order} LIMIT ?''', [*values, scoped, amount]).fetchall()
            return rows, False
        except sqlite3.OperationalError as exc:
            if 'interrupted' not in str(exc):
                raise
        finally:
            conn.set_progress_handler(None, 0)
    rows = conn.execute(f'''SELECT {columns},0 _rank FROM {joined} WHERE {table} MATCH ? AND {where}
                           ORDER BY {order} LIMIT ?''', [scoped, *values, amount]).fetchall()
    return rows, complete
