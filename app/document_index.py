#!/usr/bin/env python3
"""Durable extraction/OCR queue with immediate Linux file events and periodic recovery."""

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time

try:
    from . import documents, reconcile_shares as directory
except ImportError:
    import documents
    import reconcile_shares as directory


def log(message):
    print(f'[documents] {message}', flush=True)


def setting(name, default, minimum=1, maximum=3600):
    try:
        return min(maximum, max(minimum, int(os.getenv(name, default))))
    except ValueError:
        return default


class JobPaused(Exception):
    """Leave the durable queue unchanged when extraction is interrupted."""


def worker_state(conn, state, current=''):
    conn.execute('UPDATE document_worker SET state=?,current_id=? WHERE id=1', (state, current))
    conn.commit()


class FileEvents:
    """A separate watcher keeps metadata responsive while OCR is busy."""
    MASK = 0x00000004 | 0x00000008 | 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800
    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'inotify unavailable')
        self.watches = {}
        self.paths = {}

    def add(self, path, source='', relative=''):
        if path in self.paths:
            wd = self.paths[path]
        else:
            wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), self.MASK | 0x02000000)  # DONT_FOLLOW
            if wd < 0:
                return
            self.paths[path] = wd
        self.watches[wd] = (path, source, relative)

    def read(self, timeout=0.5):
        if not select.select([self.fd], [], [], timeout)[0]:
            return []
        try:
            data = os.read(self.fd, 1024 * 1024)
        except BlockingIOError:
            return []
        events, offset = [], 0
        while offset + 16 <= len(data):
            wd, mask, cookie, length = struct.unpack_from('iIII', data, offset)
            name = os.fsdecode(data[offset+16:offset+16+length].split(b'\0', 1)[0])
            offset += 16 + length
            if mask & 0x4000:  # Queue overflow: full rescan is mandatory.
                events.append(('', '', True))
                continue
            watch = self.watches.get(wd)
            if not watch:
                continue
            path, source, relative = watch
            if mask & 0x8000:
                self.paths.pop(path, None)
                self.watches.pop(wd, None)
            if name == '.trash':
                continue
            is_directory = bool(mask & (0x40000000 | 0x400 | 0x800 | 0x8000))
            if source and name and not is_directory:
                events.append((source, '/'.join(filter(None, (relative, name))), False))
            else:
                events.append((source, '', True))
        return events

    def close(self):
        os.close(self.fd)


def update_sources(conn):
    current = {source['id']: source for source in documents.source_inventory()}
    old = {row['id']: dict(row) for row in conn.execute('SELECT * FROM document_sources')}
    for key in old.keys() - current.keys():
        conn.execute('DELETE FROM document_sources WHERE id=?', (key,))
    new = set()
    for key, source in current.items():
        if old.get(key) != source:
            new.add(key)
            if key in old and old[key]['root'] != source['root']:
                conn.execute('DELETE FROM documents WHERE source_id=?', (key,))
            conn.execute('''INSERT INTO document_sources VALUES(:id,:kind,:label,:root,:owner_sid)
                            ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,label=excluded.label,
                            root=excluded.root,owner_sid=excluded.owner_sid''', source)
    conn.commit()
    return current, new


def watch_loop(stop):
    conn = documents.connect()
    watcher = None
    try:
        documents.ensure_schema(conn)
        try:
            watcher = FileEvents()
        except OSError:
            log('File events unavailable; using periodic scans')
        next_sources, next_scan = 0, 0
        sources = {}
        last_heartbeat = 0
        def cancelled():
            nonlocal last_heartbeat
            now = time.monotonic()
            if now - last_heartbeat >= 1:
                conn.execute('UPDATE document_worker SET heartbeat=? WHERE id=1', (time.time(),))
                conn.commit()
                last_heartbeat = now
            return stop.is_set() or documents.worker_paused(conn)
        while not stop.is_set():
            try:
                if cancelled():
                    conn.execute('UPDATE document_worker SET scanning=0 WHERE id=1')
                    conn.commit()
                    next_sources = next_scan = 0
                    stop.wait(0.5)
                    continue
                now = time.monotonic()
                full = now >= next_scan
                rescan = set()
                if now >= next_sources or full:
                    sources, added = update_sources(conn)
                    rescan.update(added)
                    next_sources = now + 2
                    if watcher:
                        for path in (directory.GROUP_ROOT, directory.PRIVATE_ROOT):
                            watcher.add(path)
                if full:
                    rescan.update(sources)
                    next_scan = now + setting('DOCUMENT_SCAN_SECONDS', 30, 2, 3600)
                changed = set()
                events = watcher.read() if watcher else []
                for source_id, relative, directory_change in events:
                    if directory_change:
                        if source_id:
                            rescan.add(source_id)
                        else:
                            next_sources = 0
                            if full or relative == '':
                                next_scan = 0
                    else:
                        changed.add((source_id, relative))
                for source_id in rescan:
                    if cancelled():
                        break
                    if source_id in sources:
                        conn.execute('UPDATE document_worker SET scanning=1 WHERE id=1')
                        conn.commit()
                        complete = documents.walk_source(conn, sources[source_id], watcher.add if watcher else None, cancelled)
                        conn.execute('UPDATE document_worker SET scanning=0,last_scan=CASE WHEN ? THEN ? ELSE last_scan END WHERE id=1', (int(complete),time.time()))
                for source_id, relative in changed:
                    if cancelled():
                        break
                    if source_id in sources and source_id not in rescan:
                        documents.discover_file(conn, sources[source_id], relative)
                conn.commit()
            except Exception as exc:
                conn.rollback()
                log(f'Catalog refresh failed: {exc}')
                stop.wait(2)
            if not watcher:
                stop.wait(1)
    finally:
        if watcher:
            watcher.close()
        conn.close()


def run_job(row, source, phase, cancelled=None):
    timeout = setting('DOCUMENT_OCR_TIMEOUT_SECONDS', 600, 30, 3600) if phase == 'ocr' else 120
    job_root = '/tmp/adfs-document-jobs'
    os.makedirs(job_root, mode=0o700, exist_ok=True)
    user = pwd.getpwnam('document-ocr')
    with tempfile.TemporaryDirectory(prefix='job-', dir=job_root) as workspace:
        # Only the extractor's own directory is traversable; the private index and
        # original trees stay inaccessible. Landlock further confines all children.
        os.chmod(job_root, 0o711)
        os.chown(workspace, user.pw_uid, user.pw_gid)
        config = {'extension': row['extension'], 'phase': phase,
                  'language': os.getenv('DOCUMENT_OCR_LANGUAGE', 'deu+eng'),
                  'max_pages': setting('DOCUMENT_MAX_PDF_PAGES', 500, 1, 5000), 'timeout': timeout}
        for name, content in [('config.json', json.dumps(config))]:
            path = os.path.join(workspace, name)
            with open(path, 'w') as handle:
                handle.write(content)
            os.chown(path, user.pw_uid, user.pw_gid)
            os.chmod(path, 0o600)
        with documents.open_file(source['root'], row['path']) as (handle, info):
            if documents.fingerprint(info) != row['fingerprint']:
                return None
            target = os.path.join(workspace, 'input')
            with open(target, 'xb') as copied:
                remaining = row['size']
                while remaining:
                    if cancelled and cancelled():
                        raise JobPaused()
                    chunk = handle.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        return None
                    copied.write(chunk)
                    remaining -= len(chunk)
                if handle.read(1):
                    return None
            if documents.fingerprint(os.fstat(handle.fileno())) != row['fingerprint']:
                return None
            os.chown(target, user.pw_uid, user.pw_gid)
            os.chmod(target, 0o400)
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': workspace,
               'TMPDIR': workspace, 'OMP_THREAD_LIMIT': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
        script = str(Path(__file__).with_name('extract_document.py'))
        process = subprocess.Popen([sys.executable, script, workspace], user=user.pw_uid, group=user.pw_gid,
                                   extra_groups=[], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True, umask=0o077)
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if cancelled and cancelled():
                    raise JobPaused()
                if time.monotonic() >= deadline:
                    raise RuntimeError('Extraction timed out')
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            # OCR child processes must not survive cancellation or a parser exit.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        with documents.open_file(workspace, 'result.json') as (handle, info):
            if info.st_size > documents.MAX_TEXT * 6 + 4096:
                raise RuntimeError('Extraction response too large')
            result = json.load(handle)
        if process.returncode or result.get('error'):
            raise RuntimeError(result.get('error', 'Extraction failed'))
        result['preview'] = ''
        with documents.open_file(source['root'], row['path']) as (_, info):
            if documents.fingerprint(info) != row['fingerprint']:
                return None
        if os.path.isfile(os.path.join(workspace, 'preview.jpg')):
            with documents.open_file(workspace, 'preview.jpg') as (handle, info):
                if info.st_size > 16 * 1024 * 1024 or handle.read(2) != b'\xff\xd8':
                    raise RuntimeError('Invalid preview')
                handle.seek(0)
                previews = os.path.join(documents.SEARCH_ROOT, 'previews')
                os.makedirs(previews, mode=0o700, exist_ok=True)
                name = uuid_name(row)
                with os.fdopen(os.open(os.path.join(previews, name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'wb') as output:
                    shutil.copyfileobj(handle, output)
                os.chmod(os.path.join(previews, name), 0o600)
                result['preview'] = name
        return result


def uuid_name(row):
    return hashlib.sha256((row['id'] + row['fingerprint']).encode()).hexdigest()[:32] + '.jpg'


def process_next(conn, prefer_ocr=False, stop=None):
    if documents.worker_paused(conn):
        worker_state(conn, 'paused')
        return False
    priority = "CASE state WHEN 'ocr' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END" if prefer_ocr else "CASE state WHEN 'pending' THEN 0 WHEN 'ocr' THEN 1 ELSE 2 END"
    row = conn.execute(f"SELECT * FROM documents WHERE state IN ('pending','ocr','failed') AND retry_at<=? ORDER BY {priority},modified DESC LIMIT 1", (time.time(),)).fetchone()
    if row is None:
        worker_state(conn, 'idle')
        return False
    source = conn.execute('SELECT * FROM document_sources WHERE id=?', (row['source_id'],)).fetchone()
    if source is None:
        return False
    phase = 'ocr' if row['state'] == 'ocr' else 'text'
    source_label = source['label'] + (' / ' + source['id'][8:] if source['kind'] == 'private' else '')
    worker_state(conn, phase, row['id'])
    supported = documents.CONTENT_SUFFIXES | documents.IMAGE_SUFFIXES
    if row['extension'] not in supported or row['size'] > setting('DOCUMENT_MAX_FILE_MB', 512, 1, 4096) * 1024 * 1024:
        conn.execute("UPDATE documents SET body='',state='name-only',pages=0,attempts=0,retry_at=0,indexed_at=? WHERE id=? AND fingerprint=?", (time.time(), row['id'], row['fingerprint']))
        conn.commit()
        worker_state(conn, 'idle')
        return True
    documents.worker_event(conn, phase, row['path'], source_label)
    conn.commit()
    try:
        result = run_job(row, source, phase, lambda: documents.worker_paused(conn) or (stop and stop.is_set()))
        if result is None:
            documents.discover_file(conn, source, row['path'])
            documents.worker_event(conn, 'changed', row['path'], source_label)
        else:
            content = row['extension'] in documents.CONTENT_SUFFIXES
            state = ('ocr' if row['extension'] == '.pdf' and result.get('needsOcr') else 'ready') if content else 'name-only'
            conn.execute('''UPDATE documents SET body=?,state=?,pages=?,preview=CASE WHEN ?='' THEN preview ELSE ? END,
                            indexed_at=?,attempts=0,retry_at=0 WHERE id=? AND fingerprint=?''',
                         (str(result.get('body', ''))[:documents.MAX_TEXT] if content else '', state, result.get('pages', 0),
                          result.get('preview', ''), result.get('preview', ''), time.time(), row['id'], row['fingerprint']))
            documents.worker_event(conn, 'queued-ocr' if state == 'ocr' else 'complete', row['path'], source_label)
            conn.execute('UPDATE document_worker SET processed=processed+1 WHERE id=1')
    except JobPaused:
        documents.worker_event(conn, 'interrupted', row['path'], source_label)
        conn.commit()
        worker_state(conn, 'paused' if documents.worker_paused(conn) else 'idle')
        return False
    except Exception as exc:
        attempts = row['attempts'] + 1
        # Preserve the OCR phase across retries and process restarts.
        retry_state = 'ocr' if phase == 'ocr' else 'failed'
        conn.execute('UPDATE documents SET state=?,attempts=?,retry_at=? WHERE id=? AND fingerprint=?',
                     (retry_state, attempts, time.time() + min(3600, 30 * 2**min(attempts,7)), row['id'], row['fingerprint']))
        log(f'Extraction deferred for {row["id"]}: {exc}')
        documents.worker_event(conn, 'failed', row['path'], source_label, message=exc)
    conn.commit()
    worker_state(conn, 'idle')
    return True


def main():
    conn = documents.connect()
    documents.ensure_schema(conn)
    lock = open(os.path.join(documents.SEARCH_ROOT, 'worker.lock'), 'a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    worker_state(conn, 'paused' if documents.worker_paused(conn) else 'idle')
    documents.worker_event(conn, 'started')
    conn.commit()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    watcher = threading.Thread(target=watch_loop, args=(stop,), name='document-watcher', daemon=True)
    watcher.start()
    log('Watching Data and Private; extraction queue is ready')
    processed = 0
    try:
        while not stop.is_set():
            try:
                # Give scans regular turns while native files are initially indexed.
                processed += 1
                if not process_next(conn, prefer_ocr=processed % 5 == 0, stop=stop):
                    stop.wait(0.5)
            except sqlite3.Error as exc:
                conn.rollback()
                log(f'Queue retry: {exc}')
                stop.wait(1)
    finally:
        stop.set()
        watcher.join(timeout=3)
        conn.close()
        lock.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
