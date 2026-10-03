#!/usr/bin/env python3
"""Run document parsers in a restricted, disposable workspace, never on originals."""

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import resource
import subprocess
import sys
import warnings
import zipfile
from xml.etree import ElementTree

try:
    from .document_types import OFFICE_SUFFIXES, IMAGE_SUFFIXES
except ImportError:
    from document_types import OFFICE_SUFFIXES, IMAGE_SUFFIXES

MAX_TEXT = 2 * 1024 * 1024


def sandbox(workspace):
    """Landlock filesystem rules and seccomp prevent parser access to live data/network."""
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 1:
        raise RuntimeError('Document isolation requires Linux Landlock')
    class Ruleset(ctypes.Structure):
        _fields_ = [('fs', ctypes.c_uint64)]
    class PathRule(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('access', ctypes.c_uint64), ('fd', ctypes.c_int32)]
    handled = (1 << 13) - 1
    if abi >= 2:
        handled |= 1 << 13
    if abi >= 3:
        handled |= 1 << 14
    rules = Ruleset(handled)
    rules_fd = libc.syscall(444, ctypes.byref(rules), ctypes.sizeof(rules), 0)
    if rules_fd < 0:
        raise OSError(ctypes.get_errno(), 'Cannot create document isolation')
    read = (1 << 0) | (1 << 2) | (1 << 3)
    try:
        for path, access in [(workspace, handled), ('/usr', read), ('/lib', read), ('/lib64', read), ('/bin', read),
                             ('/etc/fonts', read), ('/etc/ghostscript', read), ('/etc/ld.so.cache', 1 << 2),
                             ('/etc/papersize', 1 << 2), ('/dev/null', (1 << 1) | (1 << 2)),
                             ('/dev/urandom', 1 << 2), ('/proc/cpuinfo', 1 << 2), ('/proc/meminfo', 1 << 2)]:
            if not os.path.exists(path):
                continue
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(access, fd)
                if libc.syscall(445, rules_fd, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), 'Cannot restrict document path')
            finally:
                os.close(fd)
        if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.syscall(446, rules_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), 'Cannot enter document isolation')
    finally:
        os.close(rules_fd)
    # Permit local IPC used by OCR workers, deny creation of internet sockets.
    socket_number = {'aarch64': 198, 'x86_64': 41}.get(platform.machine())
    if socket_number is None:
        raise RuntimeError('Unsupported document sandbox architecture')
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    filters = (Filter * 6)(Filter(0x20,0,0,0), Filter(0x15,0,3,socket_number),
                           Filter(0x20,0,0,16), Filter(0x15,1,0,1),
                           Filter(0x06,0,0,0x50000 | errno.EPERM), Filter(0x06,0,0,0x7fff0000))
    program = Program(len(filters), filters)
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'Cannot isolate document networking')


def command(args, timeout=120):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode})')
    return result.stdout.decode('utf-8', errors='replace')


def read_text(path):
    with open(path, 'rb') as handle:
        raw = handle.read(MAX_TEXT)
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16', errors='replace')
    return raw.decode('utf-8-sig', errors='replace')


def office_text(path):
    text = []
    total = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 10000 or sum(entry.file_size for entry in entries) > 64 * 1024 * 1024:
            raise RuntimeError('Office document exceeds extraction limits')
        for entry in sorted(entries, key=lambda item: item.filename):
            name = entry.filename
            wanted = (name.startswith(('word/', 'ppt/slides/')) or name == 'content.xml') and name.endswith('.xml')
            if not wanted or entry.file_size > 16 * 1024 * 1024:
                continue
            node = ElementTree.fromstring(archive.read(entry))
            fragment = ' '.join(node.itertext())
            text.append(fragment)
            total += len(fragment)
            if total > MAX_TEXT:
                break
    return '\n'.join(text)[:MAX_TEXT]


def extract(config):
    suffix = config['extension']
    source = Path('input')
    body, pages, needs_ocr = '', 0, False
    if suffix == '.pdf':
        info = command(['pdfinfo', str(source)])
        found = re.search(r'^Pages:\s*(\d+)', info, flags=re.MULTILINE)
        pages = int(found.group(1)) if found else 0
        if pages > config['max_pages']:
            raise RuntimeError('PDF exceeds page limit')
        if config['phase'] == 'ocr':
            command(['ocrmypdf', '--redo-ocr', '--output-type', 'pdf', '--optimize', '0', '--jobs', '1',
                     '--language', config['language'], '--tesseract-timeout', '120', '--skip-big', '50',
                     str(source), 'ocr.pdf'], timeout=config['timeout'] - 15)
            source = Path('ocr.pdf')
        command(['pdftotext', '-enc', 'UTF-8', '-layout', str(source), 'text.txt'])
        body = read_text('text.txt')
        if config['phase'] != 'ocr':
            image_list = command(['pdfimages', '-list', str(source)])
            has_images = bool(re.search(r'^\s*\d+\s+\d+\s+image\s', image_list, re.MULTILINE))
            page_text = body.split('\f')[:pages]
            needs_ocr = has_images and any(len(re.sub(r'\s+', '', page)) < 80 for page in page_text)
            command(['pdftoppm', '-f', '1', '-l', '1', '-singlefile', '-scale-to', '1400', '-jpeg', str(source), 'preview'])
    elif suffix in OFFICE_SUFFIXES:
        body = office_text(source)
    elif suffix in IMAGE_SUFFIXES:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = 25_000_000
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        with Image.open(source) as image:
            image.thumbnail((1400,1400))
            image.convert('RGB').save('preview.jpg', 'JPEG', quality=85)
    else:
        raise ValueError('File type is not eligible for content extraction')
    return {'body': body[:MAX_TEXT], 'pages': pages, 'needsOcr': needs_ocr}


def main():
    workspace = os.path.abspath(sys.argv[1])
    os.chdir(workspace)
    config = json.loads(Path('config.json').read_text())
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (config['timeout'], config['timeout']))
    try:
        sandbox(workspace)
        result = extract(config)
    except Exception as exc:
        result = {'error': str(exc)[:200]}
    Path('result.json').write_text(json.dumps(result))
    return 0 if 'error' not in result else 1


if __name__ == '__main__':
    sys.exit(main())
