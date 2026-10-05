"""Provision persistent bootstrap TLS and validate uploaded certificate pairs."""
import os
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

def write_private(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.tls-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def validate_pair(cert, key):
    with tempfile.TemporaryDirectory() as root:
        cert_path, key_path = Path(root) / 'cert', Path(root) / 'key'
        write_private(cert_path, cert)
        write_private(key_path, key)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
        except (OSError, ssl.SSLError) as exc:
            raise ValueError('Zertifikat und privater Schlüssel sind ungültig oder passen nicht zusammen') from exc

def prepare(store):
    values = store.snapshot()['values']
    environment = store.environment()
    cert = Path(environment['WEB_TLS_CERT_FILE'])
    key = Path(environment['WEB_TLS_KEY_FILE'])
    mode = values['WEB_TLS_MODE']
    marker = cert.parent / 'bootstrap-certificate'
    identity_path = cert.parent / 'configuration.json'
    identity = {'hostname': values['WEB_HOSTNAME'], 'mode': mode}
    try:
        previous = json.loads(identity_path.read_text())
    except (OSError, ValueError):
        previous = None
    if mode == 'files' and values.get('WEB_TLS_CERT_PEM') and values.get('WEB_TLS_KEY_PEM'):
        validate_pair(values['WEB_TLS_CERT_PEM'], values['WEB_TLS_KEY_PEM'])
        if not cert.exists() or cert.read_text() != values['WEB_TLS_CERT_PEM'] or not key.exists() or key.read_text() != values['WEB_TLS_KEY_PEM']:
            write_private(key, values['WEB_TLS_KEY_PEM'])
            write_private(cert, values['WEB_TLS_CERT_PEM'])
        marker.unlink(missing_ok=True)
        write_private(identity_path, json.dumps(identity))
        return
    if cert.is_file() and key.is_file() and (previous is None or previous == identity):
        valid = True
        try:
            validate_pair(cert.read_text(), key.read_text())
            expired = ssl.cert_time_to_seconds(ssl._ssl._test_decode_cert(str(cert))['notAfter']) <= time.time() + 86400 * 7
        except (OSError, ValueError, ssl.SSLError):
            valid = False
            expired = True
        if valid and (not expired or mode != 'self-signed'):
            write_private(identity_path, json.dumps(identity))
            return
    cert.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    hostname = values['WEB_HOSTNAME'] or 'localhost'
    with tempfile.TemporaryDirectory(dir=cert.parent) as root:
        generated_cert, generated_key = Path(root) / 'cert', Path(root) / 'key'
        command = ['step', 'certificate', 'create', hostname, str(generated_cert), str(generated_key),
                   '--profile', 'self-signed', '--subtle', '--no-password', '--insecure', '--not-after', '8760h',
                   '--san', 'localhost', '--san', '127.0.0.1', '--san', hostname, '--san', socket.gethostname()]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        write_private(key, generated_key.read_text())
        write_private(cert, generated_cert.read_text())
    write_private(marker, '1')
    write_private(identity_path, json.dumps(identity))
