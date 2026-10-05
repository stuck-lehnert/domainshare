"""HTTP exposes public HTTPS setup only; credentials always require TLS."""
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import threading
import urllib.parse
try:
    from . import configuration
    from .tls_configuration import write_private
except ImportError:
    import configuration
    from tls_configuration import write_private

APP = Path(__file__).parent
TLS_FIELDS = {'WEB_HOSTNAME', 'ACME_CA_SERVER', 'ACME_CA_CERTIFICATES_PEM'}


def setup_code(store):
    path = store.root / 'https-setup-code'
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        code = secrets.token_urlsafe(32)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return path.read_text().strip()
        with os.fdopen(fd, 'w') as handle:
            handle.write(code)
        return code


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    capacity = threading.BoundedSemaphore(32)

    def process_request(self, request, address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(10)
            super().process_request_thread(request, address)
        finally:
            self.capacity.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log setup codes, URLs or request bodies.

    def reply(self, status, value, content_type='application/json'):
        payload = json.dumps(value).encode() if content_type == 'application/json' else value
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith('/.well-known/acme-challenge/'):
            # The ACME standalone responder listens on loopback, never port 80.
            proxy = http.client.HTTPConnection('127.0.0.1', 8080, timeout=5)
            try:
                proxy.request('GET', self.path, headers={'Host': self.headers.get('Host', '')})
                response = proxy.getresponse()
                payload = response.read(16385)
                if len(payload) > 16384:
                    raise ValueError('Challenge too large')
                self.reply(response.status, payload, 'text/plain')
            except (OSError, ValueError, http.client.HTTPException):
                self.reply(404, {'error': 'Keine aktive ACME-Challenge'})
            finally:
                proxy.close()
            return
        store = configuration.Store()
        snap = store.snapshot()
        port = str(snap['values'].get('WEB_HTTPS_PORT', '443'))
        https_url = 'https://' + snap['values']['WEB_HOSTNAME'] + (':' + port if port != '443' else '') + '/'
        if path == '/api/https/status':
            try:
                progress = json.loads((store.root / 'https-status.json').read_text())
            except (OSError, ValueError):
                progress = {'state': 'waiting'}
            self.reply(200, {'state': progress.get('state'), 'message': progress.get('message', ''),
                             'hostname': snap['values']['WEB_HOSTNAME'], 'httpsUrl': https_url,
                             'configured': snap['phase'] == 'configured'})
            return
        if snap['phase'] == 'configured':
            self.send_response(308)
            self.send_header('Location', https_url)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        files = {'/': ('https-setup.html', 'text/html; charset=utf-8'),
                 '/assets/https-setup.js': ('https-setup.js', 'text/javascript; charset=utf-8'),
                 '/assets/styles.css': ('styles.css', 'text/css; charset=utf-8')}
        if path not in files:
            self.reply(403, {'error': 'Über HTTP ist ausschließlich die HTTPS-Einrichtung verfügbar'})
            return
        filename, kind = files[path]
        self.reply(200, (APP / 'web' / filename).read_bytes(), kind)

    def do_POST(self):
        store = configuration.Store()
        if self.path != '/api/https/configure' or store.snapshot()['phase'] == 'configured':
            self.reply(403, {'error': 'Über HTTP ist ausschließlich die HTTPS-Einrichtung verfügbar'})
            return
        if self.headers.get_content_type() != 'application/json' or self.headers.get('Sec-Fetch-Site') in {'same-site', 'cross-site'}:
            self.reply(403, {'error': 'Anfrage muss vom selben Origin stammen'})
            return
        if self.headers.get('Origin') != 'http://' + self.headers.get('Host', ''):
            self.reply(403, {'error': 'Ungültiger Origin'})
            return
        supplied = self.headers.get('X-HTTPS-Setup-Code', '')
        if not supplied or not hmac.compare_digest(supplied.encode(), setup_code(store).encode()):
            self.reply(403, {'error': 'Ungültiger HTTPS-Einrichtungscode'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 131072:
                raise ValueError('Ungültige Anfragelänge')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or set(body) - TLS_FIELDS:
                raise ValueError('Nur HTTPS-Hostname, ACME-Adresse und CA-Zertifikat sind zulässig')
            if not body.get('WEB_HOSTNAME') or not body.get('ACME_CA_SERVER'):
                raise ValueError('HTTPS-Hostname und ACME-Adresse sind erforderlich')
            url = urllib.parse.urlsplit(body['ACME_CA_SERVER'])
            if url.username is not None or url.password is not None:
                raise ValueError('Die HTTP-Einrichtung darf keine Zugangsdaten enthalten')
            if body.get('ACME_CA_CERTIFICATES_PEM'):
                try:
                    ssl.create_default_context().load_verify_locations(cadata=body['ACME_CA_CERTIFICATES_PEM'])
                except (ssl.SSLError, TypeError) as exc:
                    raise ValueError('CA-Zertifikat ist kein gültiges PEM-Zertifikat') from exc
            body['WEB_TLS_MODE'] = 'acme'
            snap = store.snapshot()
            store.save(body, snap['revision'], bootstrap=True)
            # Force re-issuance on an explicit retry, including a changed root CA.
            write_private(Path(store.environment()['WEB_TLS_CERT_FILE']).parent / 'bootstrap-certificate', '1')
            write_private(store.root / 'https-status.json', json.dumps({'state': 'pending', 'message': 'ACME-Zertifikat wird angefordert'}))
            self.reply(202, {'accepted': True})
        except (ValueError, TypeError, OSError) as exc:
            self.reply(400, {'error': str(exc)})


if __name__ == '__main__':
    Server(('0.0.0.0', 80), Handler).serve_forever()
