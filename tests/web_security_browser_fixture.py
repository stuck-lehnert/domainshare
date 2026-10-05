"""Disposable HTTPS server for the sibling-subdomain browser regression."""
import json
import os
from pathlib import Path
import signal
import ssl
import tempfile
from types import SimpleNamespace

from app import documents, state_db, web_security, web_ui


def main():
    with tempfile.TemporaryDirectory(prefix='adfs-security-browser-') as root:
        path = str(Path(root) / 'state.db')
        tokens = web_ui.TokenManager('browser-fixture-secret-' * 3, 600, web_security.Sessions(path))
        web_ui.APP = SimpleNamespace(tokens=tokens)
        identity = {'sub': 'EXAMPLE\\admin', 'sid': 'S-1-5-21-1-2-3-1100', 'uid': 1000, 'role': 'domain-admin'}
        web_ui.authenticate_user = lambda name, password: identity if (name, password) == ('admin', 'fixture-password') else None
        web_ui.directory.open_db = lambda: state_db.connect_state_db(path)
        documents.SEARCH_ROOT = str(Path(root) / 'search')
        documents.SEARCH_DB = str(Path(root) / 'search' / 'search.db')
        observations = []

        class Handler(web_ui.Handler):
            def do_POST(self):
                if self.headers.get('Origin', '').startswith('https://evil.example.test:'):
                    observations.append({'cookie': bool(self.token()), 'type': self.headers.get_content_type()})
                super().do_POST()

            def do_GET(self):
                if self.path == '/test-observations':
                    self.send_json(observations)
                elif self.path == '/test-attacker':
                    body = b'<!doctype html><title>Sibling attacker</title>'
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    super().do_GET()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixture = Path(__file__).parent / 'fixtures'
        context.load_cert_chain(fixture / 'web-test.crt', fixture / 'web-test.key')
        server = web_ui.ReusableHTTPServer(('127.0.0.1', 0), Handler, context)
        port = server.server_address[1]
        os.environ['WEB_HOSTNAME'] = 'files.example.test'
        os.environ['WEB_HTTPS_PORT'] = str(port)
        os.environ['WEB_TRUSTED_ORIGINS'] = ''

        def stop(*args):
            raise SystemExit()
        signal.signal(signal.SIGTERM, stop)
        print(json.dumps({'port': port}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
