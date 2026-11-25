"""Disposable browser fixture; AD is simulated, settings APIs are real."""
import json
import os
from pathlib import Path
import signal
import ssl
import tempfile
from types import SimpleNamespace
from app import configuration, state_db, web_security, web_ui


def main():
    with tempfile.TemporaryDirectory(prefix='domainshare-configuration-browser-') as root:
        store = configuration.Store(root)
        web_ui.CONFIG = store
        identity = {'sub':'EXAMPLE\\admin','sid':'S-1-5-21-1-2-3-1100','uid':1000,'role':'domain-admin'}
        groups = [{'sid':'S-1-5-21-1-2-3-512','name':'Domain Admins'}, {'sid':'S-1-5-21-1-2-3-513','name':'Domain Users'}]
        web_ui.authenticate_user = lambda username, password: identity if username == 'admin' and password == 'fixture-password' else None
        web_ui.current_identity = lambda sid, admin_sid=None: identity
        web_ui.directory.open_db = lambda: state_db.connect_state_db(str(Path(root) / 'shares.db'))
        tokens = web_ui.TokenManager(store.snapshot()['values']['WEB_JWT_SECRET'], 600, web_security.Sessions(str(Path(root) / 'shares.db')), identity_resolver=lambda sid: identity)
        web_ui.APP = SimpleNamespace(tokens=tokens, backup=lambda include_log=True: {'enabled':False,'manualEnabled':False,'state':'disabled','log':[]})
        web_ui.STATIC_ROOT = str(Path(__file__).resolve().parents[1] / 'app/web')
        original_exists = os.path.exists
        os.path.exists = lambda path: True if str(path) in ('/run/domainshare-domain-ready','/run/domainshare-services-ready') else original_exists(path)

        class Handler(web_ui.Handler):
            def domain_groups(self):
                return groups
            def do_POST(self):
                super().do_POST()
                if self.path == '/api/bootstrap/domain' and store.snapshot()['phase'] == 'joining':
                    store.phase('groups')

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixture = Path(__file__).parent / 'fixtures'
        context.load_cert_chain(fixture / 'web-test.crt', fixture / 'web-test.key')
        server = web_ui.ReusableHTTPServer(('127.0.0.1',0),Handler,context)
        port = server.server_address[1]
        with store.connect() as conn:
            values = store.snapshot()['values']
            values.update(WEB_HOSTNAME='files.example.test', WEB_HTTPS_PORT=str(port))
            conn.execute('UPDATE configuration SET settings=?', (json.dumps(values),))
        signal.signal(signal.SIGTERM, lambda *args: (_ for _ in ()).throw(SystemExit()))
        print(json.dumps({'port':port, 'code':store.bootstrap_code()}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
