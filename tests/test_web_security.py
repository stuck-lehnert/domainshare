import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from app import state_db, web_security, web_ui


ADMIN = {'sub': 'EXAMPLE\\admin', 'sid': 'S-1-5-21-1-2-3-1100', 'uid': 1000, 'role': 'domain-admin'}
USER = {**ADMIN, 'role': 'user'}


class SessionTests(unittest.TestCase):
    def test_logout_revocation_survives_registry_reopening_and_does_not_revoke_other_sessions(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'state.db')
            manager = web_ui.TokenManager('s' * 48, 600, web_security.Sessions(path))
            token, _ = manager.issue(ADMIN['sub'], ADMIN['sid'], ADMIN['role'], ADMIN['uid'])
            other, _ = manager.issue(ADMIN['sub'], ADMIN['sid'], ADMIN['role'], ADMIN['uid'])
            reopened = web_ui.TokenManager('s' * 48, 600, web_security.Sessions(path))
            reopened.revoke(reopened.verify(token))
            for instance in (manager, reopened, web_ui.TokenManager('s' * 48, 600, web_security.Sessions(path))):
                with self.assertRaises(ValueError):
                    instance.verify(token)
                self.assertEqual(instance.verify(other)['role'], 'domain-admin')

    def test_refresh_cannot_resurrect_a_logged_out_session(self):
        manager = web_ui.TokenManager('s' * 48, 600)
        token, _ = manager.issue(ADMIN['sub'], ADMIN['sid'], ADMIN['role'])
        payload = manager.verify(token)
        manager.revoke(payload)
        manager.sessions.refresh(payload['jti'], ADMIN, time.time())
        with self.assertRaises(ValueError):
            manager.verify(token)

    def test_unregistered_legacy_signed_jwt_is_no_longer_accepted(self):
        before = web_ui.TokenManager('s' * 48, 600)
        token, _ = before.issue(ADMIN['sub'], ADMIN['sid'], ADMIN['role'])
        after = web_ui.TokenManager('s' * 48, 600)
        with self.assertRaises(ValueError):
            after.verify(token)

    def test_origin_is_exact_and_rejects_null_credentials_paths_and_non_https(self):
        self.assertEqual(web_security.origin('https://FILES.example.test:443'), ('files.example.test', 443))
        self.assertNotEqual(web_security.origin('https://evil.example.test'), web_security.origin('https://files.example.test'))
        for value in ('null', 'http://files.example.test', 'https://files.example.test.evil.test',
                      'https://files.example.test/path', 'https://user@files.example.test', 'https://files.example.test#x',
                      'https://files.example.test:0', 'https://files.example.test:'):
            if value.endswith('.evil.test'):
                self.assertNotEqual(web_security.origin(value), ('files.example.test', 443))
            else:
                with self.assertRaises(ValueError):
                    web_security.origin(value)


class LoginLimitTests(unittest.TestCase):
    def setUp(self):
        web_ui.LOGIN_LIMIT.clear()
        self.addCleanup(web_ui.LOGIN_LIMIT.clear)
        patch = mock.patch.dict(os.environ, WEB_LOGIN_ATTEMPTS_PER_5_MIN='3', WEB_LOGIN_ACCOUNT_ATTEMPTS_PER_5_MIN='3')
        patch.start()
        self.addCleanup(patch.stop)

    def test_parallel_reservations_are_counted_before_authentication(self):
        gate = threading.Barrier(8)
        def attempt(number):
            gate.wait(timeout=5)
            return web_ui.reserve_login('127.0.0.1', f'user{number}')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            self.assertEqual(sum(workers.map(attempt, range(8))), 3)

    def test_account_limit_spans_ips_case_and_domain_login_formats(self):
        for ip, username in (('1', 'alice'), ('2', 'EXAMPLE\\ALICE'), ('3', 'Alice@example.test')):
            self.assertTrue(web_ui.reserve_login(ip, username))
        self.assertFalse(web_ui.reserve_login('4', 'alice'))
        self.assertTrue(web_ui.reserve_login('4', 'bob'))

    def test_window_expires_without_an_unbounded_stale_key_collection(self):
        with mock.patch.object(web_ui.time, 'monotonic', return_value=100):
            for number in range(3):
                self.assertTrue(web_ui.reserve_login('ip', 'alice'))
            self.assertFalse(web_ui.reserve_login('ip', 'alice'))
        with mock.patch.object(web_ui.time, 'monotonic', return_value=400):
            self.assertTrue(web_ui.reserve_login('other', 'bob'))
        self.assertNotIn(('ip', 'ip'), web_ui.LOGIN_LIMIT)


class SecurityHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / 'state.db')
        self.tokens = web_ui.TokenManager('s' * 48, 600, web_security.Sessions(self.db))
        self.app = mock.Mock(tokens=self.tokens)
        self.app.overview.return_value = {'admin': True}
        self.action = mock.Mock(return_value={'paused': True})
        for patch in (mock.patch.object(web_ui, 'APP', self.app),
                      mock.patch.object(web_ui.directory, 'open_db', side_effect=lambda: state_db.connect_state_db(self.db)),
                      mock.patch.object(web_ui.documents, 'connect', side_effect=lambda: state_db.connect_state_db(self.db)),
                      mock.patch.object(web_ui.documents, 'ensure_schema'),
                      mock.patch.object(web_ui.documents, 'control_worker', self.action),
                      mock.patch.dict(os.environ, WEB_HOSTNAME='files.example.test', WEB_HTTPS_PORT='443', WEB_TRUSTED_ORIGINS='')):
            patch.start()
            self.addCleanup(patch.stop)
        web_ui.LOGIN_LIMIT.clear()
        self.addCleanup(web_ui.LOGIN_LIMIT.clear)
        self.server = web_ui.ReusableHTTPServer(('127.0.0.1', 0), web_ui.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.token, _ = self.tokens.issue(ADMIN['sub'], ADMIN['sid'], ADMIN['role'], ADMIN['uid'])
        self.csrf = self.tokens.csrf(self.tokens.verify(self.token))

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, path='/admin/api/documents/control', method='POST', headers=None, body=None):
        request_headers = {'Content-Type': 'application/json', 'Origin': 'https://files.example.test',
                           'Cookie': f'{web_ui.JWT_COOKIE}={self.token}', 'X-CSRF-Token': self.csrf}
        request_headers.update(headers or {})
        request_headers = {key: value for key, value in request_headers.items() if value is not None}
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            conn.request(method, path, headers=request_headers, body=body if body is not None else '{"action":"pause"}')
            response = conn.getresponse()
            return response.status, dict(response.headers), json.loads(response.read())
        finally:
            conn.close()

    def test_cookie_mutations_require_exact_origin_json_and_session_bound_csrf(self):
        for headers, status in (({'Origin': 'https://evil.example.test'}, 403),
                                ({'Origin': 'null'}, 403), ({'Origin': None}, 403),
                                ({'Origin': 'https://files.example.test:8443'}, 403),
                                ({'Content-Type': 'text/plain'}, 415),
                                ({'Content-Type': 'application/x-www-form-urlencoded'}, 415),
                                ({'X-CSRF-Token': None}, 403), ({'X-CSRF-Token': 'wrong'}, 403),
                                ({'Sec-Fetch-Site': 'same-site'}, 403)):
            self.assertEqual(self.request(headers=headers)[0], status, headers)
        other, _ = self.tokens.issue(ADMIN['sub'], ADMIN['sid'], ADMIN['role'])
        self.assertEqual(self.request(headers={'X-CSRF-Token': self.tokens.csrf(self.tokens.verify(other))})[0], 403)
        self.action.assert_not_called()
        self.assertEqual(self.request(headers={'Content-Type': 'application/json; charset=utf-8'})[0], 200)
        self.action.assert_called_once()

    def test_host_and_forwarded_headers_cannot_override_configured_origin(self):
        self.assertEqual(self.request(headers={'Host': 'evil.example.test', 'Origin': 'https://evil.example.test',
                                               'X-Forwarded-Host': 'evil.example.test'})[0], 403)
        self.action.assert_not_called()

    def test_bearer_api_client_still_needs_csrf_and_foreign_origins_are_rejected(self):
        headers = {'Origin': None, 'Cookie': None, 'Authorization': 'Bearer ' + self.token}
        self.assertEqual(self.request(headers={**headers, 'X-CSRF-Token': None})[0], 403)
        self.assertEqual(self.request(headers={**headers, 'Origin': 'https://evil.example.test'})[0], 403)
        self.assertEqual(self.request(headers=headers)[0], 200)

    def test_logout_revokes_cookie_and_bearer_replays(self):
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 200)
        self.assertEqual(self.request('/api/logout', headers={'Origin': 'https://evil.example.test'})[0], 403)
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 200)
        status, headers, _ = self.request('/api/logout')
        self.assertEqual(status, 200)
        self.assertIn('Max-Age=0', headers['Set-Cookie'])
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 401)
        self.assertEqual(self.request('/admin/api/overview', method='GET', headers={
            'Cookie': None, 'Authorization': 'Bearer ' + self.token})[0], 401)
        self.assertEqual(self.request()[0], 401)
        self.action.assert_not_called()

    def test_current_ad_role_controls_all_admin_routes_and_session_response(self):
        resolver = mock.Mock(return_value=USER)
        self.tokens.identity_resolver = resolver
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 200)
        resolver.assert_not_called()
        with self.tokens.sessions.connection() as conn, conn:
            conn.execute('UPDATE web_sessions SET checked=0')
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 403)
        self.assertEqual(self.request()[0], 403)
        self.assertEqual(self.request('/api/session', method='GET')[2]['role'], 'user')
        resolver.assert_called_once_with(ADMIN['sid'])
        self.action.assert_not_called()

    def test_directory_failure_is_fail_closed(self):
        self.tokens.identity_resolver = mock.Mock(return_value=None)
        with self.tokens.sessions.connection() as conn, conn:
            conn.execute('UPDATE web_sessions SET checked=0')
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 401)
        self.assertEqual(self.request()[0], 401)
        self.action.assert_not_called()

    def test_logout_still_revokes_when_directory_is_unavailable(self):
        resolver = mock.Mock(return_value=None)
        self.tokens.identity_resolver = resolver
        with self.tokens.sessions.connection() as conn, conn:
            conn.execute('UPDATE web_sessions SET checked=0')
        self.assertEqual(self.request('/api/logout')[0], 200)
        resolver.assert_not_called()
        self.assertEqual(self.request('/admin/api/overview', method='GET')[0], 401)
        self.action.assert_not_called()

    def test_login_requires_custom_header_and_origin_check(self):
        with mock.patch.object(web_ui, 'authenticate_user', return_value=USER) as auth:
            for headers in ({'X-CSRF-Token': None}, {'X-CSRF-Token': 'login', 'Origin': 'https://evil.example.test'},
                            {'X-CSRF-Token': 'login', 'Content-Type': 'text/plain'}):
                self.assertIn(self.request('/api/login', headers=headers)[0], (403, 415))
            auth.assert_not_called()
            status, _, value = self.request('/api/login', headers={'X-CSRF-Token': 'login'}, body='{"username":"admin","password":"password"}')
        self.assertEqual(status, 200)
        self.assertEqual(value['csrfToken'], self.tokens.csrf(self.tokens.verify(value['token'])))

    def test_parallel_http_login_budget_is_reserved_before_ad_authentication(self):
        release = threading.Event()
        def authenticate(*args):
            release.wait(timeout=3)
            return None
        with mock.patch.dict(os.environ, WEB_LOGIN_ATTEMPTS_PER_5_MIN='3'), \
             mock.patch.object(web_ui, 'authenticate_user', side_effect=authenticate) as auth, \
             concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            jobs = [workers.submit(self.request, '/api/login', headers={'X-CSRF-Token': 'login'},
                                   body=json.dumps({'username': f'user{number}', 'password': 'bad'})) for number in range(8)]
            deadline = time.monotonic() + 2
            while sum(job.done() for job in jobs) < 5 and time.monotonic() < deadline:
                time.sleep(0.01)
            release.set()
            statuses = [job.result()[0] for job in jobs]
        self.assertEqual(statuses.count(401), 3)
        self.assertEqual(statuses.count(429), 5)
        self.assertEqual(auth.call_count, 3)

    def test_successful_login_does_not_clear_ip_or_other_account_attempts(self):
        with mock.patch.dict(os.environ, WEB_LOGIN_ATTEMPTS_PER_5_MIN='5', WEB_LOGIN_ACCOUNT_ATTEMPTS_PER_5_MIN='3'), \
             mock.patch.object(web_ui, 'authenticate_user', side_effect=lambda name, password: USER if name == 'own' else None):
            def login(name):
                return self.request('/api/login', headers={'X-CSRF-Token': 'login'},
                                    body=json.dumps({'username': name, 'password': 'password'}))[0]
            self.assertEqual([login(name) for name in ('victim', 'victim', 'own', 'victim', 'own')], [401, 401, 200, 401, 200])
            self.assertEqual(login('victim'), 429)
            self.assertEqual(login('another'), 429)


class TlsHandshakeTests(unittest.TestCase):
    def context(self):
        # Public test-only key; no runtime dependency on a certificate CLI.
        root = Path(__file__).parent / 'fixtures'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / 'web-test.crt', root / 'web-test.key')
        return context

    def test_silent_client_does_not_block_https_and_times_out(self):
        with mock.patch.dict(os.environ, WEB_TLS_HANDSHAKE_TIMEOUT_SECONDS='1'):
            server = web_ui.ReusableHTTPServer(('127.0.0.1', 0), web_ui.Handler, self.context())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def healthy():
                    conn = http.client.HTTPSConnection(*server.server_address, context=ssl._create_unverified_context(), timeout=1)
                    try:
                        conn.request('GET', '/healthz')
                        response = conn.getresponse()
                        self.assertEqual(response.status, 200)
                        response.read()
                    finally:
                        conn.close()
                healthy()
                with socket.create_connection(server.server_address, timeout=2) as silent:
                    healthy()
                    silent.settimeout(2)
                    self.assertEqual(silent.recv(1), b'')
                    healthy()
                # Invalid handshakes release their worker slot as well.
                for number in range(70):
                    with socket.create_connection(server.server_address, timeout=2) as invalid:
                        invalid.sendall(b'not a TLS handshake\n')
                        invalid.recv(1)
                healthy()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_connection_budget_rejects_excess_and_recovers_after_handshake_timeouts(self):
        context = self.context()
        ready = threading.Event()
        entered = []
        lock = threading.Lock()
        def wrap(*args, **kwargs):
            connection = context.wrap_socket(*args, **kwargs)
            with lock:
                entered.append(connection)
                if len(entered) == 4:
                    ready.set()
            return connection
        with mock.patch.dict(os.environ, WEB_TLS_HANDSHAKE_TIMEOUT_SECONDS='1', WEB_MAX_CONNECTIONS='4'):
            server = web_ui.ReusableHTTPServer(('127.0.0.1', 0), web_ui.Handler, mock.Mock(wrap_socket=wrap))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            clients = []
            try:
                clients = [socket.create_connection(server.server_address, timeout=2) for _ in range(4)]
                self.assertTrue(ready.wait(timeout=2))
                with socket.create_connection(server.server_address, timeout=2) as excess:
                    self.assertEqual(excess.recv(1), b'')
                self.assertEqual(len(entered), 4)
                for client in clients:
                    self.assertEqual(client.recv(1), b'')
                conn = http.client.HTTPSConnection(*server.server_address, context=ssl._create_unverified_context(), timeout=2)
                try:
                    conn.request('GET', '/healthz')
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                finally:
                    conn.close()
            finally:
                for client in clients:
                    client.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
