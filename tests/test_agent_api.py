import http.client
import json
import os
from pathlib import Path
import ssl
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlencode

from app import agent_api, web_ui
from test_documents import ADMIN, ALICE, BOB, IDENTITY, DocumentFixture


class AccountTests(unittest.TestCase):
    @mock.patch.dict(os.environ, WORKGROUP='EXAMPLE')
    def test_live_status_requires_enabled_unlocked_unexpired_real_user(self):
        entry = {
            'dn': [('CN=Alice,DC=example,DC=test', False)],
            'samaccountname': [('Alice', False)],
            'objectsid': [(ALICE, False)],
            'useraccountcontrol': [('512', False)],
            'accountexpires': [('0', False)],
        }
        with mock.patch.object(agent_api.directory, 'search_directory_entries', return_value=[entry]) as search:
            self.assertEqual(agent_api.resolve_account('EXAMPLE\\ALICE'), ALICE)
            self.assertIn('(sAMAccountName=ALICE)', search.call_args.args[0])
            for attribute, value in [('useraccountcontrol', '514'), ('accountexpires', '1'),
                                     ('msds-user-account-control-computed', '16'), ('lockouttime', '1')]:
                with self.subTest(attribute=attribute), mock.patch.dict(entry, {attribute: [(value, False)]}):
                    self.assertIsNone(agent_api.resolve_account('alice'))

            search.reset_mock()
            self.assertIsNone(agent_api.resolve_account('krbtgt'))
            with self.assertRaises(ValueError):
                agent_api.resolve_account('OTHER\\Alice')
            search.assert_not_called()


class AgentHttpsTests(DocumentFixture):
    prefix = '/api/agent/v1'
    admin_url = '/admin/api/agent-tokens'

    def setUp(self):
        super().setUp()
        self.store = agent_api.TokenStore(Path(self.temp.name))
        self.sessions = web_ui.TokenManager('s' * 48, 600)
        self.identities = {'alice': ALICE, 'bob': BOB, 'admin': ADMIN}
        app = SimpleNamespace(tokens=self.sessions, agent_tokens=self.store)
        for patch in (
            mock.patch.object(web_ui, 'APP', app),
            mock.patch.object(web_ui, 'CONFIG', None),
            mock.patch.dict(os.environ, WORKGROUP='EXAMPLE'),
            mock.patch.object(agent_api, 'resolve_account', side_effect=lambda name: self.identities.get(name.lower())),
            mock.patch.object(web_ui, 'current_identity', side_effect=self.identity),
        ):
            self.enterContext(patch)

        certs = Path(__file__).parent / 'fixtures'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certs / 'web-test.crt', certs / 'web-test.key')
        self.client_context = ssl.create_default_context(cafile=str(certs / 'web-test.crt'))
        self.client_context.check_hostname = False  # pin the fixture cert on ephemeral loopback
        self.server = web_ui.ReusableHTTPServer(('127.0.0.1', 0), web_ui.Handler, context)
        server = threading.Thread(target=self.server.serve_forever, daemon=True)
        server.start()
        self.addCleanup(server.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def identity(self, sid):
        name = next(name for name, value in self.identities.items() if value == sid)
        return dict(IDENTITY, sid=sid, sub='EXAMPLE\\' + name,
                    role='domain-admin' if sid == ADMIN else 'user')

    def session_headers(self, sid):
        identity = self.identity(sid)
        token, _ = self.sessions.issue(identity['sub'], sid, identity['role'], identity['uid'])
        return {'Authorization': 'Bearer ' + token,
                'X-CSRF-Token': self.sessions.csrf(self.sessions.verify(token))}

    def request(self, path, *, method='GET', bearer=None, headers=None, body=None):
        headers = dict(headers or {})
        if bearer:
            headers['Authorization'] = 'Bearer ' + bearer
        if body is not None:
            headers['Content-Type'] = 'application/json'
            body = json.dumps(body)

        connection = http.client.HTTPSConnection(*self.server.server_address, context=self.client_context, timeout=5)
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, response.getheader('Cache-Control'), response.read()
        finally:
            connection.close()

    def agent(self, operation, token, **query):
        return self.request(self.prefix + operation + '?' + urlencode(query), bearer=token)

    def test_management_auth_csrf_and_immediate_revocation(self):
        admin = self.session_headers(ADMIN)
        user = self.session_headers(ALICE)
        fields = {'label': 'Index agent', 'usernames': ['alice', 'EXAMPLE\\bob'], 'expiresInDays': 30}
        self.assertEqual(self.request(self.admin_url)[0], 401)
        self.assertEqual(self.request(self.admin_url, headers=user)[0], 403)
        self.assertEqual(self.request('/api/agent-tokens', headers=user)[0], 404)
        self.assertEqual(self.request(self.admin_url, method='POST', headers=user, body=fields)[0], 403)
        bad_csrf = dict(admin, **{'X-CSRF-Token': 'invalid'})
        self.assertEqual(self.request(self.admin_url, method='POST', headers=bad_csrf, body=fields)[0], 403)
        self.assertEqual(self.request(self.admin_url, method='POST', headers=admin, body=dict(fields, usernames=[]))[0], 400)

        status, cache, body = self.request(self.admin_url, method='POST', headers=admin, body=fields)
        self.assertEqual(status, 201)
        self.assertIn('no-store', cache)
        issued = json.loads(body)
        token = issued['token']
        self.assertRegex(token, agent_api.TOKEN_RE)
        self.assertTrue(self.store.path.stat().st_mode & 0o777 == 0o600)
        self.assertNotIn(token.encode(), self.store.path.read_bytes())
        status, _, body = self.request(self.admin_url, headers=admin)
        self.assertEqual(status, 200)
        self.assertNotIn(token.encode(), body)
        self.assertEqual(json.loads(body)['tokens'][0]['usernames'], ['alice', 'bob'])
        self.assertEqual(self.agent('/list', token, username='bob')[0], 200)

        self.assertEqual(self.request(self.admin_url + '/revoke', method='POST', headers=admin,
                                      body={'id': issued['id']})[0], 200)
        self.assertEqual(self.agent('/list', token, username='bob')[0], 401)

    def test_agent_token_only_username_required_case_normalized_and_no_scope_escape(self):
        token = self.store.issue('Agent', {ALICE: 'alice'}, 30, 'EXAMPLE\\admin')['token']
        web_session = self.session_headers(ALICE)['Authorization'].removeprefix('Bearer ')
        self.assertEqual(self.agent('/search', None, username='alice')[0], 401)
        self.assertEqual(self.agent('/search', web_session, username='alice')[0], 401)
        self.assertEqual(self.agent('/search', token)[0], 400)
        self.assertEqual(self.agent('/list', token, username='')[0], 400)
        self.assertEqual(self.request(self.prefix + '/list?username=alice&username=bob', bearer=token)[0], 400)
        self.assertEqual(self.agent('/search', token, username='admin')[0], 403)
        self.assertEqual(self.agent('/search', token, username='bob')[0], 403)
        self.assertEqual(self.agent('/search', token, username='EXAMPLE\\ALICE')[0], 200)
        self.assertEqual(self.request(self.admin_url, bearer=token)[0], 401)
        self.assertEqual(self.request('/api/session', bearer=token)[0], 401)
        self.assertEqual(self.request(self.prefix + '/file?username=alice', method='POST', bearer=token, body={})[0], 404)

        # Recreating the same username must not inherit an older SID's token.
        self.identities['alice'] = 'S-1-5-21-1-2-3-1200'
        self.assertEqual(self.agent('/list', token, username='alice')[0], 403)

        with self.store.connect() as conn:
            conn.execute('UPDATE agent_tokens SET expires_at=0')
        self.assertEqual(self.agent('/search', token, username='alice')[0], 401)

    def test_search_directory_paging_download_and_live_permissions(self):
        token = self.store.issue('Agent', {ALICE: 'alice'}, 30, 'EXAMPLE\\admin')['token']
        finance = 'data:' + self.folder_ids['Finance']
        engineering = 'data:' + self.folder_ids['Engineering']
        args = dict(username='alice', source=finance)

        status, _, body = self.agent('/search', token, username='alice', q='Forecast')
        self.assertEqual(status, 200)
        self.assertEqual([item['name'] for item in json.loads(body)['items']], ['forecast.docx'])
        hidden = self.document('secret.hidden')['id']
        document = self.document('forecast.docx')['id']
        self.assertEqual(self.agent(f'/documents/{hidden}/download', token, username='alice')[0], 404)
        self.assertEqual(self.agent(f'/documents/{document}/download', token, username='alice')[0], 200)
        self.assertEqual(self.agent('/list', token, username='alice', source=engineering)[0], 404)
        self.assertEqual(self.agent('/list', token, username='alice', source='private:bob')[0], 404)
        self.assertEqual(self.agent('/file', token, username='alice', source='private:alice', path='own.odt')[0], 200)

        root = self.data / 'Finance'
        self.write(root / 'A' / 'fresh.txt', 'not indexed yet')
        self.write(root / '.trash' / 'deleted.txt', 'must not be listed')
        (root / 'linked').symlink_to(self.data / 'Engineering', target_is_directory=True)
        status, _, body = self.agent('/list', token, limit=1, **args)
        self.assertEqual(status, 200)
        first = json.loads(body)
        self.assertEqual(first['items'][0]['type'], 'directory')
        self.assertEqual(first['nextAfter'], 'A')
        next_page = self.agent('/list', token, after=first['nextAfter'], limit=1, **args)
        self.assertEqual([item['name'] for item in json.loads(next_page[2])['items']], ['forecast.docx'])
        self.assertEqual(self.agent('/file', token, path='A/fresh.txt', **args)[2], b'not indexed yet')
        for path in ('../Engineering/secret.hidden', 'linked/secret.hidden', '.trash/deleted.txt'):
            self.assertEqual(self.agent('/file', token, path=path, **args)[0], 404)

        self.policy.execute('DELETE FROM folder_permissions WHERE principalId=?', (ALICE,))
        self.policy.commit()
        self.assertEqual(self.agent('/list', token, **args)[0], 404)
        self.assertEqual(self.agent('/file', token, path='A/fresh.txt', **args)[0], 404)
