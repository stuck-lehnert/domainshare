import hashlib
import io
import http.client
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from app import backup_keys, backup_to_destination as backup, configuration, tls_configuration


LEGACY = {'REALM': 'EXAMPLE.TEST', 'WORKGROUP': 'EXAMPLE', 'DOMAIN': 'example.test',
          'JOIN_USER': 'service', 'JOIN_PASSWORD': 'old-secret',
          'DOMAIN_USERS_SID': 'S-1-5-21-1-2-3-513', 'DOMAIN_ADMINS_SID': 'S-1-5-21-1-2-3-512',
          'BACKUP_DESTINATION': 'rsync://backup:old-password@backup.test/target',
          'BACKUP_ARCHIVE_PASSWORD': 'old-archive-password'}


class RecoveryPhraseTests(unittest.TestCase):
    def test_official_bip39_vector_and_checksum(self):
        phrase = 'abandon ' * 11 + 'about'
        self.assertEqual(backup_keys.phrase_from_entropy(bytes(16)), phrase)
        expected = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
        self.assertEqual(backup_keys.seed(phrase, 'TREZOR').hex(), expected)
        with self.assertRaises(ValueError):
            backup_keys.archive_key('abandon ' * 12)
        with self.assertRaises(ValueError):
            backup_keys.archive_key('not a phrase')

    def test_generated_key_recovers_from_the_phrase(self):
        result = backup_keys.generate()
        self.assertEqual(len(result['phrase'].split()), 24)
        self.assertEqual(backup_keys.archive_key(result['phrase']), result['password'])
        self.assertEqual(len(result['keyId']), 24)
        self.assertEqual(hashlib.sha256((Path(backup_keys.__file__).parent / 'vendor/bip39/english.txt').read_bytes()).hexdigest(),
                         '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda')


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = configuration.Store(self.root)

    def test_first_launch_is_persistent_and_private(self):
        self.assertEqual(self.store.snapshot()['phase'], 'unconfigured')
        secret = self.store.snapshot()['values']['WEB_JWT_SECRET']
        code = self.store.bootstrap_code()
        self.assertEqual(configuration.Store(self.root).bootstrap_code(), code)
        self.assertEqual(configuration.Store(self.root).snapshot()['values']['WEB_JWT_SECRET'], secret)
        self.assertTrue(self.store.accepts_bootstrap(code))
        self.assertFalse(self.store.accepts_bootstrap('wrong'))
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)

    def test_import_preserves_paths_credentials_data_and_only_runs_once(self):
        original = self.root / 'important-file'
        original.write_bytes(b'production\x00fixture')
        self.assertTrue(self.store.import_legacy(LEGACY | {'GROUP_ROOT':'/data/groups', 'TLS_CA_PROVISIONER_PASSWORD':'ca-secret'}))
        snap = self.store.snapshot()
        self.assertEqual(snap['values']['GROUP_ROOT'], '/data/groups')
        self.assertEqual(snap['values']['TLS_CA_PASSWORD'], 'ca-secret')
        self.assertEqual(snap['values']['BACKUP_ARCHIVE_PASSWORD'], 'old-archive-password')
        self.assertFalse(snap['values']['BACKUP_ENCRYPTION_ENABLED'])
        self.assertFalse(self.store.accepts_bootstrap(self.store.bootstrap_code()))
        self.assertEqual(original.read_bytes(), b'production\x00fixture')
        with self.assertRaises(configuration.Conflict):
            self.store.import_legacy(LEGACY)
        public = json.dumps(self.store.public())
        for secret in ('old-secret','old-password','old-archive-password','ca-secret'):
            self.assertNotIn(secret, public)
        self.assertIn('rsync://backup.test/target', public)

    def test_resolved_container_import_preserves_literal_password_bytes(self):
        values=LEGACY | {'JOIN_PASSWORD':'literal-$VALUE-$(never-execute)-$$'}
        payload=json.dumps([key+'='+value for key,value in values.items()])
        with mock.patch.object(configuration,'Store',return_value=self.store), mock.patch.object(configuration.sys,'argv',['configuration','import-runtime']), mock.patch.object(configuration.sys,'stdin',io.StringIO(payload)), mock.patch.object(configuration.sys,'stdout',io.StringIO()):
            configuration.main()
        self.assertEqual(self.store.snapshot()['values']['JOIN_PASSWORD'],values['JOIN_PASSWORD'])
        with mock.patch.object(configuration,'Store',return_value=self.store), mock.patch.object(configuration.sys,'argv',['configuration','import-runtime']), mock.patch.object(configuration.sys,'stdin',io.StringIO('[]')), mock.patch.object(configuration.sys,'stdout',io.StringIO()):
            configuration.main()
        self.assertEqual(self.store.snapshot()['values']['JOIN_PASSWORD'],values['JOIN_PASSWORD'])

    def test_legacy_parser_never_executes_shell(self):
        marker = self.root / 'must-not-exist'
        text = 'JOIN_PASSWORD="$(touch ' + str(marker) + ')"\nWORKGROUP=EXAMPLE # comment\n'
        parsed = configuration.parse_legacy(text)
        self.assertEqual(parsed['JOIN_PASSWORD'], '$(touch ' + str(marker) + ')')
        self.assertEqual(parsed['WORKGROUP'], 'EXAMPLE')
        self.assertFalse(marker.exists())

    def test_key_owner_confirmation_expiry_and_configuration_revision(self):
        self.store.import_legacy(LEGACY)
        pending = self.store.generate_key('owner')
        with self.assertRaises(ValueError):
            self.store.activate_key('owner', pending['nonce'], False, True)
        with self.assertRaises(configuration.Conflict):
            self.store.activate_key('attacker', pending['nonce'], True, True)
        with self.assertRaises(ValueError):
            self.store.activate_key('owner', pending['nonce'], True, False)
        self.store.save({'BACKUP_START_HOUR': 3}, self.store.snapshot()['revision'])
        with self.assertRaises(configuration.Conflict):
            self.store.activate_key('owner', pending['nonce'], True, True)
        pending = self.store.generate_key('owner')
        with mock.patch.object(configuration.time, 'time', return_value=10**12):
            with self.assertRaises(configuration.Conflict):
                self.store.activate_key('owner', pending['nonce'], True, True)

    def test_rotation_preserves_old_keys_and_uses_new_destination_namespace(self):
        self.store.import_legacy(LEGACY)
        first = self.store.generate_key('owner')
        self.store.activate_key('owner', first['nonce'], True, True)
        old_password = self.store.snapshot()['values']['BACKUP_ARCHIVE_PASSWORD']
        second = self.store.generate_key('owner')
        self.store.activate_key('owner', second['nonce'], True, True)
        values = self.store.snapshot()['values']
        self.assertEqual(values['BACKUP_NAMESPACE'], 'keys/' + second['keyId'])
        self.assertNotEqual(first['keyId'], second['keyId'])
        self.assertEqual(backup_keys.archive_key(first['phrase']), old_password)
        self.assertEqual(backup_keys.archive_key(second['phrase']), values['BACKUP_ARCHIVE_PASSWORD'])
        self.assertNotIn(second['phrase'], self.store.path.read_bytes().decode(errors='ignore'))
        self.store.save({'BACKUP_ENCRYPTION_ENABLED':False}, self.store.snapshot()['revision'])
        self.assertEqual(self.store.snapshot()['values']['BACKUP_NAMESPACE'], 'plain')
        self.store.save({'BACKUP_ENCRYPTION_ENABLED':True}, self.store.snapshot()['revision'])
        self.assertEqual(self.store.snapshot()['values']['BACKUP_NAMESPACE'], 'keys/' + second['keyId'])

    def test_invalid_values_and_stale_writes_cannot_change_configuration(self):
        for name, value in [('BACKUP_DESTINATION','sftp://user:abc%0Aevil@server/path'), ('DOCUMENT_OCR_DPI',10000), ('WORKGROUP','a'*16), ('WEB_TRUSTED_ORIGINS','https://a/path')]:
            with self.assertRaises(ValueError):
                self.store.save({name:value}, 0)
        self.store.save({'BACKUP_START_HOUR': 4}, 0)
        with self.assertRaises(configuration.Conflict):
            self.store.save({'BACKUP_START_HOUR': 5}, 0)
        self.assertEqual(self.store.snapshot()['values']['BACKUP_START_HOUR'], 4)

    def test_defaults_use_the_realm_when_a_controller_hostname_is_selected(self):
        self.store.save({'REALM':'EXAMPLE.TEST','DOMAIN':'dc.example.test'},0,bootstrap=True)
        environment=self.store.environment()
        self.assertEqual(environment['LDAP_BASE_DN'],'DC=example,DC=test')
        self.assertEqual(environment['NETBIOS_NAME'], 'DOMAINSHARE')
        self.assertEqual(environment['SAMBA_HOSTNAME'], 'domainshare')
        self.assertEqual(environment['AD_DNS_NAME'], 'domainshare.example.test')

    def test_existing_samba_names_are_kept_when_the_store_is_reopened(self):
        self.store.import_legacy(LEGACY | {'NETBIOS_NAME': 'OFFICEFILES', 'SAMBA_HOSTNAME': 'officefiles'})

        environment = configuration.Store(self.store.root).environment()
        self.assertEqual(environment['NETBIOS_NAME'], 'OFFICEFILES')
        self.assertEqual(environment['SAMBA_HOSTNAME'], 'officefiles')
        self.assertEqual(environment['AD_DNS_NAME'], 'officefiles.example.test')

    def test_enabling_full_encryption_requires_a_confirmed_phrase(self):
        self.store.import_legacy(LEGACY)
        with self.assertRaises(ValueError):
            self.store.save({'BACKUP_ENCRYPTION_ENABLED':True},self.store.snapshot()['revision'])
        self.assertFalse(self.store.snapshot()['values']['BACKUP_ENCRYPTION_ENABLED'])

    def test_database_configuration_removes_stale_environment_overrides(self):
        environment = self.store.service_environment({'LDAP_URI':'ldap://old', 'JOIN_PASSWORD':'external', 'PATH':'/bin'})
        self.assertNotIn('LDAP_URI', environment)
        self.assertEqual(environment['JOIN_PASSWORD'], '')
        self.assertEqual(environment['PATH'], '/bin')

    def test_invalid_tls_pair_does_not_overwrite_existing_certificate(self):
        cert = self.root / 'tls/web.crt'
        tls_configuration.write_private(cert, 'old certificate')
        with self.assertRaises(ValueError):
            self.store.save({'WEB_TLS_MODE':'files','WEB_TLS_CERT_PEM':'invalid','WEB_TLS_KEY_PEM':'invalid'}, 0)
        self.assertEqual(cert.read_text(), 'old certificate')
        self.assertEqual(self.store.snapshot()['revision'], 0)

    def test_configuration_is_snapshotted_from_sqlite_without_live_wal_files(self):
        self.store.import_legacy(LEGACY)
        conn = sqlite3.connect(self.root / 'shares.db')
        conn.execute('CREATE TABLE fixture(value TEXT)')
        conn.execute("INSERT INTO fixture VALUES('important')")
        conn.commit(); conn.close()
        temporary, staged = backup.prepare_state_snapshot(str(self.root), str(self.root / 'shares.db'))
        self.addCleanup(shutil.rmtree, temporary)
        self.assertFalse((Path(staged) / 'configuration.db-wal').exists())
        copied = sqlite3.connect(Path(staged) / 'configuration.db')
        self.assertEqual(copied.execute('PRAGMA quick_check').fetchone()[0], 'ok')
        self.assertEqual(json.loads(copied.execute('SELECT settings FROM configuration').fetchone()[0])['JOIN_PASSWORD'], 'old-secret')
        copied.close()


@unittest.skipUnless(shutil.which('7z'), '7z is required for native encrypted recovery checks')
class EncryptedBackupTests(unittest.TestCase):
    def test_all_sources_encrypted_and_recovered_and_wrong_phrase_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            sources = []
            for name in ('private','groups','fslogix','state','samba-private'):
                source = Path(root) / name; source.mkdir()
                (source / 'confidential.txt').write_text('secret-content-' + name)
                sources.append((str(source), name))
            key = backup_keys.generate()
            temporary, staged = backup.prepare_encrypted_sources(sources, key['password'], root)
            try:
                encrypted = Path(staged[0][0])
                self.assertEqual(len(list(encrypted.glob('*.7z'))), len(sources))
                for archive in encrypted.glob('*.7z'):
                    self.assertNotIn(b'secret-content', archive.read_bytes())
                    wrong = subprocess.run(['7z','l','-pwrong',str(archive)], capture_output=True)
                    self.assertNotEqual(wrong.returncode, 0)
                    target = Path(root) / ('recovered-' + archive.stem)
                    recovery = subprocess.run(['7z','x','-o' + str(target),str(archive)], input=(backup_keys.archive_key(key['phrase'])+'\n').encode(),capture_output=True)
                    self.assertEqual(recovery.returncode, 0, recovery.stderr)
                    self.assertEqual(next(target.rglob('confidential.txt')).read_text(), 'secret-content-' + archive.stem)
            finally:
                shutil.rmtree(temporary)


class HttpOnboardingTests(unittest.TestCase):
    def setUp(self):
        from app import http_setup
        self.http_setup = http_setup
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = configuration.Store(self.temp.name)
        self.code = http_setup.setup_code(self.store)
        self.patch = mock.patch.object(http_setup.configuration, 'Store', return_value=self.store)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.server = http_setup.Server(('127.0.0.1', 0), http_setup.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start(); self.addCleanup(self.close)
        self.host = '%s:%s' % self.server.server_address

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)

    def request(self, path, method='POST', value=None, code=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            conn.request(method, path, body=json.dumps(value or {}), headers={'Content-Type':'application/json','Origin':'http://' + self.host, 'X-HTTPS-Setup-Code': self.code if code is None else code})
            response = conn.getresponse(); body = response.read()
            return response.status, body
        finally:
            conn.close()

    def test_http_exposes_no_credential_or_admin_endpoints(self):
        for path in ('/api/login','/api/bootstrap/domain','/api/bootstrap/import','/admin/api/settings','/api/bootstrap/finish'):
            self.assertEqual(self.request(path, value={'JOIN_PASSWORD':'secret'})[0], 403)
        for path in ('/admin/access','/api/bootstrap/settings','/assets/setup.js','/assets/settings.js'):
            self.assertEqual(self.request(path, method='GET')[0], 403)
        self.assertEqual(self.store.snapshot()['revision'], 0)

    def test_https_link_and_redirect_respect_external_port(self):
        status, body = self.request('/api/https/status', method='GET')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['httpsUrl'], 'https://localhost/')
        values = self.store.snapshot()['values']
        values.update(WEB_HOSTNAME='files.localhost', WEB_HTTPS_PORT='18445')
        with self.store.connect() as conn:
            conn.execute('UPDATE configuration SET settings=? WHERE id=1', (json.dumps(values),))
        status, body = self.request('/api/https/status', method='GET')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['httpsUrl'], 'https://files.localhost:18445/')
        self.assertEqual(self.store.snapshot()['phase'], 'unconfigured')
        with self.store.connect() as conn:
            conn.execute("UPDATE configuration SET phase='configured' WHERE id=1")
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            connection.request('GET', '/')
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 308)
            self.assertEqual(response.getheader('Location'), 'https://files.localhost:18445/')
        finally:
            connection.close()

    def test_https_and_http_setup_capabilities_are_separate(self):
        https_code = self.store.bootstrap_code()
        self.assertNotEqual(https_code, self.code)
        self.assertFalse(self.store.accepts_bootstrap(self.code))
        value = {'WEB_HOSTNAME':'files.example.test','ACME_CA_SERVER':'https://ca.example.test/acme/directory'}
        self.assertEqual(self.request('/api/https/configure', value=value, code=https_code)[0], 403)
        self.assertEqual(self.request('/api/https/configure', value=value)[0], 202)
        self.assertEqual(self.store.snapshot()['values']['WEB_TLS_MODE'], 'acme')
        self.assertEqual(self.store.snapshot()['phase'], 'unconfigured')

    def test_http_tls_fields_cannot_include_credentials_or_invalid_root(self):
        value = {'WEB_HOSTNAME':'files.example.test','ACME_CA_SERVER':'https://ca.example.test/acme/directory'}
        for changes in ({'JOIN_USER':'admin'}, {'JOIN_PASSWORD':'secret'}, {'BACKUP_DESTINATION':'sftp://secret@server/path'}, {'ACME_CA_SERVER':'https://user:password@server/acme'}, {'ACME_CA_CERTIFICATES_PEM':'not a certificate'}):
            self.assertEqual(self.request('/api/https/configure', value=value | changes)[0], 400)
        self.assertEqual(self.store.snapshot()['revision'], 0)

    def test_uploaded_ca_is_validated_and_persisted_for_acme(self):
        root = (Path(__file__).parent / 'fixtures/web-test.crt').read_text()
        value = {'WEB_HOSTNAME':'files.example.test','ACME_CA_SERVER':'https://ca.example.test/acme/directory','ACME_CA_CERTIFICATES_PEM':root}
        self.assertEqual(self.request('/api/https/configure', value=value)[0], 202)
        self.assertEqual(Path(self.store.environment()['ACME_CA_CERTIFICATES']).read_text().strip(), root.strip())


class SettingsAuthorizationTests(unittest.TestCase):
    def setUp(self):
        from app import web_ui, web_security, state_db
        from types import SimpleNamespace
        self.web_ui = web_ui
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.store = configuration.Store(self.temp.name)
        self.store.import_legacy(LEGACY | {'WEB_HOSTNAME':'files.example.test'})
        db = str(Path(self.temp.name) / 'shares.db')
        self.tokens = web_ui.TokenManager(self.store.snapshot()['values']['WEB_JWT_SECRET'],600,web_security.Sessions(db))
        for patch in (mock.patch.object(web_ui,'CONFIG',self.store),
                      mock.patch.object(web_ui,'APP',SimpleNamespace(tokens=self.tokens)),
                      mock.patch.object(web_ui,'lock_is_held',return_value=False),
                      mock.patch.dict(os.environ,clear=False)):
            patch.start();self.addCleanup(patch.stop)
        self.server = web_ui.ReusableHTTPServer(('127.0.0.1',0),web_ui.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.addCleanup(self.close)
        self.admin, _ = self.tokens.issue('EXAMPLE\\admin','S-1-5-21-1-2-3-1100','domain-admin',1000)
        self.user, _ = self.tokens.issue('EXAMPLE\\user','S-1-5-21-1-2-3-1101','user',1001)

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=5)

    def request(self,path,method='GET',value=None,token=None,csrf=True):
        token = self.admin if token is None else token
        headers = {'Content-Type':'application/json','Origin':'https://files.example.test'}
        if token:
            headers['Cookie'] = self.web_ui.JWT_COOKIE + '=' + token
            if csrf:headers['X-CSRF-Token'] = self.tokens.csrf(self.tokens.verify(token))
        conn = http.client.HTTPConnection(*self.server.server_address,timeout=5)
        try:
            conn.request(method,path,headers=headers,body=json.dumps(value or {}))
            response=conn.getresponse();return response.status,json.loads(response.read())
        finally:
            conn.close()

    def test_settings_and_keys_require_an_administrator_and_csrf(self):
        for token,status in (('',401),(self.user,403)):
            self.assertEqual(self.request('/admin/api/settings',token=token)[0],status)
            self.assertEqual(self.request('/admin/api/settings/backup-key/generate','POST',token=token)[0],status)
        self.assertEqual(self.request('/admin/api/settings/backup-key/generate','POST',csrf=False)[0],403)
        status,public=self.request('/admin/api/settings')
        self.assertEqual(status,200)
        self.assertNotIn('old-secret',json.dumps(public))
        with self.store.connect() as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM pending_backup_keys').fetchone()[0],0)

    def test_authenticated_save_uses_revision_and_keeps_imported_secrets(self):
        revision=self.store.snapshot()['revision']
        status,_=self.request('/admin/api/settings','POST',{'revision':revision,'values':{'BACKUP_START_HOUR':8}})
        self.assertEqual(status,200)
        self.assertEqual(self.store.snapshot()['values']['JOIN_PASSWORD'],'old-secret')
        self.assertEqual(self.request('/admin/api/settings','POST',{'revision':revision,'values':{'BACKUP_START_HOUR':9}})[0],409)
        self.assertEqual(self.store.snapshot()['values']['BACKUP_START_HOUR'],8)
