"""Persistent application settings. Environment input is imported only once."""
import argparse
import contextlib
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import ssl
import sys
import time
import urllib.parse

try:
    from . import backup_keys
except ImportError:
    import backup_keys

ROOT = Path('/state')
SID = re.compile(r'S-\d+(?:-\d+)+')
DNS = re.compile(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?')


def field(section, label, default='', kind='text', minimum=None, maximum=None, **extra):
    return dict(section=section, label=label, default=default, kind=kind, minimum=minimum, maximum=maximum, **extra)


FIELDS = {
    'REALM': field('domain', 'Kerberos-Domäne', kind='dns', required=True),
    'WORKGROUP': field('domain', 'NetBIOS-Domäne', kind='netbios', required=True),
    'DOMAIN': field('domain', 'Domänencontroller / AD-DNS-Name', kind='dns', required=True),
    'JOIN_USER': field('domain', 'Konto für Domänenbeitritt und LDAP'),
    'JOIN_PASSWORD': field('domain', 'Passwort für Domänenbeitritt und LDAP', kind='secret'),
    'LDAP_URI': field('domain', 'LDAP-Adresse (optional)', kind='ldap'),
    'LDAP_BASE_DN': field('domain', 'LDAP-Basis-DN (optional)'),
    'DOMAIN_USERS_SID': field('groups', 'Benutzergruppe', kind='group', required=True),
    'DOMAIN_ADMINS_SID': field('groups', 'Administratorengruppe', kind='group', required=True),
    'FSLOGIX_GROUP_SID': field('groups', 'FSLogix-Gruppe', kind='group', required=True),
    'NETBIOS_NAME': field('network', 'Servername (NetBIOS)', 'DOMAINSHARE', 'netbios'),
    'SAMBA_HOSTNAME': field('network', 'Servername (DNS)', 'domainshare', 'dns'),
    'AD_DNS_NAME': field('network', 'AD-DNS-Eintrag (optional)', kind='dns'),
    'AD_DNS_IP': field('network', 'IP-Adresse für AD-DNS-Eintrag (optional)', kind='ip'),
    'WEB_HOSTNAME': field('tls', 'HTTPS-Hostname', 'localhost', 'dns'),
    'WEB_TLS_MODE': field('tls', 'HTTPS-Zertifikat', 'self-signed', 'choice', choices=['self-signed', 'acme', 'ca', 'files']),
    'WEB_TLS_AUTORENEW': field('tls', 'Zertifikate automatisch erneuern', True, 'bool'),
    'ACME_CA_SERVER': field('tls', 'ACME-Verzeichnisadresse', kind='https'),
    'ACME_CA_CERTIFICATES_PEM': field('tls', 'CA-Vertrauenszertifikat (PEM)', kind='pem'),
    'ACME_CA_CERTIFICATES_URL': field('tls', 'Adresse für CA-Vertrauenszertifikat (optional)', kind='https'),
    'ACME_CA_CERTIFICATES_INSECURE_DOWNLOAD': field('tls', 'CA-Download ohne Zertifikatsprüfung', False, 'bool'),
    'ACME_RENEW_CHECK_SECONDS': field('tls', 'Erneuerung prüfen (Sekunden)', 900, 'int', 60, 86400),
    'TLS_CA_URL': field('tls', 'CA-Adresse', kind='https'),
    'TLS_CA_ROOT_PEM': field('tls', 'CA-Wurzelzertifikat (PEM)', kind='pem'),
    'TLS_CA_FINGERPRINT': field('tls', 'CA-Fingerabdruck'),
    'TLS_CA_PROVISIONER': field('tls', 'CA-Provisioner'),
    'TLS_CA_TOKEN': field('tls', 'CA-Einrichtungstoken', kind='secret'),
    'TLS_CA_PASSWORD': field('tls', 'CA-Provisioner-Passwort', kind='secret'),
    'WEB_TLS_CERT_PEM': field('tls', 'HTTPS-Zertifikat (PEM)', kind='pem'),
    'WEB_TLS_KEY_PEM': field('tls', 'Privater HTTPS-Schlüssel (PEM)', kind='secretpem'),
    'WEB_TRUSTED_ORIGINS': field('web', 'Weitere HTTPS-Origins (kommagetrennt)', kind='origins'),
    'WEB_JWT_TTL_SECONDS': field('web', 'Sitzungsdauer (Sekunden)', 28800, 'int', 300, 604800),
    'WEB_AUTH_RECHECK_SECONDS': field('web', 'AD-Rechte erneut prüfen (Sekunden)', 60, 'int', 5, 300),
    'WEB_LOGIN_ATTEMPTS_PER_5_MIN': field('web', 'Anmeldeversuche pro IP / 5 Minuten', 10, 'int', 3, 100),
    'WEB_LOGIN_ACCOUNT_ATTEMPTS_PER_5_MIN': field('web', 'Anmeldeversuche pro Konto / 5 Minuten', 10, 'int', 3, 100),
    'WEB_TLS_HANDSHAKE_TIMEOUT_SECONDS': field('web', 'TLS-Handshake-Zeitlimit (Sekunden)', 5, 'int', 1, 30),
    'WEB_REQUEST_TIMEOUT_SECONDS': field('web', 'Anfrage-Zeitlimit (Sekunden)', 30, 'int', 1, 300),
    'WEB_MAX_CONNECTIONS': field('web', 'Gleichzeitige Web-Verbindungen', 64, 'int', 4, 512),
    'WEB_USAGE_SCAN_INTERVAL_SECONDS': field('web', 'Belegung erfassen (Sekunden)', 900, 'int', 10, 86400),
    'WEB_DIRECTORY_CACHE_SECONDS': field('web', 'AD-Verzeichniszwischenspeicher (Sekunden)', 300, 'int', 5, 3600),
    'PRIVATE_SKIP_USERS': field('files', 'Private Ordner: ausgeschlossene Benutzer (kommagetrennt)'),
    'PRIVATE_SKIP_PREFIXES': field('files', 'Private Ordner: ausgeschlossene Präfixe (kommagetrennt)'),
    'TRASH_RETENTION_DAYS': field('files', 'Papierkorb aufbewahren (Tage)', 7, 'int', 1, 365),
    'AUDIT_SKIP_USER_SUFFIXES': field('files', 'Protokoll: ausgeschlossene Kontosuffixe', '_svc,_ServiceAcc'),
    'AUDIT_QUERY_MAX_DAYS': field('files', 'Protokoll: größter Suchzeitraum (Tage)', 31, 'int', 1, 366),
    'DOCUMENT_SCAN_SECONDS': field('documents', 'Dateien erneut erfassen (Sekunden)', 30, 'int', 5, 3600),
    'DOCUMENT_OCR_LANGUAGE': field('documents', 'OCR-Sprachen', 'deu+eng', 'languages'),
    'DOCUMENT_OCR_TIMEOUT_SECONDS': field('documents', 'OCR-Auftrag-Zeitlimit (Sekunden)', 600, 'int', 30, 3600),
    'DOCUMENT_OCR_DPI': field('documents', 'OCR-Auflösung (DPI)', 300, 'int', 150, 400),
    'DOCUMENT_OCR_MAX_DIMENSION': field('documents', 'OCR: größte Bildkante (Pixel)', 3500, 'int', 1500, 5000),
    'DOCUMENT_OCR_PAGE_TIMEOUT_SECONDS': field('documents', 'OCR-Seiten-Zeitlimit (Sekunden)', 30, 'int', 5, 120),
    'DOCUMENT_MAX_FILE_MB': field('documents', 'Größte Datei für Texterfassung (MiB)', 512, 'int', 1, 4096),
    'DOCUMENT_MAX_PDF_PAGES': field('documents', 'Größte PDF-Seitenzahl', 500, 'int', 1, 5000),
    'BACKUP_DESTINATION': field('backup', 'Sicherungsziel', kind='secreturl'),
    'BACKUP_AUTO_ENABLED': field('backup', 'Automatische Sicherungen', False, 'bool'),
    'BACKUP_START_HOUR': field('backup', 'Tägliche Startzeit (Stunde, UTC)', 2, 'int', 0, 23),
    'BACKUP_RETENTION_DAILY': field('backup', 'Tägliche Sicherungen aufbewahren', 3, 'int', 0, 10000),
    'BACKUP_RETENTION_WEEKLY': field('backup', 'Wöchentliche Sicherungen aufbewahren', 2, 'int', 0, 10000),
    'BACKUP_RETENTION_MONTHLY': field('backup', 'Monatliche Sicherungen aufbewahren', 2, 'int', 0, 10000),
    'BACKUP_RETENTION_YEARLY': field('backup', 'Jährliche Sicherungen aufbewahren', 1, 'int', 0, 10000),
    'BACKUP_ENCRYPTION_ENABLED': field('backup', 'Alle Sicherungsdaten verschlüsseln', True, 'bool'),
    'BACKUP_PROGRESS_INTERVAL_SECONDS': field('backup', 'Fortschritt erfassen (Sekunden)', 10, 'int', 1, 300),
}
PRIVATE_FIELDS = {'WEB_JWT_SECRET', 'BACKUP_ARCHIVE_PASSWORD', 'BACKUP_KEY_ID', 'BACKUP_KEY_FORMAT',
                  'BACKUP_NAMESPACE', 'STATE_DB_PATH', 'SHARE_DB_PATH', 'STATE_ROOT', 'GROUP_ROOT',
                  'GROUP_ARCHIVE_ROOT', 'PRIVATE_ROOT', 'FSLOGIX_ROOT', 'DOCUMENT_STATE_ROOT',
                  'RECONCILE_STATUS_FILE', 'RECONCILE_LOG_FILE', 'BACKUP_STATUS_FILE', 'BACKUP_LOG_FILE',
                  'BACKUP_ARCHIVE_TEMP_DIR', 'WEB_TLS_CERT_FILE', 'WEB_TLS_KEY_FILE', 'ACME_CA_CERTIFICATES',
                  'TLS_CA_ROOT', 'TLS_CA_PROVISIONER_PASSWORD', 'TLS_CA_PROVISIONER_PASSWORD_FILE', 'AUDIT_SOURCE_GLOB', 'AUDIT_ARCHIVE_DIR', 'AUDIT_POLL_SECONDS',
                  'TLS_CA_STATE_DIR', 'TLS_CA_REBOOTSTRAP', 'BACKUP_PROGRESS',
                  'WEB_HTTPS_PORT', 'WEB_BIND_PORT', 'WEB_BIND_ADDRESS', 'ACME_HTTP_LISTEN'}
SECTIONS = {'domain': 'Active Directory', 'groups': 'Gruppen für Anmeldung und Systemzugriff',
            'network': 'Server und DNS', 'tls': 'HTTPS und Zertifikate', 'web': 'Web-Zugriff',
            'files': 'Dateien und Protokolle', 'documents': 'Dokumentindex und OCR', 'backup': 'Sicherungen'}


def validate(name, value):
    spec = FIELDS[name]
    kind = spec['kind']
    if kind == 'bool':
        if value in (True, 'true', '1', 1):
            return True
        if value in (False, 'false', '0', 0):
            return False
        raise ValueError(spec['label'] + ': ungültiger Schalter')
    if kind == 'int':
        if isinstance(value, bool) or not re.fullmatch(r'\d+', str(value)):
            raise ValueError(spec['label'] + ': ganze Zahl erforderlich')
        value = int(value)
        if not spec['minimum'] <= value <= spec['maximum']:
            raise ValueError(spec['label'] + ': Wert außerhalb des zulässigen Bereichs')
        return value
    if not isinstance(value, str) or len(value) > (65536 if 'pem' in kind else 4096):
        raise ValueError(spec['label'] + ': ungültiger Wert')
    if '\0' in value or ('pem' not in kind and any(char in value for char in '\r\n')):
        raise ValueError(spec['label'] + ': ungültige Steuerzeichen')
    if kind not in ('secret', 'secretpem'):
        value = value.strip()
    if not value:
        return value
    if kind == 'dns' and not DNS.fullmatch(value):
        raise ValueError(spec['label'] + ': ungültiger DNS-Name')
    if kind == 'netbios' and not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', value):
        raise ValueError(spec['label'] + ': höchstens 15 Buchstaben/Ziffern, _ oder -')
    if kind == 'group' and not SID.fullmatch(value):
        raise ValueError(spec['label'] + ': ungültige Gruppen-SID')
    if kind == 'ip':
        ipaddress.ip_address(value)
    if kind == 'languages' and not re.fullmatch(r'[a-z]{3}(?:\+[a-z]{3})*', value):
        raise ValueError('Ungültige OCR-Sprachen')
    if kind == 'choice' and value not in spec['choices']:
        raise ValueError(spec['label'] + ': ungültige Auswahl')
    if name in ('ACME_CA_CERTIFICATES_PEM', 'TLS_CA_ROOT_PEM'):
        try:
            ssl.create_default_context().load_verify_locations(cadata=value)
        except ssl.SSLError as exc:
            raise ValueError(spec['label'] + ': ungültiges PEM-Zertifikat') from exc
    if kind in ('https', 'ldap', 'secreturl'):
        parsed = urllib.parse.urlsplit(value)
        allowed = {'https'} if kind == 'https' else {'ldap', 'ldaps'} if kind == 'ldap' else {'rsync', 'sftp', 'smb', 'cifs', 'davfs', 'dav', 'webdav', 'https', 'http'}
        if parsed.scheme not in allowed or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError(spec['label'] + ': ungültige Adresse')
        if kind == 'https' and (parsed.username is not None or parsed.password is not None):
            raise ValueError(spec['label'] + ': Zugangsdaten in dieser Adresse sind nicht zulässig')
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError(spec['label'] + ': ungültiger Port')
        if any(char in urllib.parse.unquote(value) for char in '\r\n\0'):
            raise ValueError(spec['label'] + ': ungültige Steuerzeichen in der Adresse')
    if kind == 'origins':
        try:
            from .web_security import origin
        except ImportError:
            from web_security import origin
        for item in value.split(','):
            origin(item.strip())
    return value


class Conflict(ValueError):
    pass


class Store:
    def __init__(self, root=ROOT):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / 'configuration.db'
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with self.connect() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS configuration (
                id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, phase TEXT NOT NULL,
                service_revision INTEGER NOT NULL, settings TEXT NOT NULL)''')
            defaults = {name: spec['default'] for name, spec in FIELDS.items()}
            defaults['WEB_JWT_SECRET'] = secrets.token_urlsafe(48)
            conn.execute('INSERT OR IGNORE INTO configuration VALUES(1,0,?,0,?)', ('unconfigured', json.dumps(defaults)))
            conn.execute('''CREATE TABLE IF NOT EXISTS pending_backup_keys (
                nonce TEXT PRIMARY KEY, owner TEXT NOT NULL, expires REAL NOT NULL, revision INTEGER NOT NULL,
                password TEXT NOT NULL, key_id TEXT NOT NULL, format TEXT NOT NULL)''')
            conn.execute('CREATE TABLE IF NOT EXISTS scheduled_backups (slot TEXT PRIMARY KEY)')

    @contextlib.contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def snapshot(self):
        with self.connect() as conn:
            row = dict(conn.execute('SELECT * FROM configuration WHERE id=1').fetchone())
        row['values'] = json.loads(row.pop('settings'))
        return row

    def public(self, section=None):
        snap = self.snapshot()
        result = {'revision': snap['revision'], 'phase': snap['phase'], 'sections': [],
                  'encryption': {'keyId': snap['values'].get('BACKUP_KEY_ID', ''),
                                 'legacy': bool(snap['values'].get('BACKUP_ARCHIVE_PASSWORD') and not snap['values'].get('BACKUP_KEY_ID'))}}
        for name, label in SECTIONS.items():
            if section and section != name:
                continue
            fields = []
            for key, spec in FIELDS.items():
                if spec['section'] != name:
                    continue
                value = snap['values'].get(key, spec['default'])
                secret = spec['kind'] in ('secret', 'secretpem', 'secreturl')
                fields.append(dict(spec, key=key, value='' if secret else value, configured=bool(value) if secret else False))
                if spec['kind'] == 'secreturl' and value:
                    url = urllib.parse.urlsplit(value)
                    fields[-1]['summary'] = urllib.parse.urlunsplit((url.scheme, url.hostname + (':' + str(url.port) if url.port else ''), url.path, '', ''))
            result['sections'].append({'id': name, 'label': label, 'fields': fields})
        return result

    def save(self, changes, revision, *, bootstrap=False):
        if not isinstance(changes, dict) or any(name not in FIELDS for name in changes):
            raise ValueError('Unbekannte Einstellung')
        normalized = {name: validate(name, value) for name, value in changes.items()}
        if not bootstrap and any(name in normalized for name in ('REALM', 'WORKGROUP')):
            current = self.snapshot()['values']
            if any(normalized[name] != current[name] for name in ('REALM', 'WORKGROUP') if name in normalized):
                raise ValueError('Ein Wechsel der AD-Domäne erfordert einen erneuten Domänenbeitritt')
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            snap = dict(conn.execute('SELECT * FROM configuration WHERE id=1').fetchone())
            if revision != snap['revision']:
                raise Conflict('Einstellungen wurden inzwischen geändert; bitte erneut laden')
            values = json.loads(snap['settings'])
            values.update(normalized)
            if values['WEB_TLS_MODE'] == 'files' and not (values.get('WEB_TLS_CERT_PEM') and values.get('WEB_TLS_KEY_PEM')) and not (values.get('WEB_TLS_CERT_FILE') and values.get('WEB_TLS_KEY_FILE')):
                raise ValueError('Bitte HTTPS-Zertifikat und privaten Schlüssel gemeinsam hochladen')
            if 'BACKUP_ENCRYPTION_ENABLED' in normalized and values.get('BACKUP_KEY_ID'):
                values['BACKUP_NAMESPACE'] = 'keys/' + values['BACKUP_KEY_ID'] if values['BACKUP_ENCRYPTION_ENABLED'] else 'plain'
            if values['BACKUP_DESTINATION'] and values['BACKUP_ENCRYPTION_ENABLED'] and not values.get('BACKUP_KEY_ID'):
                raise ValueError('Bitte zuerst eine Wiederherstellungsphrase erzeugen und bestätigen')
            if values['WEB_TLS_MODE'] == 'files' and (values.get('WEB_TLS_CERT_PEM') or values.get('WEB_TLS_KEY_PEM')):
                try:
                    from .tls_configuration import validate_pair
                except ImportError:
                    from tls_configuration import validate_pair
                validate_pair(values['WEB_TLS_CERT_PEM'], values['WEB_TLS_KEY_PEM'])
            previous = json.loads(snap['settings'])
            if values == previous:
                return self.public()
            service_change = any(FIELDS[key]['section'] != 'backup' and (not bootstrap or FIELDS[key]['section'] != 'groups') and values[key] != previous.get(key) for key in normalized)
            conn.execute('UPDATE configuration SET settings=?,revision=revision+1,service_revision=service_revision+? WHERE id=1',
                         (json.dumps(values), int(service_change)))
        return self.public()

    def phase(self, value):
        with self.connect() as conn:
            conn.execute('UPDATE configuration SET phase=?,revision=revision+1 WHERE id=1', (value,))

    def bootstrap_code(self):
        path = self.root / 'setup-code'
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

    def accepts_bootstrap(self, supplied):
        return self.snapshot()['phase'] != 'configured' and bool(supplied) and hmac.compare_digest(supplied.encode(), self.bootstrap_code().encode())

    def finish(self, revision):
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT * FROM configuration WHERE id=1').fetchone()
            if row['revision'] != revision:
                raise Conflict('Einstellungen wurden inzwischen geändert')
            values = json.loads(row['settings'])
            required = ('REALM', 'WORKGROUP', 'DOMAIN', 'DOMAIN_USERS_SID', 'DOMAIN_ADMINS_SID', 'FSLOGIX_GROUP_SID')
            if any(not values.get(key) for key in required):
                raise ValueError('Domäne und Gruppen müssen vollständig eingerichtet sein')
            conn.execute("UPDATE configuration SET phase='configured',revision=revision+1,service_revision=service_revision+1 WHERE id=1")
        (self.root / 'setup-code').unlink(missing_ok=True)

    def generate_key(self, owner):
        result = backup_keys.generate()
        nonce = secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute('DELETE FROM pending_backup_keys WHERE expires<?', (time.time(),))
            revision = conn.execute('SELECT revision FROM configuration WHERE id=1').fetchone()[0]
            conn.execute('INSERT INTO pending_backup_keys VALUES(?,?,?,?,?,?,?)',
                         (nonce, owner, time.time() + 900, revision, result['password'], result['keyId'], result['format']))
        return {key: result[key] for key in ('phrase', 'keyId', 'format')} | {'nonce': nonce}

    def activate_key(self, owner, nonce, written_down, acknowledge_old):
        if written_down is not True:
            raise ValueError('Bitte bestätigen, dass die Phrase sicher notiert wurde')
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            pending = conn.execute('SELECT * FROM pending_backup_keys WHERE nonce=? AND owner=? AND expires>?', (nonce, owner, time.time())).fetchone()
            current = conn.execute('SELECT * FROM configuration WHERE id=1').fetchone()
            if not pending or pending['revision'] != current['revision']:
                raise Conflict('Schlüsselerzeugung ist abgelaufen oder Einstellungen wurden geändert')
            values = json.loads(current['settings'])
            if values.get('BACKUP_ARCHIVE_PASSWORD') and acknowledge_old is not True:
                raise ValueError('Alte Sicherungen benötigen weiterhin ihre alte Phrase bzw. ihr altes Passwort; ohne diese sind deren Daten verloren')
            values.update(BACKUP_ARCHIVE_PASSWORD=pending['password'], BACKUP_KEY_ID=pending['key_id'],
                          BACKUP_KEY_FORMAT=pending['format'], BACKUP_NAMESPACE='keys/' + pending['key_id'], BACKUP_ENCRYPTION_ENABLED=True)
            conn.execute('UPDATE configuration SET settings=?,revision=revision+1 WHERE id=1', (json.dumps(values),))
            conn.execute('DELETE FROM pending_backup_keys WHERE nonce=?', (nonce,))
        return self.public('backup')

    def import_legacy(self, values):
        snap = self.snapshot()
        if snap['phase'] == 'configured' or snap['revision'] != 0:
            raise Conflict('Die Erstübernahme wurde bereits durchgeführt')
        public = {key: validate(key, value) for key, value in values.items() if key in FIELDS}
        private = {key: value for key, value in values.items() if key in PRIVATE_FIELDS}
        if private.get('TLS_CA_PROVISIONER_PASSWORD'):
            public['TLS_CA_PASSWORD'] = private.pop('TLS_CA_PROVISIONER_PASSWORD')
        if private.get('TLS_CA_PROVISIONER_PASSWORD_FILE') and Path(private['TLS_CA_PROVISIONER_PASSWORD_FILE']).is_file():
            public['TLS_CA_PASSWORD'] = Path(private.pop('TLS_CA_PROVISIONER_PASSWORD_FILE')).read_text().rstrip('\r\n')
        if not public.get('WEB_TLS_MODE'):
            public['WEB_TLS_MODE'] = 'acme' if public.get('ACME_CA_SERVER') else 'ca' if public.get('TLS_CA_URL') else 'files' if private.get('WEB_TLS_CERT_FILE') else 'self-signed'
        if not all(public.get(key) for key in ('REALM', 'WORKGROUP', 'DOMAIN', 'DOMAIN_USERS_SID', 'DOMAIN_ADMINS_SID')):
            return False
        public.setdefault('FSLOGIX_GROUP_SID', public['DOMAIN_USERS_SID'])
        # Keep the legacy format and password until encryption is deliberately
        # enabled/renewed. Existing remote snapshots remain at their old path.
        public['BACKUP_ENCRYPTION_ENABLED'] = False
        public.setdefault('BACKUP_AUTO_ENABLED', True)
        combined = snap['values'] | public | private
        with self.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            changed = conn.execute("UPDATE configuration SET settings=?,phase='configured',revision=1,service_revision=1 WHERE id=1 AND revision=0", (json.dumps(combined),)).rowcount
            if not changed:
                raise Conflict('Einstellungen wurden inzwischen geändert')
        return True

    def environment(self, materialize=True):
        values = self.snapshot()['values']
        result = {name: ('true' if value else 'false') if isinstance(value, bool) else str(value)
                  for name, value in values.items() if name in FIELDS or name in PRIVATE_FIELDS}
        for name in ('LDAP_URI', 'LDAP_BASE_DN', 'AD_DNS_NAME'):
            if not result.get(name):
                result.pop(name, None)
        if values.get('REALM') and not result.get('LDAP_BASE_DN'):
            result['LDAP_BASE_DN'] = ','.join('DC=' + part for part in values['REALM'].lower().split('.'))
        if values.get('REALM') and not result.get('AD_DNS_NAME'):
            hostname = values.get('SAMBA_HOSTNAME', FIELDS['SAMBA_HOSTNAME']['default']).lower()
            result['AD_DNS_NAME'] = hostname if '.' in hostname else hostname + '.' + values['REALM'].lower()
        result.update(WEB_ENABLED='true', STATE_ROOT=str(self.root), STATE_DB_PATH=values.get('STATE_DB_PATH', str(self.root / 'shares.db')),
                      WEB_TLS_CERT_FILE=values.get('WEB_TLS_CERT_FILE', str(self.root / 'tls' / 'web.crt')),
                      WEB_TLS_KEY_FILE=values.get('WEB_TLS_KEY_FILE', str(self.root / 'tls' / 'web.key')),
                      WEB_BIND_PORT=values.get('WEB_BIND_PORT', '8443'), WEB_HTTPS_PORT=values.get('WEB_HTTPS_PORT', '443'),
                      ACME_HTTP_LISTEN='127.0.0.1:8080', ACME_CA_CERTIFICATES=values.get('ACME_CA_CERTIFICATES') or
                      (str(self.root / 'tls' / 'acme-ca-certificates.pem') if values.get('ACME_CA_CERTIFICATES_PEM') or values.get('ACME_CA_CERTIFICATES_URL') else '/etc/ssl/certs/ca-certificates.crt'))
        for key, filename in (('ACME_CA_CERTIFICATES_PEM', 'acme-ca-certificates.pem'), ('TLS_CA_ROOT_PEM', 'ca-root.pem'),
                              ('TLS_CA_PASSWORD', 'ca-password')):
            if values.get(key):
                directory = self.root / 'tls'
                directory.mkdir(mode=0o700, exist_ok=True)
                target = directory / filename
                if materialize and (not target.exists() or target.read_text() != values[key]):
                    try:
                        from .tls_configuration import write_private
                    except ImportError:
                        from tls_configuration import write_private
                    write_private(target, values[key])
                if key == 'TLS_CA_ROOT_PEM':
                    result['TLS_CA_ROOT'] = str(target)
                    if not result.get('TLS_CA_FINGERPRINT'):
                        result['TLS_CA_FINGERPRINT'] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(values[key])).hexdigest()
                if key == 'ACME_CA_CERTIFICATES_PEM':
                    result['ACME_CA_CERTIFICATES'] = str(target)
                if key == 'TLS_CA_PASSWORD':
                    result['TLS_CA_PROVISIONER_PASSWORD_FILE'] = str(target)
            elif key == 'TLS_CA_PASSWORD' and materialize:
                (self.root / 'tls' / filename).unlink(missing_ok=True)
        return result

    def service_environment(self, inherited=None):
        result = dict(os.environ if inherited is None else inherited)
        for name in set(FIELDS) | PRIVATE_FIELDS:
            result.pop(name, None)
        result.update(self.environment())
        return result


def parse_legacy(text):
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:]
        key, sep, value = line.partition('=')
        if not sep or key not in FIELDS and key not in PRIVATE_FIELDS:
            continue
        tokens = shlex.split(value, comments=True, posix=True)
        result[key] = ' '.join(tokens)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['import-legacy', 'import-runtime', 'export-shell'])
    args = parser.parse_args()
    store = Store()
    if args.action in ('import-legacy', 'import-runtime'):
        payload = sys.stdin.read(1024 * 1024)
        if store.snapshot()['revision'] != 0:
            print('Persistent configuration already exists; legacy import skipped.')
            return
        if args.action == 'import-runtime':
            items = json.loads(payload)
            if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
                raise ValueError('Invalid container configuration')
            values = dict(item.split('=', 1) for item in items if '=' in item)
        else:
            values = parse_legacy(payload)
        if not store.import_legacy(values):
            if args.action == 'import-runtime':
                print('No legacy domain configuration found; continue web setup.')
                return
            raise ValueError('Unvollständige frühere Konfiguration')
        print('Imported existing configuration without changing data or the domain join.')
    else:
        for key, value in store.environment().items():
            print('export ' + key + '=' + shlex.quote(value))


if __name__ == '__main__':
    main()
