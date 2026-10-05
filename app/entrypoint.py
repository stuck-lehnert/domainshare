"""Keep setup HTTPS available while AD services join, start, or recover."""
import datetime as dt
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import configuration
import tls_configuration
import http_setup

APP = Path(__file__).parent

def stop(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

def start(command, store, extra=None):
    environment = store.service_environment()
    environment.update(extra or {})
    return subprocess.Popen(command, env=environment, start_new_session=True)

def write_status(store, **changes):
    target = store.root / 'services-status.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps(changes))
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)

def main():
    store = configuration.Store()
    if store.snapshot()['revision'] == 0:
        store.import_legacy(dict(os.environ))
    if store.snapshot()['phase'] != 'configured':
        print('[setup] Open http://<server>/ for HTTPS only. HTTPS setup code: ' + http_setup.setup_code(store), flush=True)
        print('[setup] Open https://<server>/ and enter setup code: ' + store.bootstrap_code(), flush=True)
    tls_configuration.prepare(store)
    ui = service = backup = certificate = None
    http = start([sys.executable, str(APP / 'http_setup.py')], store)
    revision = -1
    running = True
    next_retry = 0
    next_tls_retry = 0
    def terminate(*args):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        while running:
            snap = store.snapshot()
            if snap['service_revision'] != revision:
                stop(service)
                stop(certificate)
                stop(ui)
                service = ui = certificate = None
                Path('/run/adfs-domain-ready').unlink(missing_ok=True)
                Path('/run/adfs-services-ready').unlink(missing_ok=True)
                revision = snap['service_revision']
                next_retry = 0
                next_tls_retry = 0
                try:
                    tls_configuration.prepare(store)
                except (OSError, ValueError, subprocess.SubprocessError):
                    write_status(store, state='failed', message='HTTPS-Zertifikat konnte nicht eingerichtet werden')
            if ui is None or ui.poll() is not None:
                ui = start([sys.executable, str(APP / 'run_service.py'), 'web_ui.py'], store)
            if http.poll() is not None:
                http = start([sys.executable, str(APP / 'http_setup.py')], store)
            tls_marker = Path(store.environment()['WEB_TLS_CERT_FILE']).parent / 'bootstrap-certificate'
            wants_acme = snap['values']['WEB_TLS_MODE'] == 'acme' and bool(snap['values']['ACME_CA_SERVER'])
            if certificate is not None and certificate.poll() is not None:
                succeeded = certificate.returncode == 0
                stop(certificate)
                certificate = None
                tls_configuration.write_private(store.root / 'https-status.json', json.dumps({'state': 'ready' if succeeded else 'failed', 'message': 'HTTPS ist eingerichtet. Über HTTPS fortfahren.' if succeeded else 'ACME-Zertifikat konnte nicht angefordert werden. Hostname, CA und Erreichbarkeit von Port 80 prüfen.'}))
            if wants_acme and tls_marker.exists() and certificate is None and time.monotonic() >= next_tls_retry:
                tls_configuration.write_private(store.root / 'https-status.json', json.dumps({'state': 'working', 'message': 'ACME-Zertifikat wird angefordert'}))
                certificate = start([str(APP / 'init.sh'), '--configure-tls'], store, {'ADFS_SUPERVISED': 'true'})
                next_tls_retry = time.monotonic() + 60
            desired = snap['phase'] in ('joining', 'groups', 'configured') and all(snap['values'].get(key) for key in ('REALM', 'WORKGROUP', 'DOMAIN'))
            if wants_acme and (certificate is not None or tls_marker.exists()):
                desired = False
            if desired and (service is None or service.poll() is not None) and time.monotonic() >= next_retry:
                mode = [] if snap['phase'] == 'configured' else ['--bootstrap-domain']
                write_status(store, state='starting', message='AD-Dienste werden gestartet')
                service = start([str(APP / 'init.sh'), *mode], store, {'ADFS_SUPERVISED': 'true'})
                next_retry = time.monotonic() + 30
            if service is not None and service.poll() is not None:
                code = service.returncode
                stop(service)
                service = None
                Path('/run/adfs-services-ready').unlink(missing_ok=True)
                write_status(store, state='failed', message=f'AD-Dienste konnten nicht gestartet werden (Status {code}); Einstellungen prüfen')
            elif service is not None and Path('/run/adfs-domain-ready').exists():
                if snap['phase'] == 'joining':
                    store.phase('groups')
                write_status(store, state='running', message='Domänenverbindung hergestellt')
            if backup is not None and backup.poll() is not None:
                backup = None
            values = snap['values']
            now = dt.datetime.now(dt.timezone.utc)
            if snap['phase'] == 'configured' and backup is None and values['BACKUP_DESTINATION'] and values['BACKUP_AUTO_ENABLED'] and now.hour == values['BACKUP_START_HOUR']:
                slot = now.strftime('%Y-%m-%dT%H')
                with store.connect() as conn:
                    claimed = conn.execute('INSERT OR IGNORE INTO scheduled_backups VALUES(?)', (slot,)).rowcount
                if claimed:
                    backup = start([sys.executable, str(APP / 'run_service.py'), 'backup_to_destination.py'], store, {'BACKUP_TRIGGER': 'automatic'})
            time.sleep(1)
    finally:
        stop(service)
        stop(ui)
        stop(backup)
        stop(certificate)
        stop(http)
    return 0

if __name__ == '__main__':
    sys.exit(main())
