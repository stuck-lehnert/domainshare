"""Start a service from a single persisted configuration snapshot."""
import os
from pathlib import Path
import runpy
import sys
import configuration

if __name__ == '__main__':
    environment = configuration.Store().service_environment()
    os.environ.clear()
    os.environ.update(environment)
    allowed = {'web_ui.py', 'backup_to_destination.py', 'document_index.py', 'audit_collector.py', 'reconcile_shares.py', 'trash.py'}
    if len(sys.argv) < 2 or sys.argv[1] not in allowed:
        raise SystemExit('Unknown service')
    target = Path(__file__).parent / sys.argv[1]
    sys.argv = [str(target), *sys.argv[2:]]
    runpy.run_path(str(target), run_name='__main__')
