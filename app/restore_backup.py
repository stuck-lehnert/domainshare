"""Offline recovery; never accept a recovery phrase through argv/environment."""
import argparse
import getpass
from pathlib import Path
import subprocess
try:
    from .backup_keys import archive_key
except ImportError:
    from backup_keys import archive_key


def main():
    parser = argparse.ArgumentParser(description='Decrypt a backup archive into a new recovery directory; never overwrite live data.')
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('The recovery output must be a new directory')
    if not args.archive.is_file():
        parser.error('Archive does not exist')
    password = archive_key(getpass.getpass('24-word recovery phrase: '))
    args.output.mkdir(mode=0o700, parents=True)
    result = subprocess.run(['7z', 'x', '-aos', '-o' + str(args.output.resolve()), '--', str(args.archive.resolve())],
                            input=(password + '\n').encode(), capture_output=True)
    if result.returncode:
        raise SystemExit('Recovery failed. Check the phrase, archive, and available disk space. No live data was changed.')
    print('Recovered into ' + str(args.output) + '; inspect before copying to live storage.')


if __name__ == '__main__':
    main()
