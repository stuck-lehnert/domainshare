import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def setup_commands(self, state, *options):
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory)
            setup = sandbox / "setup"
            shutil.copy2(ROOT / "setup", setup)

            docker = sandbox / "docker"
            docker.write_text(
                """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$DOCKER_COMMANDS"
case "$*" in
  'compose ps --all -q samba')
    if [[ "$TEST_STATE" != fresh ]]; then printf 'previous-container\\n'; fi
    ;;
  'inspect previous-container --format {{index .Config.Labels "org.domainshare.role"}}')
    if [[ "$TEST_STATE" == split ]]; then printf 'samba\\n'; fi
    ;;
  'inspect previous-container --format {{json .Config.Env}}')
    printf '["REALM=EXAMPLE.TEST"]\\n'
    ;;
  'compose --profile tools run --rm --no-deps -T config-import domainshare import-runtime')
    [[ $(cat) == '["REALM=EXAMPLE.TEST"]' ]]
    ;;
esac
""",
                encoding="utf-8",
            )
            docker.chmod(0o700)
            log = sandbox / "commands"
            env = dict(os.environ, PATH=f"{sandbox}:{os.environ['PATH']}",
                       DOCKER_COMMANDS=str(log), TEST_STATE=state)
            subprocess.run([str(setup), *options], check=True, env=env, capture_output=True, timeout=10)
            return log.read_text(encoding="utf-8").splitlines()

    def test_normal_deploy_does_not_replace_samba(self):
        self.assertEqual(self.setup_commands("split")[2:], [
            "compose build management",
            "compose up -d --no-deps --no-recreate samba",
            "compose up -d --no-deps management",
        ])

    def test_explicit_samba_update_stops_management_first(self):
        self.assertEqual(self.setup_commands("split", "--restart-samba")[2:], [
            "compose build samba management",
            "compose stop management",
            "compose up -d --no-deps --force-recreate samba",
            "compose up -d --no-deps --force-recreate management",
        ])

    def test_migration_imports_old_environment_before_replacing_samba(self):
        commands = self.setup_commands("combined")[2:]
        self.assertEqual(commands[0], "compose build samba management")
        self.assertCountEqual(commands[1:3], [
            "inspect previous-container --format {{json .Config.Env}}",
            "compose --profile tools run --rm --no-deps -T config-import domainshare import-runtime",
        ])
        self.assertEqual(commands[3:], [
            "compose stop management",
            "compose up -d --no-deps --force-recreate samba",
            "compose up -d --no-deps --force-recreate management",
        ])

    def test_first_setup_creates_both_services(self):
        self.assertEqual(self.setup_commands("fresh")[1:], [
            "compose build samba management",
            "compose up -d --no-deps --no-recreate samba",
            "compose up -d --no-deps management",
        ])
