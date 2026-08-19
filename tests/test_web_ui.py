import datetime as dt
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from app import audit_collector
from app import audit_store
from app import web_ui
from app import state_db


class TokenManagerTests(unittest.TestCase):
    def test_issues_and_verifies_short_lived_admin_jwt(self):
        manager = web_ui.TokenManager("s" * 48, 600)

        token, expires = manager.issue("EXAMPLE\\alice")
        payload = manager.verify(token)

        self.assertEqual(payload["sub"], "EXAMPLE\\alice")
        self.assertEqual(payload["role"], "domain-admin")
        self.assertEqual(payload["exp"], expires)

    def test_rejects_tampered_jwt(self):
        manager = web_ui.TokenManager("s" * 48, 600)
        token, _ = manager.issue("EXAMPLE\\alice")

        with self.assertRaisesRegex(ValueError, "Invalid or expired"):
            manager.verify(f"{token[:-1]}x")

    def test_requires_a_long_secret(self):
        with self.assertRaisesRegex(RuntimeError, "32 bytes"):
            web_ui.TokenManager("short", 600)


class ReportPayloadTests(unittest.TestCase):
    @mock.patch("app.web_ui.backup_payload")
    def test_report_snapshot_excludes_all_log_data(self, backup_payload):
        backup_payload.return_value = {"state": "completed"}
        app = mock.Mock()
        app.directory.get.return_value = {"groups": [], "fetchedAt": None}
        app.usage.snapshot.return_value = {"groups": [], "users": [], "totals": {}}
        app.system_summary.return_value = {
            "hostname": "files.example.test",
            "checks": {},
            "tls": {},
            "serverTime": "2026-08-01T12:00:00+00:00",
        }

        payload = web_ui.App.report(app)

        backup_payload.assert_called_once_with(include_log=False)
        self.assertNotIn("log", payload["backup"])
        self.assertNotIn("audit", payload["system"])
        self.assertNotIn("usage", payload["system"])
        self.assertEqual(payload["system"]["hostname"], "files.example.test")

    @mock.patch("app.web_ui.tail_lines")
    @mock.patch("app.web_ui.read_json")
    def test_log_free_backup_snapshot_does_not_read_log_file(self, read_json, tail_lines):
        read_json.return_value = {
            "state": "completed",
            "log": ["GEHEIME SICHERUNGSAUSGABE"],
        }

        payload = web_ui.backup_payload(include_log=False)

        self.assertNotIn("log", payload)
        tail_lines.assert_not_called()


class AdministrationActionTests(unittest.TestCase):
    def test_log_query_flag_defaults_on_and_accepts_explicit_off_values(self):
        self.assertTrue(web_ui.query_includes_log({}))
        self.assertTrue(web_ui.query_includes_log({"log": ["1"]}))
        for value in ("0", "false", "NO", "off"):
            self.assertFalse(web_ui.query_includes_log({"log": [value]}))

    @mock.patch("app.web_ui.tail_lines", return_value=["backup log"])
    @mock.patch("app.web_ui.read_json", return_value={})
    def test_backup_payload_exposes_manual_mode_when_automatic_runs_are_off(
        self, _read_json, _tail_lines
    ):
        with mock.patch.dict(
            os.environ,
            {
                "BACKUP_DESTINATION": "rsync://backup.example.test/target",
                "BACKUP_AUTO_ENABLED": "false",
                "BACKUP_START_HOUR": "4",
            },
            clear=True,
        ):
            payload = web_ui.backup_payload()

        self.assertTrue(payload["enabled"])
        self.assertTrue(payload["manualEnabled"])
        self.assertFalse(payload["automaticEnabled"])
        self.assertEqual(payload["scheduledHour"], 4)
        self.assertEqual(payload["state"], "waiting")
        self.assertEqual(payload["log"], ["backup log"])

    @mock.patch("app.web_ui.tail_lines", return_value=[])
    def test_backup_payload_marks_unowned_active_status_interrupted(
        self, _tail_lines
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            status_path = os.path.join(tmpdir, "backup-status.json")
            lock_path = os.path.join(tmpdir, "backup.lock")
            web_ui.write_json_atomic(
                status_path,
                {
                    "state": "running",
                    "workerPid": 4242,
                    "currentSource": "data/fslogix",
                    "activeFiles": [{"path": "profile.vhdx"}],
                },
            )
            with (
                mock.patch.object(web_ui, "BACKUP_STATUS_FILE", status_path),
                mock.patch.object(web_ui, "BACKUP_LOCK_FILE", lock_path),
                mock.patch.dict(
                    os.environ,
                    {"BACKUP_DESTINATION": "rsync://backup.test/target"},
                    clear=True,
                ),
            ):
                payload = web_ui.backup_payload()
                persisted = web_ui.read_json(status_path, {})

        self.assertEqual(payload["state"], "failed")
        self.assertFalse(payload["processRunning"])
        self.assertTrue(payload["interrupted"])
        self.assertIsNone(payload["workerPid"])
        self.assertIsNone(payload["currentSource"])
        self.assertEqual(payload["activeFiles"], [])
        self.assertIsNotNone(payload["finishedAt"])
        self.assertEqual(persisted["state"], "failed")
        self.assertTrue(persisted["interrupted"])

    @mock.patch("app.web_ui.tail_lines", return_value=[])
    def test_backup_payload_keeps_status_active_while_lock_is_owned(
        self, _tail_lines
    ):
        with tempfile.TemporaryDirectory() as tmpdir:
            status_path = os.path.join(tmpdir, "backup-status.json")
            lock_path = os.path.join(tmpdir, "backup.lock")
            web_ui.write_json_atomic(
                status_path, {"state": "running", "workerPid": 4242}
            )
            with open(lock_path, "w", encoding="utf-8") as lock_file:
                web_ui.fcntl.flock(lock_file, web_ui.fcntl.LOCK_EX)
                with (
                    mock.patch.object(
                        web_ui, "BACKUP_STATUS_FILE", status_path
                    ),
                    mock.patch.object(web_ui, "BACKUP_LOCK_FILE", lock_path),
                    mock.patch.dict(
                        os.environ,
                        {"BACKUP_DESTINATION": "rsync://backup.test/target"},
                        clear=True,
                    ),
                ):
                    payload = web_ui.backup_payload()
                web_ui.fcntl.flock(lock_file, web_ui.fcntl.LOCK_UN)

            persisted = web_ui.read_json(status_path, {})

        self.assertEqual(payload["state"], "running")
        self.assertTrue(payload["processRunning"])
        self.assertEqual(persisted["state"], "running")


    @mock.patch("app.web_ui.tail_lines", return_value=["reconcile log"])
    @mock.patch("app.web_ui.read_json", return_value={})
    def test_reconciliation_payload_has_progress_schedule_and_log(
        self, _read_json, _tail_lines
    ):
        payload = web_ui.reconciliation_payload()

        self.assertEqual(payload["state"], "waiting")
        self.assertEqual(payload["phase"], "waiting")
        self.assertEqual(payload["percent"], 0.0)
        self.assertTrue(payload["automaticEnabled"])
        self.assertEqual(payload["scheduledIntervalMinutes"], 5)
        self.assertEqual(payload["log"], ["reconcile log"])

    @mock.patch("app.web_ui.tail_lines")
    @mock.patch("app.web_ui.read_json", return_value={"state": "completed"})
    def test_log_free_reconciliation_snapshot_does_not_read_log_file(
        self, _read_json, tail_lines
    ):
        payload = web_ui.reconciliation_payload(include_log=False)

        self.assertNotIn("log", payload)
        tail_lines.assert_not_called()

    @mock.patch("app.web_ui.log")
    @mock.patch("app.web_ui.launch_background")
    @mock.patch("app.web_ui.lock_is_held", return_value=False)
    def test_manual_backup_launches_with_web_trigger(
        self, _lock_is_held, launch_background, _log
    ):
        with mock.patch.dict(
            os.environ,
            {
                "BACKUP_DESTINATION": "rsync://backup.example.test/target",
                "BACKUP_ARCHIVE_PASSWORD": "archive secret",
            },
            clear=True,
        ):
            result = web_ui.start_backup_action("EXAMPLE\\alice")

        self.assertEqual(result, {"accepted": True, "action": "backup"})
        launch_background.assert_called_once_with(
            [web_ui.sys.executable, "/app/backup_to_destination.py"],
            {"BACKUP_TRIGGER": "web"},
        )

    @mock.patch("app.web_ui.launch_background")
    @mock.patch("app.web_ui.lock_is_held", return_value=False)
    def test_manual_backup_requires_archive_password(
        self, _lock_is_held, launch_background
    ):
        with mock.patch.dict(
            os.environ,
            {"BACKUP_DESTINATION": "rsync://backup.example.test/target"},
            clear=True,
        ):
            with self.assertRaisesRegex(
                web_ui.ActionConflict, "BACKUP_ARCHIVE_PASSWORD"
            ):
                web_ui.start_backup_action("EXAMPLE\\alice")

        launch_background.assert_not_called()

    @mock.patch("app.web_ui.log")
    @mock.patch("app.web_ui.launch_background")
    @mock.patch("app.web_ui.lock_is_held", return_value=False)
    def test_manual_reconciliation_launches_with_web_trigger(
        self, _lock_is_held, launch_background, _log
    ):
        result = web_ui.start_reconciliation_action("EXAMPLE\\alice")

        self.assertEqual(result, {"accepted": True, "action": "reconciliation"})
        launch_background.assert_called_once_with(
            [web_ui.sys.executable, "/app/reconcile_shares.py"],
            {"RECONCILE_TRIGGER": "web"},
        )


class ReportCompilerTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is needed for the browser Typst smoke test")
    def test_vendored_browser_typst_compiles_report_to_pdf(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        result = subprocess.run(
            [shutil.which("node"), os.path.join(root, "tests", "report_pdf_smoke.mjs")],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Typst PDF smoke test passed", result.stdout)


class DomainAuthenticationTests(unittest.TestCase):
    @mock.patch.dict(os.environ, {"WORKGROUP": "EXAMPLE"})
    def test_bare_username_defaults_to_configured_netbios_domain(self):
        self.assertEqual(web_ui.normalize_username("alice"), "EXAMPLE\\alice")

    @mock.patch.dict(os.environ, {"WORKGROUP": "EXAMPLE"})
    def test_qualified_username_remains_supported(self):
        self.assertEqual(web_ui.normalize_username("EXAMPLE\\alice"), "EXAMPLE\\alice")
    @mock.patch.dict(
        os.environ,
        {
            "WORKGROUP": "EXAMPLE",
            "REALM": "EXAMPLE.COM",
            "DOMAIN_ADMINS_SID": "S-1-5-21-1-2-3-512",
        },
    )
    @mock.patch("app.web_ui.subprocess.run")
    def test_password_uses_kerberos_stdin_and_checks_admin_sid(self, run):
        run.side_effect = [
            mock.Mock(returncode=0, stdout=""),
            mock.Mock(returncode=0, stdout="S-1-5-21-1-2-3-1100 SID_USER (1)\n"),
            mock.Mock(returncode=0, stdout="S-1-5-21-1-2-3-1100\nS-1-5-21-1-2-3-512\n"),
        ]

        result = web_ui.authenticate_domain_admin("alice", "p@ss word")

        self.assertEqual(result, "EXAMPLE\\alice")
        self.assertEqual(run.call_args_list[0].args[0], ["kinit", "alice@EXAMPLE.COM"])
        self.assertNotIn("p@ss word", run.call_args_list[0].args[0])


class DirectoryPrimaryGroupTests(unittest.TestCase):
    def test_tree_expands_users_whose_primary_group_is_nested(self):
        domain_users_dn = "CN=Domänen-Benutzer,CN=Users,DC=example,DC=com"
        frank_dn = "CN=Frank,CN=Users,DC=example,DC=com"
        root = {
            "objectGUID": "root-guid",
            "objectSid": "S-1-5-21-111-222-333-1200",
            "samAccountName": "FS_Alle",
            "shareName": "Alle",
            "distinguishedName": "CN=FS_Alle,CN=Users,DC=example,DC=com",
            "memberDns": [domain_users_dn],
            "objectClasses": {"group"},
        }
        domain_users = {
            "distinguishedname": [(domain_users_dn, False)],
            "objectsid": [("S-1-5-21-111-222-333-513", False)],
            "samaccountname": [("Domänen-Benutzer", False)],
            "displayname": [("Domänen-Benutzer", False)],
            "objectclass": [("group", False)],
        }
        frank = {
            "distinguishedname": [(frank_dn, False)],
            "samaccountname": [("frank", False)],
            "displayname": [("Frank", False)],
            "primarygroupid": [("513", False)],
            "objectclass": [("user", False)],
        }

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.object(
            web_ui, "STATE_DB", os.path.join(tmpdir, "missing.db")
        ), mock.patch.object(
            web_ui.directory, "fetch_fileshare_groups", return_value=[root]
        ), mock.patch.object(
            web_ui.directory,
            "search_directory_entries",
            side_effect=[[domain_users], [frank]],
        ):
            result = web_ui.DirectoryCache().fetch()

        nested_group = result["groups"][0]["members"][0]
        self.assertEqual(nested_group["sam"], "Domänen-Benutzer")
        self.assertEqual(
            [member["sam"] for member in nested_group["members"]],
            ["frank"],
        )
        self.assertEqual(result["groups"][0]["userCount"], 1)
        self.assertFalse(result["truncated"])


class AuditParsingTests(unittest.TestCase):
    def test_parses_full_audit_record(self):
        line = (
            "[2026/07/31 12:34:56.123456,  1] smbd_audit: "
            "2026/07/31 12:34:56|alice|192.0.2.5|PC01|Data|pread|OK|Finance/report.xlsx\n"
        )

        event = audit_collector.parse_audit_line(line, "/var/log/samba/log.pc01")

        self.assertEqual(event["user"], "alice")
        self.assertEqual(event["action"], "read")
        self.assertEqual(event["path"], "Finance/report.xlsx")
        self.assertTrue(event["success"])

    def test_parses_samba_two_line_payload_record(self):
        line = (
            "  2026/07/31 12:34:56|DEV\\alice|192.0.2.5|PC01|"
            "Private|pread_send|ok|/data/private/alice/notes.txt\n"
        )

        event = audit_collector.parse_audit_line(line, "/var/log/samba/log.pc01")

        self.assertEqual(event["timestamp"], "2026-07-31T12:34:56+00:00")
        self.assertEqual(event["user"], "DEV\\alice")
        self.assertEqual(event["action"], "read")
        self.assertEqual(event["path"], "/data/private/alice/notes.txt")
        self.assertTrue(event["success"])

    def test_normalizes_only_high_level_file_actions(self):
        expected = {
            "recvfile": "write",
            "renameat": "move",
            "unlinkat": "delete",
        }

        for operation, action in expected.items():
            with self.subTest(operation=operation):
                line = f"smbd_audit: x|alice|192.0.2.5|PC01|Data|{operation}|OK|file.txt\n"
                event = audit_collector.parse_audit_line(line, "/var/log/samba/log.pc01")
                self.assertEqual(event["action"], action)

        for operation in ("connect", "readdir", "fstat", "create_file", "fsetxattr"):
            with self.subTest(operation=operation):
                line = f"smbd_audit: x|alice|192.0.2.5|PC01|Data|{operation}|OK|file.txt\n"
                self.assertIsNone(
                    audit_collector.parse_audit_line(line, "/var/log/samba/log.pc01")
                )

    def test_skips_configured_user_suffixes_case_insensitively(self):
        with mock.patch.dict(
            os.environ,
            {"AUDIT_SKIP_USER_SUFFIXES": "_svc,_ServiceAcc"},
        ):
            for user in ("DEV\\backup_SVC", "report_serviceacc@dev.test"):
                with self.subTest(user=user):
                    line = f"smbd_audit: x|{user}|192.0.2.5|PC01|Data|pread|OK|file.txt\n"
                    self.assertIsNone(
                        audit_collector.parse_audit_line(line, "/var/log/samba/log.pc01")
                    )

        with mock.patch.dict(os.environ, {"AUDIT_SKIP_USER_SUFFIXES": ""}):
            line = "smbd_audit: x|DEV\\backup_svc|192.0.2.5|PC01|Data|pread|OK|file.txt\n"
            self.assertIsNotNone(
                audit_collector.parse_audit_line(line, "/var/log/samba/log.pc01")
            )

    def test_parses_fslogix_activity_for_separate_storage(self):
        line = (
            "smbd_audit: x|alice|192.0.2.5|PC01|"
            "fSlOgIx|pwrite|OK|profile.vhdx\n"
        )

        event = audit_collector.parse_audit_line(
            line, "/var/log/samba/log.pc01"
        )

        self.assertIsNotNone(event)
        self.assertEqual(event["share"], "fSlOgIx")
        self.assertEqual(event["path"], "profile.vhdx")

    def test_tracks_rotated_file_by_inode_without_reingesting_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active = os.path.join(tmpdir, "log.pc01")
            database = os.path.join(tmpdir, "state.db")
            line = (
                "[2026/07/31 12:34:56.000000, 1] smbd_audit: "
                "x|alice|192.0.2.5|PC01|Data|pread|OK|a.txt\n"
            )
            with open(active, "w", encoding="utf-8") as handle:
                handle.write(line)

            store = audit_store.AuditStore(database)
            try:
                with mock.patch.object(
                    audit_collector,
                    "SAMBA_LOG_GLOB",
                    os.path.join(tmpdir, "log.*"),
                ):
                    self.assertEqual(audit_collector.collect_once(store), 1)
                    rotated = f"{active}.old"
                    os.rename(active, rotated)
                    with open(active, "w", encoding="utf-8") as handle:
                        handle.write(line.replace("a.txt", "b.txt"))
                    self.assertEqual(audit_collector.collect_once(store), 1)
                paths = [
                    row[0]
                    for row in store.conn.execute(
                        "SELECT path FROM audit_events ORDER BY id"
                    )
                ]
                self.assertEqual(paths, ["a.txt", "b.txt"])
            finally:
                store.close()

    def test_processes_known_rotated_inode_before_new_active_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active = os.path.join(tmpdir, "log.pc01")
            database = os.path.join(tmpdir, "state.db")
            today = dt.datetime.now(dt.timezone.utc).strftime("%Y/%m/%d")
            read = (
                f"[{today} 12:34:56.000000, 1] smbd_audit: "
                "x|alice|192.0.2.5|PC01|Data|pread|OK|a.txt\n"
            )
            write = read.replace("pread|OK|a.txt", "pwrite|OK|changed.txt")
            with open(active, "w", encoding="utf-8") as handle:
                handle.write(read)

            store = audit_store.AuditStore(database)
            try:
                with mock.patch.object(
                    audit_collector,
                    "SAMBA_LOG_GLOB",
                    os.path.join(tmpdir, "log.*"),
                ):
                    self.assertEqual(audit_collector.collect_once(store), 1)
                    with open(active, "a", encoding="utf-8") as handle:
                        handle.write(read)
                    os.rename(active, f"{active}.old")
                    with open(active, "w", encoding="utf-8") as handle:
                        handle.write(write)
                    self.assertEqual(audit_collector.collect_once(store), 1)

                rows = store.conn.execute(
                    "SELECT action, path FROM audit_events ORDER BY id"
                ).fetchall()
                self.assertEqual(
                    [(row["action"], row["path"]) for row in rows],
                    [("read", "a.txt"), ("write", "changed.txt")],
                )
            finally:
                store.close()


    def test_deduplicates_reads_per_second_across_interleaved_events(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)

            def event(
                action="read",
                path="a.txt",
                second="12:34:56",
                share="Data",
                source="log.pc01",
            ):
                timestamp = f"{dt.datetime.now(dt.timezone.utc).date()}T{second}+00:00"
                return {
                    "timestamp": timestamp,
                    "ingestedAt": timestamp,
                    "user": "LOCAL\\silvia.mueller",
                    "clientIp": "10.100.0.22",
                    "client": "PC01",
                    "share": share,
                    "operation": "pread" if action == "read" else "pwrite",
                    "action": action,
                    "path": path,
                    "result": "OK",
                    "success": True,
                    "source": source,
                }

            try:
                inserted = store.append_batch(
                    [
                        event(source="log.pc01"),
                        event(path="profile.vhdx", share="FSLogix"),
                        event(action="write", path="changed.txt"),
                        event(action="write", path="changed.txt", source="log.pc02"),
                        event(source="log.pc02"),
                        event(path="b.txt"),
                        event(source="log.pc03"),
                    ],
                    {},
                    set(),
                )
                repeated_poll = store.append_batch(
                    [event(source="log.pc04")], {}, set()
                )
                next_second = store.append_batch(
                    [event(second="12:34:57")], {}, set()
                )
                rows = store.conn.execute(
                    """
                    SELECT action, share, path, occurred_second
                    FROM audit_events
                    ORDER BY id
                    """
                ).fetchall()
                fingerprints = store.conn.execute(
                    """
                    SELECT count(*) FROM audit_event_dedup
                    """
                ).fetchone()[0]
            finally:
                store.close()

        self.assertEqual(inserted, 5)
        self.assertEqual(repeated_poll, 0)
        self.assertEqual(next_second, 1)
        self.assertEqual(len(rows), 6)
        self.assertEqual(fingerprints, 4)
        self.assertEqual(
            [(row["action"], row["share"], row["path"]) for row in rows],
            [
                ("read", "Data", "a.txt"),
                ("read", "FSLogix", "profile.vhdx"),
                ("write", "Data", "changed.txt"),
                ("write", "Data", "changed.txt"),
                ("read", "Data", "b.txt"),
                ("read", "Data", "a.txt"),
            ],
        )


    def test_deduplicates_fslogix_writes_but_preserves_private_writes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)
            day = dt.datetime.now(dt.timezone.utc).date()
            timestamp = f"{day}T13:39:23+00:00"
            fslogix_write = {
                "timestamp": timestamp,
                "ingestedAt": timestamp,
                "user": "LOCAL\\ralf.schwientek",
                "clientIp": "10.100.0.21",
                "client": "PC01",
                "share": "FSLogix",
                "operation": "pwrite",
                "action": "write",
                "path": "/data/fslogix/profile.vhd",
                "result": "OK",
                "success": True,
                "source": "log.pc01",
            }
            private_write = dict(
                fslogix_write,
                share="Private",
                path="/data/private/file.txt",
            )
            fslogix_read = dict(
                fslogix_write, operation="pread", action="read"
            )
            try:
                inserted = store.append_batch(
                    [
                        fslogix_write,
                        dict(fslogix_write, source="log.pc02"),
                        private_write,
                        dict(private_write, source="log.pc02"),
                        fslogix_read,
                    ],
                    {},
                    set(),
                )
                repeated_poll = store.append_batch(
                    [dict(fslogix_write, source="log.pc03")], {}, set()
                )
                next_timestamp = f"{day}T13:39:24+00:00"
                next_second = store.append_batch(
                    [dict(
                        fslogix_write,
                        timestamp=next_timestamp,
                        ingestedAt=next_timestamp,
                        source="log.pc04",
                    )],
                    {},
                    set(),
                )
                rows = store.conn.execute(
                    "SELECT action, share FROM audit_events ORDER BY id"
                ).fetchall()
                fingerprints = store.conn.execute(
                    "SELECT count(*) FROM audit_event_dedup"
                ).fetchone()[0]
            finally:
                store.close()

        self.assertEqual(inserted, 4)
        self.assertEqual(repeated_poll, 0)
        self.assertEqual(next_second, 1)
        self.assertEqual(fingerprints, 3)
        self.assertEqual(
            [(row["action"], row["share"]) for row in rows],
            [
                ("write", "FSLogix"),
                ("write", "Private"),
                ("write", "Private"),
                ("read", "FSLogix"),
                ("write", "FSLogix"),
            ],
        )


class AuditQueryTests(unittest.TestCase):
    def make_event(self, timestamp, user, success=True):
        return {
            "timestamp": timestamp,
            "ingestedAt": timestamp,
            "user": user,
            "clientIp": "192.0.2.5",
            "client": "PC01",
            "share": "Data",
            "operation": "pread" if success else "unlinkat",
            "action": "read" if success else "delete",
            "path": "folder/file.txt",
            "result": "OK" if success else "NT_STATUS_ACCESS_DENIED",
            "success": success,
            "source": "log.pc01",
        }

    def test_queries_indexed_events_with_filters_and_keyset_cursor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            yesterday = today - dt.timedelta(days=1)
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)
            events = [
                self.make_event(f"{today}T12:00:0{index}+00:00", "alice")
                for index in range(3)
            ]
            events.extend(
                [
                    self.make_event(f"{today}T12:00:04+00:00", "bob", False),
                    self.make_event(f"{today}T12:00:06+00:00", "robot_svc"),
                    self.make_event(f"{yesterday}T12:00:00+00:00", "alice"),
                ]
            )
            store.append_batch(events, {}, set())
            store.close()

            with mock.patch.object(web_ui, "STATE_DB", database):
                first = web_ui.query_audit(
                    {
                        "from": [yesterday.isoformat()],
                        "to": [today.isoformat()],
                        "user": ["alice"],
                        "limit": ["2"],
                    }
                )
                failed = web_ui.query_audit(
                    {
                        "from": [today.isoformat()],
                        "to": [today.isoformat()],
                        "result": ["fail"],
                    }
                )
                second = web_ui.query_audit(
                    {
                        "from": [yesterday.isoformat()],
                        "to": [today.isoformat()],
                        "user": ["alice"],
                        "limit": ["2"],
                        "cursor": [str(first["nextCursor"])],
                    }
                )
                visible = web_ui.query_audit(
                    {
                        "from": [today.isoformat()],
                        "to": [today.isoformat()],
                        "limit": ["100"],
                    }
                )

        self.assertEqual(first["matched"], 4)
        self.assertEqual(len(first["events"]), 2)
        self.assertEqual(len(second["events"]), 2)
        self.assertEqual(failed["events"][0]["user"], "bob")
        self.assertNotIn("robot_svc", visible["facets"]["users"])
        self.assertEqual(set(visible["facets"]["actions"]), {"read", "delete"})

    def test_store_separates_main_and_fslogix_streams(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            store = audit_store.AuditStore(os.path.join(tmpdir, "state.db"))
            main_event = self.make_event(f"{today}T12:00:00+00:00", "alice")
            fslogix_event = dict(main_event, share="FSLogix", path="profile.vhdx")
            try:
                inserted = store.append_batch(
                    [fslogix_event, main_event], {}, set()
                )
                main = audit_store.query_activity(
                    store.conn, today, today, {"limit": ["100"]}
                )
                fslogix = audit_store.query_activity(
                    store.conn,
                    today,
                    today,
                    {"limit": ["100"]},
                    stream="fslogix",
                )
                plans = {}
                for stream, operator, index in (
                    ("main", "<>", "audit_events_main_time"),
                    ("fslogix", "=", "audit_events_fslogix_time"),
                ):
                    plans[stream] = " ".join(
                        row["detail"]
                        for row in store.conn.execute(
                            f"""
                            EXPLAIN QUERY PLAN
                            SELECT id FROM audit_events
                            WHERE occurred_second >= ? AND occurred_second < ?
                              AND share {operator} 'FSLogix' COLLATE NOCASE
                            ORDER BY occurred_second DESC, id DESC
                            LIMIT 101
                            """,
                            (0, 9999999999),
                        )
                    )
                    self.assertIn(index, plans[stream])
            finally:
                store.close()

        self.assertEqual(inserted, 2)
        self.assertEqual(main["matched"], 1)
        self.assertEqual(main["events"][0]["share"], "Data")
        self.assertEqual(main["stream"], "main")
        self.assertEqual(fslogix["matched"], 1)
        self.assertEqual(fslogix["events"][0]["share"], "FSLogix")
        self.assertEqual(fslogix["stream"], "fslogix")

    def test_query_metadata_uses_rollups_instead_of_raw_event_scans(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            store = audit_store.AuditStore(os.path.join(tmpdir, "state.db"))
            events = [
                self.make_event(f"{today}T12:00:0{index}+00:00", "alice")
                for index in range(4)
            ]
            store.append_batch(events, {}, set())
            statements = []
            store.conn.set_trace_callback(statements.append)
            try:
                result = audit_store.query_activity(
                    store.conn, today, today, {"limit": ["1"]}
                )
            finally:
                store.conn.set_trace_callback(None)
                store.close()

        normalized = [" ".join(statement.casefold().split()) for statement in statements]
        self.assertEqual(result["matched"], 4)
        self.assertTrue(result["matchedExact"])
        self.assertTrue(result["hasMore"])
        self.assertTrue(
            any("from audit_daily_counts" in statement for statement in normalized)
        )
        self.assertTrue(
            any("from audit_daily_counts" in statement for statement in normalized)
        )
        self.assertFalse(
            any(
                "select count(*) from audit_events" in statement
                for statement in normalized
            )
        )
        self.assertFalse(
            any(
                "select distinct user from audit_events" in statement
                for statement in normalized
            )
        )

    def test_pending_rollups_never_scan_raw_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)
            events = [
                self.make_event(f"{today}T12:00:0{index}+00:00", "alice")
                for index in range(4)
            ]
            store.append_batch(events, {}, set())
            for table in (
                "audit_daily_totals",
                "audit_daily_counts",
                "audit_daily_facets",
                "audit_rollup_state",
            ):
                store.conn.execute(f"DELETE FROM {table}")
            store.conn.commit()
            store.close()

            store = audit_store.AuditStore(database)
            statements = []
            store.conn.set_trace_callback(statements.append)
            try:
                result = audit_store.query_activity(
                    store.conn, today, today, {"limit": ["1"]}
                )
                summary = audit_store.audit_summary(store.conn, database)
            finally:
                store.conn.set_trace_callback(None)
                store.close()

        normalized = [
            " ".join(statement.casefold().split())
            for statement in statements
        ]
        self.assertTrue(result["hasMore"])
        self.assertIsNone(result["matched"])
        self.assertFalse(result["matchedExact"])
        self.assertEqual(result["facets"]["users"], [])
        self.assertFalse(result["indexing"]["ready"])
        self.assertFalse(summary["indexing"]["ready"])
        self.assertFalse(
            any(
                "select count(*) from audit_events" in statement
                for statement in normalized
            )
        )
        self.assertFalse(
            any(
                "select distinct" in statement and "from audit_events" in statement
                for statement in normalized
            )
        )


    def test_path_query_does_not_block_on_an_exact_count(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            store = audit_store.AuditStore(os.path.join(tmpdir, "state.db"))
            events = [
                self.make_event(f"{today}T12:00:0{index}+00:00", "alice")
                for index in range(3)
            ]
            store.append_batch(events, {}, set())
            statements = []
            store.conn.set_trace_callback(statements.append)
            try:
                result = audit_store.query_activity(
                    store.conn,
                    today,
                    today,
                    {"path": ["file"], "limit": ["1"], "facets": ["0"]},
                )
            finally:
                store.conn.set_trace_callback(None)
                store.close()

        normalized = [" ".join(statement.casefold().split()) for statement in statements]
        self.assertIsNone(result["matched"])
        self.assertFalse(result["matchedExact"])
        self.assertTrue(result["hasMore"])
        self.assertTrue(
            any("from audit_paths_fts" in statement for statement in normalized)
        )
        self.assertTrue(
            any("from audit_path_events" in statement for statement in normalized)
        )
        self.assertTrue(
            any("pe.path_id =" in statement for statement in normalized)
        )
        self.assertFalse(
            any("lower(path) like" in statement for statement in normalized)
        )

        self.assertFalse(
            any(
                "select count(*) from audit_events" in statement
                for statement in normalized
            )
        )

    def test_incrementally_backfills_legacy_events_without_double_counting_live_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)
            legacy = [
                self.make_event(f"{today}T12:00:0{index}+00:00", "alice")
                for index in range(3)
            ]
            store.append_batch(legacy, {}, set())
            store.conn.execute("UPDATE audit_events SET path_id = NULL")
            store.conn.execute("DELETE FROM audit_path_events")

            for table in (
                "audit_daily_totals",
                "audit_daily_counts",
                "audit_daily_facets",
                "audit_rollup_state",
            ):
                store.conn.execute(f"DELETE FROM {table}")
            store.conn.commit()
            store.close()

            store = audit_store.AuditStore(database)
            live = self.make_event(f"{today}T12:00:09+00:00", "bob")
            store.append_batch([live], {}, set())
            before = audit_store.query_activity(
                store.conn, today, today, {"limit": ["10"]}
            )
            self.assertEqual(store.backfill_rollups(limit=2), 2)
            self.assertEqual(store.backfill_rollups(limit=2), 1)
            self.assertEqual(store.backfill_rollups(limit=2), 0)
            after = audit_store.query_activity(
                store.conn, today, today, {"limit": ["10"]}
            )
            total = store.conn.execute(
                "SELECT sum(event_count) FROM audit_daily_totals"
            ).fetchone()[0]
            ready = store.conn.execute(
                "SELECT ready FROM audit_rollup_state WHERE singleton = 1"
            ).fetchone()[0]
            missing_path_ids = store.conn.execute(
                "SELECT count(*) FROM audit_events WHERE path_id IS NULL"
            ).fetchone()[0]
            path_event_count = store.conn.execute(
                "SELECT count(*) FROM audit_path_events"
            ).fetchone()[0]

            store.close()

        self.assertEqual(before["matched"], 4)
        self.assertEqual(after["matched"], 4)
        self.assertEqual(total, 4)
        self.assertEqual(ready, 1)
        self.assertEqual(missing_path_ids, 0)
        self.assertEqual(path_event_count, 4)


    def test_upgrade_rebuilds_main_and_fslogix_rollups(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)
            main_event = self.make_event(f"{today}T12:00:00+00:00", "alice")
            fslogix_event = dict(
                main_event, share="FSLogix", path="profile.vhdx"
            )
            store.append_batch([main_event, fslogix_event], {}, set())
            store.conn.execute("DROP TABLE audit_rollup_state")
            store.conn.execute(
                """
                CREATE TABLE audit_rollup_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    backfill_next_id INTEGER NOT NULL,
                    backfill_max_id INTEGER NOT NULL,
                    ready INTEGER NOT NULL CHECK (ready IN (0, 1))
                )
                """
            )
            store.conn.execute(
                "INSERT INTO audit_rollup_state VALUES (1, 3, 2, 1)"
            )
            store.conn.commit()
            store.close()

            store = audit_store.AuditStore(database)
            try:
                self.assertEqual(store.backfill_rollups(limit=1), 1)
                self.assertEqual(store.backfill_rollups(limit=1), 1)
                self.assertEqual(store.backfill_rollups(limit=1), 0)
                main = audit_store.query_activity(
                    store.conn, today, today, {"limit": ["1"]}
                )
                fslogix = audit_store.query_activity(
                    store.conn,
                    today,
                    today,
                    {"limit": ["1"]},
                    stream="fslogix",
                )
                total = store.conn.execute(
                    "SELECT sum(event_count) FROM audit_daily_totals"
                ).fetchone()[0]
                policy_version = store.conn.execute(
                    """
                    SELECT policy_version FROM audit_rollup_state
                    WHERE singleton = 1
                    """
                ).fetchone()[0]
            finally:
                store.close()

        self.assertEqual(main["matched"], 1)
        self.assertEqual(fslogix["matched"], 1)
        self.assertEqual(total, 2)
        self.assertEqual(policy_version, 5)

    def test_upgrade_collapses_recent_fslogix_write_duplicates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            database = os.path.join(tmpdir, "state.db")
            store = audit_store.AuditStore(database)
            event = self.make_event(f"{today}T12:00:00+00:00", "alice")
            event = dict(
                event,
                share="FSLogix",
                operation="pwrite",
                action="write",
                path="/data/fslogix/profile.vhd",
            )
            store.append_batch([event], {}, set())
            for source in ("log.pc02", "log.pc03"):
                store.conn.execute(
                    """
                    INSERT INTO audit_events (
                        occurred_at, occurred_second, ingested_at, user, account,
                        client_ip, client, share, action, result, success, path,
                        path_id, source
                    )
                    SELECT occurred_at, occurred_second, ingested_at, user,
                           account, client_ip, client, share, action, result,
                           success, path, path_id, ?
                    FROM audit_events
                    WHERE id = 1
                    """,
                    (source,),
                )
            store.conn.execute(
                "ALTER TABLE audit_event_dedup RENAME TO audit_read_dedup"
            )
            store.conn.execute(
                "UPDATE audit_rollup_state SET policy_version = 4"
            )
            store.conn.commit()
            store.close()

            store = audit_store.AuditStore(database)
            try:
                live = dict(event, source="log.live")
                live_inserted = store.append_batch([live], {}, set())
                while store.backfill_rollups(limit=1):
                    pass
                event_count = store.conn.execute(
                    "SELECT count(*) FROM audit_events"
                ).fetchone()[0]
                rolled_up = store.conn.execute(
                    "SELECT sum(event_count) FROM audit_daily_totals"
                ).fetchone()[0]
                dedup_keys = store.conn.execute(
                    "SELECT count(*) FROM audit_event_dedup"
                ).fetchone()[0]
                policy_version = store.conn.execute(
                    "SELECT policy_version FROM audit_rollup_state"
                ).fetchone()[0]
                retained_source = store.conn.execute(
                    "SELECT source FROM audit_events"
                ).fetchone()[0]
            finally:
                store.close()

        self.assertEqual(event_count, 1)
        self.assertEqual(rolled_up, 1)
        self.assertEqual(live_inserted, 1)
        self.assertEqual(retained_source, "log.live")
        self.assertEqual(dedup_keys, 1)
        self.assertEqual(policy_version, 5)


    def test_schema_has_filter_indexes_and_rollup_tables(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = audit_store.AuditStore(os.path.join(tmpdir, "state.db"))
            try:
                indexes = {
                    row[0]
                    for row in store.conn.execute(
                        "SELECT name FROM sqlite_schema WHERE type = 'index'"
                    )
                }
                tables = {
                    row[0]
                    for row in store.conn.execute(
                        "SELECT name FROM sqlite_schema WHERE type = 'table'"
                    )
                }
            finally:
                store.close()
        self.assertTrue(
            {
                "audit_events_main_time",
                "audit_events_main_action_time",
                "audit_events_main_success_time",
                "audit_events_main_user_time",
                "audit_events_main_account_time",
                "audit_events_main_share_time",
                "audit_events_main_result_time",
                "audit_events_fslogix_time",
                "audit_events_fslogix_action_time",
                "audit_events_fslogix_success_time",
                "audit_events_fslogix_user_time",
                "audit_events_fslogix_account_time",
                "audit_events_fslogix_result_time",
                "audit_event_dedup_time",
            }.issubset(indexes)
        )
        self.assertTrue(
            {
                "audit_daily_totals",
                "audit_daily_counts",
                "audit_daily_facets",
                "audit_rollup_state",
                "audit_paths",
                "audit_paths_fts",
                "audit_path_events",
                "audit_event_dedup",
            }.issubset(tables)
        )

    def test_drops_only_known_legacy_audit_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in (
                "2026-07-30.jsonl",
                "2026-07-29.jsonl.gz",
                "collector-state.json",
                "keep.txt",
            ):
                with open(os.path.join(tmpdir, name), "w", encoding="utf-8"):
                    pass

            self.assertEqual(audit_store.drop_legacy_audit_files(tmpdir), 3)
            self.assertEqual(os.listdir(tmpdir), ["keep.txt"])


class StateDatabaseMigrationTests(unittest.TestCase):
    def test_drops_only_known_recomputable_web_cache_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ("usage.json", "usage.json.tmp", "keep.txt"):
                with open(os.path.join(tmpdir, name), "w", encoding="utf-8"):
                    pass

            self.assertEqual(state_db.drop_legacy_web_cache(tmpdir), 2)
            self.assertEqual(os.listdir(tmpdir), ["keep.txt"])


class WebPresentationTests(unittest.TestCase):
    def asset(self, name):
        path = os.path.join(os.path.dirname(__file__), "..", "app", "web", name)
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_login_and_application_views_obey_hidden_attribute(self):
        html = self.asset("index.html")
        css = self.asset("styles.css")

        self.assertIn('id="login-view" class="login-view" hidden', html)
        self.assertIn('id="app-view" class="shell" hidden', html)
        self.assertIn("[hidden] { display: none !important; }", css)

    def test_ui_is_german_plain_utc_and_left_aligns_time(self):
        html = self.asset("index.html")
        script = self.asset("app.js")
        css = self.asset("styles.css")

        self.assertIn('<html lang="de">', html)
        self.assertIn("Benutzername", html)
        self.assertNotIn("nav-group", html)
        self.assertIn('>Datenbelegung</a>', html)
        self.assertIn('>Benutzerbelegung</a>', html)
        self.assertIn('href="/reconciliation" data-route="reconciliation">Freigabenabgleich</a>', html)
        self.assertIn('href="/report" data-route="report">PDF-Bericht</a>', html)
        self.assertNotIn("brand-mark", html)
        self.assertNotIn("eyebrow", html + script)
        self.assertIn("getUTCHours()", script)
        self.assertIn(" UTC`", script)
        self.assertNotIn("localTime", script)
        self.assertIn('class="timestamp"', script)
        self.assertIn(".timestamp { text-align: left;", css)
        self.assertIn("Umbenennen", script)
        self.assertNotIn("Umbenennen/Verschieben", script)
        self.assertIn("Löschen", script)
        self.assertIn("Indexaufbau", script)
        self.assertIn("/activity/fslogix", html)
        self.assertIn("/api/fslogix-activity", script)
        self.assertIn('renderActivity("fslogix")', script)
        self.assertIn('href="/trash" data-route="trash">Papierkorb</a>', html)
        self.assertIn("/api/trash?", script)
        self.assertIn("/api/trash/download?id=", script)
        self.assertIn('api("/api/trash/restore"', script)
        self.assertIn("Herunterladen", script)
        self.assertIn("Wiederherstellen", script)
        self.assertNotIn(">Auflisten<", script)
        self.assertNotIn(">Metadaten<", script)
        self.assertNotIn(">Sitzung<", script)
        self.assertNotIn('name="operation"', script)
        self.assertIn('class="shares-view"', script)
        self.assertIn('class="split shares-split"', script)
        self.assertIn(".shares-view { display: flex; height: calc(100vh - 4.5rem);", css)
        self.assertIn(".shares-split .list", css)
        self.assertIn(".shares-split .tree", css)

    def test_admin_actions_are_german_and_backup_automatic_setting_is_env_only(self):
        script = self.asset("app.js")

        self.assertIn("Sicherung jetzt starten", script)
        self.assertIn("Freigaben jetzt abgleichen", script)
        self.assertIn('api("/api/actions/backup"', script)
        self.assertIn('api("/api/actions/reconciliation"', script)
        self.assertIn('includeLog ? "/api/reconciliation"', script)
        self.assertIn('"/api/backup?log=0"', script)
        self.assertIn('"/api/reconciliation?log=0"', script)
        self.assertEqual(script.count("if (active || previousActive)"), 2)
        self.assertIn('const body = document.querySelector("#reconciliation-body")', script)
        self.assertIn("if (!body.isConnected || !button.isConnected)", script)
        self.assertNotIn('document.querySelector("#reconciliation-body").innerHTML', script)
        self.assertNotIn("BACKUP_AUTO_ENABLED", script)
        self.assertIn("data.interrupted", script)

    def test_pdf_report_is_client_side_and_uses_only_log_free_endpoint(self):
        script = self.asset("app.js")
        report = self.asset("report.mjs")
        typst = self.asset(os.path.join("vendor", "typst", "typst.mjs"))

        self.assertIn('api("/api/report")', script)
        self.assertIn('import("/assets/report.mjs")', script)
        self.assertNotIn('api("/api/activity', report)
        self.assertNotIn('api("/api/backup', report)
        self.assertIn('compiler.pdf({mainContent:', report)
        self.assertIn('/assets/vendor/typst/0.6.0-csp1/compiler.wasm', report)
        self.assertIn("getUTCHours()", report)
        self.assertIn("above: 1.8pt, below: 1.8pt", report)
        self.assertIn('["Automatik", backup.automaticEnabled ? "Aktiv" : "Ausgeschaltet"]', report)
        self.assertIn("Aktivitätsprotokoll und Sicherungsprotokoll sind nicht Bestandteil", report)
        self.assertNotIn("new Function", typst)
        self.assertIn("createCspSafeFunction", typst)

    def test_samba_audits_only_supported_file_operations(self):
        path = os.path.join(os.path.dirname(__file__), "..", "etc", "samba", "smb.conf")
        with open(path, encoding="utf-8") as handle:
            config = handle.read()

        expected = {
            "pread", "pread_recv", "read", "sendfile", "offload_read_recv",
            "pwrite", "pwrite_recv", "write", "recvfile",
            "offload_write_recv", "renameat", "unlinkat",
        }
        success_lines = [
            line for line in config.splitlines()
            if line.strip().startswith("full_audit:success =")
        ]
        failure_lines = [
            line for line in config.splitlines()
            if line.strip().startswith("full_audit:failure =")
        ]
        self.assertEqual(len(success_lines), 3)
        self.assertEqual(len(failure_lines), 3)
        fslogix_config = config.split("[FSLogix]", 1)[1]
        self.assertIn("full_audit", fslogix_config)
        for line in success_lines + failure_lines:
            self.assertEqual(set(line.split("=", 1)[1].split()), expected)

    def test_samba_recycles_all_three_shares_for_seven_day_cleanup(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(
            os.path.join(root, "etc", "samba", "smb.conf"),
            encoding="utf-8",
        ) as handle:
            config = handle.read()
        with open(os.path.join(root, "app", "init.sh"), encoding="utf-8") as handle:
            init_script = handle.read()
        with open(os.path.join(root, "Dockerfile"), encoding="utf-8") as handle:
            dockerfile = handle.read()

        for share, next_share in (
            ("Private", "Data"),
            ("Data", "FSLogix"),
            ("FSLogix", None),
        ):
            share_config = config.split(f"[{share}]", 1)[1]
            if next_share:
                share_config = share_config.split(f"[{next_share}]", 1)[0]
            # Audit must wrap recycle so an SMB deletion remains unlinkat in the
            # activity log instead of becoming the recycle module's renameat.
            self.assertIn("vfs objects = acl_xattr full_audit recycle", share_config)
            self.assertIn("recycle:repository = .trash/%U", share_config)
            self.assertIn("recycle:keeptree = yes", share_config)
            self.assertIn("recycle:versions = yes", share_config)
            self.assertIn("recycle:touch_mtime = yes", share_config)
            self.assertIn("recycle:exclude = *.tmp,*.TMP,~$*", share_config)
            self.assertIn("recycle:exclude_dir = .trash", share_config)
            self.assertIn("veto files = /.trash/", share_config)

        for module in ("acl_xattr", "recycle", "full_audit"):
            self.assertIn(module, init_script)
        self.assertIn("/app/trash.py --cleanup", init_script)
        self.assertIn("TRASH_RETENTION_DAYS", init_script)
        self.assertIn("COPY app/trash.py /app/trash.py", dockerfile)

    def test_application_has_no_favicon(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        web_root = os.path.join(root, "app", "web")
        with open(os.path.join(web_root, "index.html"), encoding="utf-8") as handle:
            index = handle.read()
        with open(os.path.join(root, "app", "web_ui.py"), encoding="utf-8") as handle:
            server = handle.read()

        self.assertNotIn("favicon", index.casefold())
        self.assertNotIn("favicon", server.casefold())
        self.assertFalse(os.path.exists(os.path.join(web_root, "favicon.svg")))

    def test_disposable_dc_is_compatible_with_rootless_podman(self):
        root = os.path.join(os.path.dirname(__file__), "..")
        with open(
            os.path.join(root, "dev", "ad-dc.Dockerfile"),
            encoding="utf-8",
        ) as handle:
            dockerfile = handle.read()
        with open(
            os.path.join(root, "dev", "ad-entrypoint.sh"),
            encoding="utf-8",
        ) as handle:
            entrypoint = handle.read()
        with open(os.path.join(root, "scripts", "dev"), encoding="utf-8") as handle:
            launcher = handle.read()

        self.assertIn("lowerBound: 10000", dockerfile)
        self.assertIn("upperBound: 60000", dockerfile)
        self.assertIn("xattr_tdb:file = /var/lib/samba/state/xattr.tdb", entrypoint)
        self.assertIn("samba-tool ntacl sysvolcheck", entrypoint)
        self.assertNotIn("--use-rfc2307", entrypoint)
        self.assertNotIn("--cap-add SYS_ADMIN", launcher)


class TlsSummaryTests(unittest.TestCase):
    @mock.patch("app.web_ui.ssl._ssl._test_decode_cert")
    def test_certificate_expiry_is_returned_as_utc_iso_timestamp(self, decode):
        decode.return_value = {"notAfter": "Jul 31 12:34:56 2027 GMT"}

        self.assertEqual(web_ui.tls_summary()["notAfter"], "2027-07-31T12:34:56+00:00")


class UsageScannerTests(unittest.TestCase):
    def test_aggregates_private_and_fslogix_by_user(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            group_root = os.path.join(tmpdir, "data")
            private_root = os.path.join(tmpdir, "private")
            fslogix_root = os.path.join(tmpdir, "fslogix")
            os.makedirs(os.path.join(group_root, "Finance"))
            os.makedirs(os.path.join(private_root, "alice"))
            os.makedirs(os.path.join(fslogix_root, "alice_S-1-5-21-1-2-3-1001"))
            os.makedirs(os.path.join(group_root, ".trash", "alice"))
            os.makedirs(os.path.join(private_root, ".trash", "alice"))
            os.makedirs(os.path.join(fslogix_root, ".trash", "alice"))
            with open(os.path.join(group_root, "Finance", "a"), "wb") as handle:
                handle.write(b"a" * 7)
            with open(os.path.join(private_root, "alice", "b"), "wb") as handle:
                handle.write(b"b" * 3)
            with open(os.path.join(fslogix_root, "alice_S-1-5-21-1-2-3-1001", "c"), "wb") as handle:
                handle.write(b"c" * 5)
            for root in (group_root, private_root, fslogix_root):
                with open(
                    os.path.join(root, ".trash", "alice", "deleted"),
                    "wb",
                ) as handle:
                    handle.write(b"x" * 100)
            database = os.path.join(tmpdir, "state.db")

            env = {"GROUP_ROOT": group_root, "PRIVATE_ROOT": private_root, "FSLOGIX_ROOT": fslogix_root}
            with mock.patch.dict(os.environ, env), mock.patch.object(web_ui, "STATE_DB", database), mock.patch.object(web_ui, "fslogix_username", return_value="alice"):
                value = web_ui.UsageScanner().scan()

            self.assertEqual(value["totals"]["dataBytes"], 7)
            self.assertEqual(value["users"][0]["privateBytes"], 3)
            self.assertEqual(value["users"][0]["fslogixBytes"], 5)
            self.assertEqual(value["users"][0]["totalBytes"], 8)
            conn = sqlite3.connect(database)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM web_cache WHERE key = 'usage'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
