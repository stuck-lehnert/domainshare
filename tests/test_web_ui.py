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
            read = (
                "[2026/07/31 12:34:56.000000, 1] smbd_audit: "
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

    def test_deduplicates_only_uninterrupted_identical_reads_in_one_second(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            active = os.path.join(tmpdir, "log.pc01")
            database = os.path.join(tmpdir, "state.db")

            def line(operation, path, second="12:34:56"):
                return (
                    f"[2026/07/31 {second}.000000, 1] smbd_audit: "
                    f"x|alice|192.0.2.5|PC01|Data|{operation}|OK|{path}\n"
                )

            with open(active, "w", encoding="utf-8") as handle:
                handle.writelines(
                    [
                        line("pread", "a.txt"),
                        line("pread", "a.txt"),
                        line("pread", "b.txt"),
                        line("pread", "a.txt"),
                        line("pread", "a.txt"),
                    ]
                )

            store = audit_store.AuditStore(database)
            try:
                with mock.patch.object(
                    audit_collector,
                    "SAMBA_LOG_GLOB",
                    os.path.join(tmpdir, "log.*"),
                ):
                    self.assertEqual(audit_collector.collect_once(store), 3)
                    with open(active, "a", encoding="utf-8") as handle:
                        handle.write(line("pread", "a.txt"))
                    self.assertEqual(audit_collector.collect_once(store), 0)
                    with open(active, "a", encoding="utf-8") as handle:
                        handle.write(line("pwrite", "changed.txt"))
                        handle.write(line("pread", "a.txt"))
                    self.assertEqual(audit_collector.collect_once(store), 2)
                    with open(active, "a", encoding="utf-8") as handle:
                        handle.write(line("pread", "a.txt", "12:34:57"))
                    self.assertEqual(audit_collector.collect_once(store), 1)

                rows = store.conn.execute(
                    "SELECT action, path, occurred_at FROM audit_events ORDER BY id"
                ).fetchall()
                self.assertEqual(
                    [(row["action"], row["path"]) for row in rows],
                    [
                        ("read", "a.txt"),
                        ("read", "b.txt"),
                        ("read", "a.txt"),
                        ("write", "changed.txt"),
                        ("read", "a.txt"),
                        ("read", "a.txt"),
                    ],
                )
                self.assertTrue(rows[-1]["occurred_at"].endswith("12:34:57+00:00"))
            finally:
                store.close()


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

    def test_schema_has_filter_and_time_indexes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = audit_store.AuditStore(os.path.join(tmpdir, "state.db"))
            try:
                indexes = {
                    row[0]
                    for row in store.conn.execute(
                        "SELECT name FROM sqlite_schema WHERE type = 'index'"
                    )
                }
            finally:
                store.close()
        self.assertTrue(
            {
                "audit_events_time",
                "audit_events_action_time",
                "audit_events_success_time",
                "audit_events_user_time",
                "audit_events_account_time",
                "audit_events_share_time",
                "audit_events_result_time",
            }.issubset(indexes)
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
        self.assertNotIn("BACKUP_AUTO_ENABLED", script)

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
        for line in success_lines + failure_lines:
            self.assertEqual(set(line.split("=", 1)[1].split()), expected)


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
            with open(os.path.join(group_root, "Finance", "a"), "wb") as handle:
                handle.write(b"a" * 7)
            with open(os.path.join(private_root, "alice", "b"), "wb") as handle:
                handle.write(b"b" * 3)
            with open(os.path.join(fslogix_root, "alice_S-1-5-21-1-2-3-1001", "c"), "wb") as handle:
                handle.write(b"c" * 5)
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
