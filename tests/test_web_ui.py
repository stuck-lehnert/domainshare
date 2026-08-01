import datetime as dt
import os
import sqlite3
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
        self.assertNotIn("brand-mark", html)
        self.assertNotIn("eyebrow", html + script)
        self.assertIn("getUTCHours()", script)
        self.assertIn(" UTC`", script)
        self.assertNotIn("localTime", script)
        self.assertIn('class="timestamp"', script)
        self.assertIn(".timestamp { text-align: left;", css)
        self.assertIn("Umbenennen/Verschieben", script)
        self.assertIn("Löschen", script)
        self.assertNotIn(">Auflisten<", script)
        self.assertNotIn(">Metadaten<", script)
        self.assertNotIn(">Sitzung<", script)
        self.assertNotIn('name="operation"', script)

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
