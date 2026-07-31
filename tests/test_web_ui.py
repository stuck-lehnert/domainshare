import datetime as dt
import gzip
import json
import os
import tempfile
import unittest
from unittest import mock

from app import audit_collector
from app import web_ui


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

    def test_tracks_rotated_file_by_inode_without_reingesting_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = os.path.join(tmpdir, "audit")
            os.mkdir(archive)
            active = os.path.join(tmpdir, "log.pc01")
            line = (
                "[2026/07/31 12:34:56.000000, 1] smbd_audit: "
                "x|alice|192.0.2.5|PC01|Data|pread|OK|a.txt\n"
            )
            with open(active, "w", encoding="utf-8") as handle:
                handle.write(line)

            with mock.patch.object(audit_collector, "SAMBA_LOG_GLOB", os.path.join(tmpdir, "log.*")), mock.patch.object(audit_collector, "ARCHIVE_DIR", archive), mock.patch.object(audit_collector, "STATE_FILE", os.path.join(archive, "state.json")):
                state = {}
                self.assertEqual(audit_collector.collect_once(state), 1)
                rotated = f"{active}.old"
                os.rename(active, rotated)
                with open(active, "w", encoding="utf-8") as handle:
                    handle.write(line.replace("a.txt", "b.txt"))
                self.assertEqual(audit_collector.collect_once(state), 1)


class AuditQueryTests(unittest.TestCase):
    def make_event(self, timestamp, user, success=True):
        return {
            "timestamp": timestamp,
            "user": user,
            "clientIp": "192.0.2.5",
            "share": "Data",
            "operation": "pread" if success else "openat",
            "action": "read" if success else "metadata",
            "path": "folder/file.txt",
            "result": "OK" if success else "NT_STATUS_ACCESS_DENIED",
            "success": success,
        }

    def test_queries_plain_and_compressed_days_with_filters_and_cursor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            today = dt.datetime.now(dt.timezone.utc).date()
            yesterday = today - dt.timedelta(days=1)
            current = os.path.join(tmpdir, f"{today.isoformat()}.jsonl")
            old = os.path.join(tmpdir, f"{yesterday.isoformat()}.jsonl.gz")
            with open(current, "w", encoding="utf-8") as handle:
                for index in range(3):
                    handle.write(json.dumps(self.make_event(f"{today}T12:00:0{index}+00:00", "alice")) + "\n")
                handle.write(json.dumps(self.make_event(f"{today}T12:00:04+00:00", "bob", False)) + "\n")
            with gzip.open(old, "wt", encoding="utf-8") as handle:
                handle.write(json.dumps(self.make_event(f"{yesterday}T12:00:00+00:00", "alice")) + "\n")

            with mock.patch.object(web_ui, "AUDIT_ROOT", tmpdir):
                first = web_ui.query_audit({"from": [yesterday.isoformat()], "to": [today.isoformat()], "user": ["alice"], "limit": ["2"]})
                failed = web_ui.query_audit({"from": [today.isoformat()], "to": [today.isoformat()], "result": ["fail"]})
                second = web_ui.query_audit({"from": [yesterday.isoformat()], "to": [today.isoformat()], "user": ["alice"], "limit": ["2"], "cursor": [str(first["nextCursor"])]})

        self.assertEqual(first["matched"], 4)
        self.assertEqual(len(first["events"]), 2)
        self.assertEqual(len(second["events"]), 2)
        self.assertEqual(failed["events"][0]["user"], "bob")


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
            cache = os.path.join(tmpdir, "usage.json")

            env = {"GROUP_ROOT": group_root, "PRIVATE_ROOT": private_root, "FSLOGIX_ROOT": fslogix_root}
            with mock.patch.dict(os.environ, env), mock.patch.object(web_ui, "USAGE_CACHE_FILE", cache), mock.patch.object(web_ui, "fslogix_username", return_value="alice"):
                value = web_ui.UsageScanner().scan()

        self.assertEqual(value["totals"]["dataBytes"], 7)
        self.assertEqual(value["users"][0]["privateBytes"], 3)
        self.assertEqual(value["users"][0]["fslogixBytes"], 5)
        self.assertEqual(value["users"][0]["totalBytes"], 8)


if __name__ == "__main__":
    unittest.main()
