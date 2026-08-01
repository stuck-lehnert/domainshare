import io
import os
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

from app import backup_to_destination as backup


class BackupLoggerTests(unittest.TestCase):
    def test_logger_writes_console_and_timestamped_file(self):
        console = io.StringIO()
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "backup.log")
            logger = backup.BackupLogger(console_stream=console, error_stream=errors)
            logger.configure(log_path)
            logger.log("hello")
            logger.close()

            self.assertEqual(console.getvalue(), "[backup] hello\n")
            self.assertEqual(errors.getvalue(), "")
            with open(log_path, encoding="utf-8") as handle:
                contents = handle.read()

        self.assertRegex(
            contents,
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00 \[backup\] hello\n$",
        )


class ProgressConfigTests(unittest.TestCase):
    def test_parse_progress_mode_accepts_known_values(self):
        with mock.patch.dict(os.environ, {"BACKUP_PROGRESS": "ALWAYS"}):
            self.assertEqual(backup.parse_progress_mode(), "always")

    def test_parse_progress_mode_defaults_invalid_values(self):
        with mock.patch.dict(os.environ, {"BACKUP_PROGRESS": "loud"}):
            with mock.patch.object(backup, "log") as log:
                self.assertEqual(backup.parse_progress_mode(), "auto")
        log.assert_called_once()

    def test_should_show_progress_bar_honors_mode_and_tty(self):
        class Stream:
            def __init__(self, is_tty):
                self.is_tty = is_tty

            def isatty(self):
                return self.is_tty

        self.assertTrue(backup.should_show_progress_bar("always", Stream(False)))
        self.assertFalse(backup.should_show_progress_bar("never", Stream(True)))
        self.assertTrue(backup.should_show_progress_bar("auto", Stream(True)))
        self.assertFalse(backup.should_show_progress_bar("auto", Stream(False)))


class ProgressParsingTests(unittest.TestCase):
    def test_splitter_handles_carriage_returns_newlines_and_ansi(self):
        splitter = backup.OutputRecordSplitter()

        self.assertEqual(splitter.feed("\x1b[2Kone\rtwo\n\nthree"), ["one", "two"])
        self.assertEqual(splitter.close(), ["three"])

    def test_parse_rclone_file_progress_includes_bytes(self):
        progress = backup.parse_rclone_progress_record(
            " * data/private/file.txt: 50% /10Mi, 2Mi/s, ETA 4s"
        )

        self.assertEqual(progress.file_path, "data/private/file.txt")
        self.assertEqual(progress.percent, 50.0)
        self.assertEqual(progress.transferred_bytes, 5 * 1024 * 1024)
        self.assertEqual(progress.total_bytes, 10 * 1024 * 1024)
        self.assertEqual(progress.detail, "/10Mi, 2Mi/s, ETA 4s")

    def test_parse_rsync_file_progress_uses_current_file_and_bytes(self):
        progress = backup.parse_rsync_progress_record(
            "        1,024 50% 1.00MB/s 0:00:01", "dir/file.bin"
        )

        self.assertEqual(progress.file_path, "dir/file.bin")
        self.assertEqual(progress.percent, 50.0)
        self.assertEqual(progress.transferred_bytes, 1024)
        self.assertEqual(progress.total_bytes, 2048)
        self.assertEqual(progress.detail, "1.00MB/s 0:00:01")

    def test_format_amounts_uses_auto_units(self):
        self.assertEqual(backup.format_amounts(1536, 4096), "1.50 kB / 2.50 kB left")
        self.assertEqual(
            backup.format_amounts(5 * 1024**3, 8 * 1024**3),
            "5.00 GB / 3.00 GB left",
        )

    def test_reporter_throttles_progress_but_logs_final_event(self):
        clock = [0.0]
        logs = []
        overall = backup.OverallProgress(100)
        reporter = backup.SyncProgressReporter(
            "rsync",
            "/src",
            "data/private",
            source_total_bytes=100,
            overall_progress=overall,
            interval_seconds=10,
            interactive=True,
            stream=io.StringIO(),
            now=lambda: clock[0],
            log_func=lambda message, console=True: logs.append((message, console)),
        )

        reporter.observe("dir/file.bin")
        reporter.observe("        10 10% 1.00MB/s 0:00:09")
        clock[0] = 5.0
        reporter.observe("        20 20% 1.00MB/s 0:00:08")
        clock[0] = 10.0
        reporter.observe("        30 30% 1.00MB/s 0:00:07")
        clock[0] = 11.0
        reporter.observe("       100 100% 1.00MB/s 0:00:00")

        file_logs = [entry for entry in logs if entry[0].startswith("Upload progress ")]

        self.assertEqual(len(file_logs), 3)
        self.assertIn("dir/file.bin 10%", file_logs[0][0])
        self.assertIn("10 B / 90 B left", file_logs[0][0])
        self.assertIn("dir/file.bin 30%", file_logs[1][0])
        self.assertIn("dir/file.bin 100%", file_logs[2][0])
        self.assertTrue(any(entry[0].startswith("Total upload progress") for entry in logs))
        self.assertTrue(all(console is False for _, console in logs))


    def test_interactive_dashboard_renders_total_row_at_bottom(self):
        stream = io.StringIO()
        reporter = backup.SyncProgressReporter(
            "rclone",
            "/src",
            "data/private",
            source_total_bytes=2048,
            overall_progress=backup.OverallProgress(2048),
            interval_seconds=10,
            interactive=True,
            stream=stream,
            now=lambda: 0.0,
            log_func=lambda message, console=True: None,
        )

        reporter.observe(" * file-a.bin: 50% /1Ki, 1Ki/s, ETA 1s")

        rendered = stream.getvalue()
        self.assertLess(rendered.index("file-a.bin"), rendered.rindex("TOTAL"))

    def test_visible_active_files_are_limited_to_twelve(self):
        reporter = backup.SyncProgressReporter(
            "rclone",
            "/src",
            "data/private",
            source_total_bytes=20 * 1024,
            overall_progress=backup.OverallProgress(20 * 1024),
            interval_seconds=10,
            interactive=False,
            now=lambda: 100.0,
            log_func=lambda message, console=True: None,
        )
        for index in range(20):
            reporter._active_files[f"file-{index}"] = backup.FileProgress(
                file_path=f"file-{index}",
                percent=10,
                transferred_bytes=10,
                total_bytes=100,
                detail="",
            )
            reporter._active_seen_at[f"file-{index}"] = 100.0 + float(index)

        self.assertEqual(len(reporter._visible_active_files()), 12)

    def test_measure_backup_payload_sums_regular_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "nested")
            os.mkdir(nested)
            with open(os.path.join(tmpdir, "one.bin"), "wb") as handle:
                handle.write(b"a" * 3)
            with open(os.path.join(nested, "two.bin"), "wb") as handle:
                handle.write(b"b" * 5)

            sizes, total = backup.measure_backup_payload([(tmpdir, "data/private")])

        self.assertEqual(sizes[tmpdir], 8)
        self.assertEqual(total, 8)


class GroupArchiveTests(unittest.TestCase):
    def test_archive_password_is_required_and_rejects_control_characters(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "BACKUP_ARCHIVE_PASSWORD"):
                backup.archive_password()

        with mock.patch.dict(
            os.environ, {"BACKUP_ARCHIVE_PASSWORD": "secret\nsecond-line"}, clear=True
        ):
            with self.assertRaisesRegex(RuntimeError, "unsupported characters"):
                backup.archive_password()

    def test_groups_are_staged_as_encrypted_non_solid_archives(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source_root = os.path.join(tmpdir, "groups")
            os.makedirs(os.path.join(source_root, "data", "Finance"))
            os.makedirs(os.path.join(source_root, "archive", "Former"))
            os.makedirs(os.path.join(source_root, "metadata"))
            with open(
                os.path.join(source_root, "data", "Finance", "report.txt"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("finance")
            with open(
                os.path.join(source_root, "archive", "Former", "old.txt"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("former")
            with open(
                os.path.join(source_root, "data", "README.txt"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("preserve me")
            with open(
                os.path.join(source_root, "metadata", "index.txt"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("metadata")

            commands = []

            def fake_run(command, **kwargs):
                commands.append((command, kwargs))
                archive_path = command[-3]
                with open(archive_path, "wb") as handle:
                    handle.write(b"dummy-7z")
                return backup.subprocess.CompletedProcess(command, 0, "", "")

            staged_temp = None
            try:
                with mock.patch.object(backup, "run_command", side_effect=fake_run):
                    staged_temp, staged_root, count = backup.prepare_group_archives(
                        source_root, "archive secret", tmpdir
                    )

                self.assertEqual(count, 2)
                self.assertTrue(
                    os.path.isfile(os.path.join(staged_root, "data", "Finance.7z"))
                )
                self.assertTrue(
                    os.path.isfile(os.path.join(staged_root, "archive", "Former.7z"))
                )
                self.assertTrue(
                    os.path.isfile(os.path.join(staged_root, "data", "README.txt"))
                )
                self.assertTrue(
                    os.path.isfile(os.path.join(staged_root, "metadata", "index.txt"))
                )
                self.assertFalse(
                    os.path.exists(os.path.join(staged_root, "data", "Finance"))
                )

                self.assertEqual(len(commands), 2)
                for command, kwargs in commands:
                    self.assertEqual(command[:3], ["7z", "a", "-t7z"])
                    self.assertIn("-m0=lzma2", command)
                    self.assertIn("-mx=5", command)
                    self.assertIn("-mmt=on", command)
                    self.assertIn("-ms=off", command)
                    self.assertIn("-mhe=on", command)
                    self.assertIn("-p", command)
                    self.assertNotIn("archive secret", command)
                    self.assertEqual(kwargs["input_text"], "archive secret\n")
                    self.assertFalse(kwargs["check"])
                    self.assertTrue(os.path.isdir(kwargs["cwd"]))
            finally:
                if staged_temp is not None:
                    shutil.rmtree(staged_temp, ignore_errors=True)

    @unittest.skipUnless(shutil.which("7z"), "7z is needed for the archive smoke test")
    def test_real_archive_is_encrypted_and_non_solid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = os.path.join(tmpdir, "Finance")
            archive_path = os.path.join(tmpdir, "Finance.7z")
            os.mkdir(source)
            with open(os.path.join(source, "report.txt"), "w", encoding="utf-8") as handle:
                handle.write("classified")

            backup.create_group_archive(source, archive_path, "correct secret")

            correct = subprocess.run(
                [shutil.which("7z"), "l", "-slt", archive_path],
                input="correct secret\n",
                capture_output=True,
                text=True,
                check=False,
            )
            wrong = subprocess.run(
                [shutil.which("7z"), "l", "-slt", archive_path],
                input="wrong secret\n",
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(correct.returncode, 0, correct.stdout + correct.stderr)
        self.assertIn("Solid = -", correct.stdout)
        self.assertIn("Path = Finance/report.txt", correct.stdout)
        self.assertNotEqual(wrong.returncode, 0)


class StateSnapshotTests(unittest.TestCase):
    def test_online_snapshot_includes_wal_commits_and_other_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = os.path.join(tmpdir, "state")
            os.mkdir(state_root)
            database = os.path.join(state_root, "shares.db")
            with open(os.path.join(state_root, "backup-status.json"), "w", encoding="utf-8") as handle:
                handle.write("status")

            writer = sqlite3.connect(database)
            writer.execute("PRAGMA journal_mode = WAL")
            writer.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT)")
            writer.execute("INSERT INTO events (value) VALUES ('committed-in-wal')")
            writer.commit()
            snapshot_root = None
            try:
                snapshot_root, staged_state = backup.prepare_state_snapshot(
                    state_root,
                    database,
                )
                staged_database = os.path.join(staged_state, "shares.db")
                reader = sqlite3.connect(staged_database)
                try:
                    self.assertEqual(
                        reader.execute("SELECT value FROM events").fetchone()[0],
                        "committed-in-wal",
                    )
                    self.assertEqual(reader.execute("PRAGMA quick_check").fetchone()[0], "ok")
                finally:
                    reader.close()
                with open(os.path.join(staged_state, "backup-status.json"), encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), "status")
                self.assertFalse(os.path.exists(f"{staged_database}-wal"))
                self.assertFalse(os.path.exists(f"{staged_database}-shm"))
            finally:
                writer.close()
                if snapshot_root is not None:
                    shutil.rmtree(snapshot_root, ignore_errors=True)

    def test_state_database_must_be_inside_state_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state_root = os.path.join(tmpdir, "state")
            os.mkdir(state_root)
            database = os.path.join(tmpdir, "outside.db")
            sqlite3.connect(database).close()

            with self.assertRaisesRegex(RuntimeError, "below STATE_ROOT"):
                backup.prepare_state_snapshot(state_root, database)


class BackendProgressCommandTests(unittest.TestCase):
    def test_rclone_sync_uses_progress_flags(self):
        destination = backup.parse_destination("sftp://user@example.com/backups")
        backend = backup.RcloneBackend(destination)
        try:
            with mock.patch.object(backup, "run_streaming_command") as run_streaming:
                backend.sync_source(
                    "20260101T000000Z",
                    "/src",
                    "data/private",
                    source_total_bytes=1024,
                    overall_progress=backup.OverallProgress(1024),
                    progress_interval_seconds=7,
                    interactive_progress=False,
                )

            command = run_streaming.call_args.args[0]
            self.assertIn("--progress", command)
            self.assertIn("--stats", command)
            self.assertIn("7s", command)
            self.assertIn("--transfers", command)
            self.assertIn(str(backup.MAX_PARALLEL_FILE_UPLOADS), command)
            self.assertIn("--log-level", command)
            self.assertIn("INFO", command)
            self.assertIn("--config", command)
            self.assertEqual(
                run_streaming.call_args.kwargs["progress"].backend_name, "rclone"
            )
        finally:
            backend.close()

    def test_rsync_sync_uses_progress_flags(self):
        destination = backup.parse_destination("rsync://user@example.com/module/path")
        backend = backup.RsyncBackend(destination)

        with mock.patch.object(backup, "run_streaming_command") as run_streaming:
            backend.sync_source(
                "20260101T000000Z",
                "/src",
                "data/private",
                source_total_bytes=1024,
                overall_progress=backup.OverallProgress(1024),
                progress_interval_seconds=7,
                interactive_progress=False,
            )

        command = run_streaming.call_args.args[0]
        self.assertIn("--mkpath", command)
        self.assertIn("--progress", command)
        self.assertIn("--outbuf=L", command)
        self.assertEqual(
            run_streaming.call_args.kwargs["progress"].backend_name, "rsync"
        )
        self.assertIs(run_streaming.call_args.kwargs["env"], backend.command_env)


if __name__ == "__main__":
    unittest.main()
