import io
import os
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
        self.assertIn("--progress", command)
        self.assertIn("--outbuf=L", command)
        self.assertEqual(
            run_streaming.call_args.kwargs["progress"].backend_name, "rsync"
        )
        self.assertIs(run_streaming.call_args.kwargs["env"], backend.command_env)


if __name__ == "__main__":
    unittest.main()
