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

    def test_parse_rclone_file_progress(self):
        progress = backup.parse_rclone_progress_record(
            " * data/private/file.txt: 42.5% /10Mi, 2Mi/s, ETA 4s"
        )

        self.assertEqual(progress.file_path, "data/private/file.txt")
        self.assertEqual(progress.percent, 42.5)
        self.assertEqual(progress.detail, "/10Mi, 2Mi/s, ETA 4s")

    def test_parse_rsync_file_progress_uses_current_file(self):
        progress = backup.parse_rsync_progress_record(
            "        1,024 50% 1.00MB/s 0:00:01", "dir/file.bin"
        )

        self.assertEqual(progress.file_path, "dir/file.bin")
        self.assertEqual(progress.percent, 50.0)
        self.assertEqual(progress.detail, "1.00MB/s 0:00:01")

    def test_reporter_throttles_progress_but_logs_final_event(self):
        clock = [0.0]
        logs = []
        reporter = backup.SyncProgressReporter(
            "rsync",
            "/src",
            "data/private",
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

        self.assertEqual(len(logs), 3)
        self.assertIn("dir/file.bin 10%", logs[0][0])
        self.assertIn("dir/file.bin 30%", logs[1][0])
        self.assertIn("dir/file.bin 100%", logs[2][0])
        self.assertEqual([console for _, console in logs], [False, False, False])


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
                    progress_interval_seconds=7,
                    interactive_progress=False,
                )

            command = run_streaming.call_args.args[0]
            self.assertIn("--progress", command)
            self.assertIn("--stats", command)
            self.assertIn("7s", command)
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
