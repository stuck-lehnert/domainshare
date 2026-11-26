import io
import os
from pathlib import Path
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


class BackupStatusTests(unittest.TestCase):
    def test_status_records_and_clears_worker_pid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            status = backup.BackupStatus(
                os.path.join(tmpdir, "backup-status.json")
            )
            status.begin("rsync://backup.test/target", "manual")
            self.assertEqual(status.value["workerPid"], os.getpid())

            status.complete("done")

        self.assertIsNone(status.value["workerPid"])
        self.assertEqual(status.value["state"], "completed")



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
            os.makedirs(os.path.join(tmpdir, ".trash", "alice"))
            with open(
                os.path.join(tmpdir, ".trash", "alice", "deleted.bin"), "wb"
            ) as handle:
                handle.write(b"x" * 100)

            sizes, total = backup.measure_backup_payload([(tmpdir, "data/private")])

        self.assertEqual(sizes[tmpdir], 8)
        self.assertEqual(total, 8)


class GroupArchiveTests(unittest.TestCase):
    def test_archiving_accepts_only_missing_file_warnings(self):
        missing = "WARNING: errno=2 : No such file or directory\nFinance/gone.txt\n"
        denied = "WARNING: errno=13 : Permission denied\nFinance/private.txt\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "Finance"
            source.mkdir()
            archive = Path(tmpdir) / "Finance.7z"
            archive.write_bytes(b"staged archive")

            for code, stderr, accepted in ((1, missing, True), (1, missing + denied, False),
                                          (1, denied, False), (2, missing, False)):
                with self.subTest(code=code, stderr=stderr):
                    result = backup.subprocess.CompletedProcess([], code, "", stderr)
                    with mock.patch.object(backup, "run_command", return_value=result) as run:
                        if accepted:
                            self.assertTrue(backup.create_group_archive(str(source), str(archive), None))
                            self.assertIn("-xr!~$*", run.call_args.args[0])
                        else:
                            with self.assertRaisesRegex(RuntimeError, "Unable to archive"):
                                backup.create_group_archive(str(source), str(archive), None)

    def test_missing_archive_is_only_skipped_when_whole_source_has_vanished(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "Finance"
            archive = Path(tmpdir) / "Finance.7z"
            missing = "WARNING: No such file or directory\nFinance\n"
            result = backup.subprocess.CompletedProcess([], 1, "", missing)

            with mock.patch.object(backup, "run_command", return_value=result):
                self.assertFalse(backup.create_group_archive(str(source), str(archive), None))
                source.mkdir()
                with self.assertRaisesRegex(RuntimeError, "Unable to archive"):
                    backup.create_group_archive(str(source), str(archive), None)

    def test_staging_skips_entries_that_disappear_after_the_directory_is_listed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "groups"
            data = root / "data"
            data.mkdir(parents=True)
            gone = data / "temporary.txt"
            gone.touch()
            (data / "~$report.docx").touch()
            (data / "report.docx").write_bytes(b"report")

            scan = backup.scan_live_backup_directory

            def scan_and_remove(path):
                entries = scan(path)
                if Path(path) == data:
                    gone.unlink()
                return entries

            with mock.patch.object(backup, "scan_live_backup_directory", side_effect=scan_and_remove):
                _, staged, count = backup.prepare_group_archives(str(root), "", tmpdir)

            self.assertEqual(count, 0)
            self.assertEqual([file.name for file in (Path(staged) / "data").iterdir()], ["report.docx"])

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
            os.makedirs(os.path.join(source_root, "data", ".trash", "alice"))
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
                os.path.join(source_root, "data", ".trash", "alice", "deleted.txt"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write("retained deletion")
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
                self.assertFalse(
                    os.path.exists(os.path.join(staged_root, "data", ".trash"))
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
    def test_document_cache_is_omitted_without_changing_originals_or_access_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            cache = state / "documents"
            cache.mkdir(parents=True)
            (cache / "search.db").write_bytes(b"derived index")
            original = Path(tmpdir) / "original.pdf"
            original.write_bytes(b"original PDF bytes")
            database = state / "shares.db"
            sqlite3.connect(database).close()
            (state / "data-xattrs.tdb").write_bytes(b"access records")
            pending = state / backup.PENDING_SNAPSHOTS_DIRECTORY
            pending.mkdir()
            (pending / "journal").write_text("20260101T000000Z\n")
            for suffix in ('', '-wal', '-shm', '-journal'):
                (state / ('agent-tokens.db' + suffix)).write_bytes(b'agent token state')
            with mock.patch.dict(os.environ, {"DOCUMENT_STATE_ROOT": str(cache)}):
                snapshot_root, staged = backup.prepare_state_snapshot(str(state), str(database))
            try:
                self.assertFalse((Path(staged) / "documents").exists())
                self.assertFalse((Path(staged) / pending.name).exists())
                self.assertEqual(list(Path(staged).glob('agent-tokens.db*')), [])
                self.assertEqual((cache / "search.db").read_bytes(), b"derived index")
                self.assertEqual(original.read_bytes(), b"original PDF bytes")
                self.assertEqual((Path(staged) / "data-xattrs.tdb").read_bytes(), b"access records")
                self.assertTrue((Path(staged) / "shares.db").exists())
            finally:
                shutil.rmtree(snapshot_root)

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
    def test_only_rsync_source_vanished_exit_code_is_tolerated(self):
        for code, accepted in ((24, True), (23, False), (11, False)):
            with self.subTest(code=code):
                process = mock.Mock(stdout=io.StringIO("transfer output\n"))
                process.poll.return_value = code
                process.wait.return_value = code
                progress = mock.Mock()
                with mock.patch.object(backup.subprocess, "Popen", return_value=process):
                    if accepted:
                        backup.run_streaming_command(["rsync"], progress=progress, accept_vanished_source=True)
                    else:
                        with self.assertRaisesRegex(RuntimeError, "transfer output"):
                            backup.run_streaming_command(["rsync"], progress=progress, accept_vanished_source=True)
                progress.finish.assert_called_once_with(success=accepted)

    def test_rclone_retries_vanished_source_but_does_not_hide_failed_retry(self):
        destination = backup.parse_destination("sftp://backup.example.test/path")
        backend = backup.RcloneBackend(destination)
        self.addCleanup(backend.close)
        missing = RuntimeError("Failed to copy: failed to open source object: lstat /source/gone: no such file or directory")
        denied = RuntimeError("Failed to copy: permission denied")
        kwargs = dict(source_total_bytes=1, overall_progress=backup.OverallProgress(1),
                      progress_interval_seconds=2, interactive_progress=False)

        with mock.patch.object(backup, "run_streaming_command", side_effect=[missing, None]) as run:
            backend.sync_source("20260101T000000Z", "/source", "data/private", **kwargs)
            self.assertEqual(run.call_count, 2)

        with mock.patch.object(backup, "run_streaming_command", side_effect=[missing, denied]):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                backend.sync_source("20260101T000000Z", "/source", "data/private", **kwargs)

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
            self.assertIn("--exclude", command)
            self.assertIn("~$*", command)
            self.assertIn("/.trash/**", command)
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
        self.assertIn("--exclude=/.trash/", command)
        self.assertIn("--exclude=~$*", command)
        self.assertTrue(run_streaming.call_args.kwargs["accept_vanished_source"])
        self.assertEqual(
            run_streaming.call_args.kwargs["progress"].backend_name, "rsync"
        )
        self.assertIs(run_streaming.call_args.kwargs["env"], backend.command_env)


class SnapshotCleanupTests(unittest.TestCase):
    snapshot = "20260102T000000Z"
    previous = "20260101T000000Z"

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.destination = backup.parse_destination("rsync://backup.example.test/module/path")
        self.enterContext(mock.patch.object(backup, "STATE_ROOT", str(self.root / "state")))
        self.pending = Path(backup.pending_snapshot_path(self.destination))

    def test_destination_journal_is_scoped_to_target_and_namespace(self):
        old = backup.parse_destination("rsync://backup:old@backup.example.test/module/path/plain")
        new = backup.parse_destination("rsync://backup:new@backup.example.test/module/path/plain")
        self.assertEqual(backup.pending_snapshot_path(old), backup.pending_snapshot_path(new))
        new.path = "/module/path/keys/0123456789abcdef01234567"
        self.assertNotEqual(backup.pending_snapshot_path(old), backup.pending_snapshot_path(new))

    def test_failed_transfer_cleans_only_its_partial_snapshot_and_local_stage(self):
        staged = self.root / "staged-state"
        staged.mkdir()
        Path(backup.STATE_ROOT).mkdir()
        backend = mock.Mock()
        orphan = "20260101T010000Z"
        backend.list_snapshot_directories.side_effect = [
            [self.previous, orphan], [self.previous, orphan, self.snapshot],
        ]
        backend.snapshot_has_marker.return_value = False
        backend.sync_source.side_effect = RuntimeError("transfer failed")
        environment = {
            "BACKUP_DESTINATION": self.destination.raw_url,
            "BACKUP_STATUS_FILE": str(self.root / "status.json"),
        }

        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(backup, "BACKUP_STATUS", None),
            mock.patch.object(backup, "GROUPS_SOURCE_PATH", str(self.root / "missing-groups")),
            mock.patch.object(backup, "prepare_state_snapshot", return_value=(str(staged), str(staged))),
            mock.patch.object(backup, "available_sources", return_value=[(str(staged), "state")]),
            mock.patch.object(backup, "build_backend", return_value=backend),
            mock.patch.object(backup, "choose_snapshot_name", return_value=self.snapshot) as choose,
        ):
            with self.assertRaisesRegex(RuntimeError, "transfer failed"):
                backup.run_backup()

        choose.assert_called_once_with({self.previous, orphan})
        backend.delete_snapshot.assert_called_once_with(self.snapshot)
        backend.write_marker.assert_not_called()
        backend.close.assert_called_once()
        self.assertFalse(self.pending.exists())
        self.assertFalse(staged.exists())

    def test_cleanup_retries_and_never_deletes_if_marker_status_is_unknown(self):
        backup.record_pending_snapshot(str(self.pending), self.snapshot)
        backend = mock.Mock()
        backend.list_snapshot_directories.return_value = [self.previous, self.snapshot]
        backend.snapshot_has_marker.side_effect = [RuntimeError("network unavailable"), False, False]
        backend.delete_snapshot.side_effect = [RuntimeError("delete denied"), None]

        with self.assertRaisesRegex(RuntimeError, "network unavailable"):
            backup.cleanup_pending_snapshot(backend, str(self.pending))
        backend.delete_snapshot.assert_not_called()
        self.assertTrue(self.pending.is_file())

        with self.assertRaisesRegex(RuntimeError, "delete denied"):
            backup.cleanup_pending_snapshot(backend, str(self.pending))
        self.assertTrue(self.pending.is_file())

        backup.cleanup_pending_snapshot(backend, str(self.pending))
        self.assertFalse(self.pending.exists())
        self.assertEqual(backend.delete_snapshot.call_args_list, [mock.call(self.snapshot)] * 2)

    def verify_local_cleanup(self, backend):
        roots = self.root / "snapshots"
        for name in (self.previous, self.snapshot):
            (roots / name / "data").mkdir(parents=True)
            (roots / name / "data" / "report").write_bytes(b"report")
        (roots / self.previous / ".backup_complete").touch()

        self.assertEqual(backend.list_snapshots(), [self.previous])
        backup.record_pending_snapshot(str(self.pending), self.previous)
        backup.cleanup_pending_snapshot(backend, str(self.pending))
        self.assertTrue((roots / self.previous / "data" / "report").is_file())

        backup.record_pending_snapshot(str(self.pending), self.snapshot)
        backup.cleanup_pending_snapshot(backend, str(self.pending))
        self.assertEqual(sorted(path.name for path in roots.iterdir()), [self.previous])
        self.assertFalse(self.pending.exists())

    @unittest.skipUnless(shutil.which("rsync"), "rsync is needed for the cleanup smoke test")
    def test_rsync_removes_only_the_unmarked_snapshot(self):
        backend = backup.RsyncBackend(self.destination)
        backend.remote_base = str(self.root)
        self.assertEqual(backend.list_snapshot_directories(), [])
        self.verify_local_cleanup(backend)

    @unittest.skipUnless(shutil.which("rclone"), "rclone is needed for the cleanup smoke test")
    def test_rclone_removes_only_the_unmarked_snapshot(self):
        local_remote = {"type": "alias", "remote": str(self.root)}
        with mock.patch.object(backup.RcloneBackend, "_build_remote", return_value=(local_remote, "")):
            backend = backup.RcloneBackend(self.destination)
        self.addCleanup(backend.close)
        self.assertEqual(backend.list_snapshot_directories(), [])
        self.verify_local_cleanup(backend)


if __name__ == "__main__":
    unittest.main()
