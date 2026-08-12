import base64
import datetime as dt
import os
import tempfile
import unittest
from unittest import mock

from app import trash


class TrashTests(unittest.TestCase):
    def roots(self, tmpdir):
        return {
            "GROUP_ROOT": os.path.join(tmpdir, "data"),
            "PRIVATE_ROOT": os.path.join(tmpdir, "private"),
            "FSLOGIX_ROOT": os.path.join(tmpdir, "fslogix"),
            "TRASH_RETENTION_DAYS": "7",
        }

    def recycled_file(self, root, relative, content=b"content"):
        path = os.path.join(root, trash.TRASH_DIRECTORY, *relative.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_lists_downloads_and_restores_versioned_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.roots(tmpdir)
            with mock.patch.dict(os.environ, env):
                trash.ensure_trash_roots()
                self.assertEqual(
                    os.stat(
                        os.path.join(env["GROUP_ROOT"], trash.TRASH_DIRECTORY)
                    ).st_mode
                    & 0o7777,
                    0o1733,
                )
                source = self.recycled_file(
                    env["GROUP_ROOT"],
                    "alice/Finance/Copy #2 of report.xlsx",
                    b"spreadsheet",
                )
                before = os.stat(source)

                result = trash.list_items(share="data", path="REPORT")
                self.assertEqual(result["retentionDays"], 7)
                self.assertEqual(result["matched"], 1)
                item = result["items"][0]
                self.assertEqual(item["share"], "Data")
                self.assertEqual(item["path"], "Finance/report.xlsx")
                self.assertEqual(item["deletedBy"], "alice")
                self.assertEqual(item["size"], 11)

                handle, download = trash.open_download(str(item["id"]))
                with handle:
                    self.assertEqual(handle.read(), b"spreadsheet")
                self.assertEqual(download["name"], "report.xlsx")

                restored = trash.restore_item(str(item["id"]))
                destination = os.path.join(
                    env["GROUP_ROOT"], "Finance", "report.xlsx"
                )
                self.assertEqual(
                    restored,
                    {
                        "restored": True,
                        "share": "Data",
                        "path": "Finance/report.xlsx",
                    },
                )
                self.assertFalse(os.path.exists(source))
                with open(destination, "rb") as handle:
                    self.assertEqual(handle.read(), b"spreadsheet")
                self.assertEqual(os.stat(destination).st_ino, before.st_ino)

    def test_restore_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.roots(tmpdir)
            with mock.patch.dict(os.environ, env):
                trash.ensure_trash_roots()
                source = self.recycled_file(
                    env["PRIVATE_ROOT"], "alice/alice/document.txt", b"deleted"
                )
                destination = os.path.join(
                    env["PRIVATE_ROOT"], "alice", "document.txt"
                )
                os.makedirs(os.path.dirname(destination), exist_ok=True)
                with open(destination, "wb") as handle:
                    handle.write(b"current")
                item_id = trash.encode_item_id(
                    "Private", "alice/alice/document.txt"
                )

                with self.assertRaises(FileExistsError):
                    trash.restore_item(item_id)

                with open(destination, "rb") as handle:
                    self.assertEqual(handle.read(), b"current")
                self.assertTrue(os.path.isfile(source))

    def test_restore_does_not_follow_destination_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.roots(tmpdir)
            with mock.patch.dict(os.environ, env):
                trash.ensure_trash_roots()
                source = self.recycled_file(
                    env["GROUP_ROOT"], "alice/Finance/report.txt", b"deleted"
                )
                outside = os.path.join(tmpdir, "outside")
                os.makedirs(outside)
                os.symlink(outside, os.path.join(env["GROUP_ROOT"], "Finance"))
                item_id = trash.encode_item_id(
                    "Data", "alice/Finance/report.txt"
                )

                with self.assertRaises(OSError):
                    trash.restore_item(item_id)

                self.assertTrue(os.path.isfile(source))
                self.assertFalse(os.path.exists(os.path.join(outside, "report.txt")))

    def test_cleanup_removes_only_files_older_than_seven_days(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.roots(tmpdir)
            with mock.patch.dict(os.environ, env):
                trash.ensure_trash_roots()
                old = self.recycled_file(
                    env["FSLOGIX_ROOT"], "alice/old.vhd", b"old"
                )
                recent = self.recycled_file(
                    env["FSLOGIX_ROOT"], "alice/recent.vhd", b"recent"
                )
                now = dt.datetime.now(dt.timezone.utc)
                old_time = (now - dt.timedelta(days=8)).timestamp()
                os.utime(old, (old_time, old_time))

                result = trash.cleanup_expired(now)

                self.assertEqual(result, {"removed": 1, "removedBytes": 3})
                self.assertFalse(os.path.exists(old))
                self.assertTrue(os.path.isfile(recent))
                self.assertEqual(trash.list_items(now=now)["matched"], 1)

    def test_cleanup_removes_expired_symlinks_without_following_them(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.roots(tmpdir)
            with mock.patch.dict(os.environ, env):
                trash.ensure_trash_roots()
                outside = os.path.join(tmpdir, "outside")
                os.makedirs(outside)
                repository = os.path.join(
                    env["GROUP_ROOT"], trash.TRASH_DIRECTORY, "alice"
                )
                os.makedirs(repository, exist_ok=True)
                link = os.path.join(repository, "linked-directory")
                os.symlink(outside, link)
                now = dt.datetime.now(dt.timezone.utc)
                old_time = (now - dt.timedelta(days=8)).timestamp()
                os.utime(link, (old_time, old_time), follow_symlinks=False)

                result = trash.cleanup_expired(now)

                self.assertEqual(result, {"removed": 1, "removedBytes": 0})
                self.assertFalse(os.path.lexists(link))
                self.assertTrue(os.path.isdir(outside))

    def test_ids_cannot_escape_repository_and_symlinks_are_not_exposed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self.roots(tmpdir)
            with mock.patch.dict(os.environ, env):
                trash.ensure_trash_roots()
                encoded = base64.urlsafe_b64encode(
                    b"Data\0../outside"
                ).decode().rstrip("=")
                with self.assertRaises(ValueError):
                    trash.decode_item_id(encoded)

                repository = os.path.join(
                    env["GROUP_ROOT"], trash.TRASH_DIRECTORY, "alice"
                )
                os.makedirs(repository, exist_ok=True)
                link = os.path.join(repository, "link.txt")
                os.symlink("/etc/passwd", link)
                self.assertEqual(trash.list_items()["matched"], 0)
                with self.assertRaises(ValueError):
                    trash.open_download(
                        trash.encode_item_id("Data", "alice/link.txt")
                    )


if __name__ == "__main__":
    unittest.main()
