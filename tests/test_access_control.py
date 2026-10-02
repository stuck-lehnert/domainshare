import os
import json
import tempfile
import sqlite3
import unittest
from unittest import mock

from app import access_control as access
from app import reconcile_shares as directory

ADMIN = 'S-1-5-21-1-2-3-512'
ALICE = 'S-1-5-21-1-2-3-1100'
BOB = 'S-1-5-21-1-2-3-1101'
USERS = {ALICE: {'sam': 'alice', 'name': 'Alice'}, BOB: {'sam': 'bob', 'name': 'Bob'}}


class ManagedAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.patches = [mock.patch.object(directory, 'DB_PATH', os.path.join(root, 'state.db')),
                        mock.patch.object(directory, 'GROUP_ROOT', os.path.join(root, 'data')),
                        mock.patch.object(directory, 'GROUP_ARCHIVE_ROOT', os.path.join(root, 'archive')),
                        mock.patch.object(directory, 'LOCK_PATH', os.path.join(root, 'reconcile.lock'))]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        os.makedirs(directory.GROUP_ROOT)
        self.conn = directory.open_db()
        self.addCleanup(self.conn.close)
        access.ensure_schema(self.conn)

    def change(self, body):
        with mock.patch.object(access, 'sync_permissions'), mock.patch.object(directory, 'run_command', return_value=mock.Mock(returncode=0)):
            return access.apply_change(self.conn, body, 'EXAMPLE\\admin', USERS)

    def folder(self, name='Finance'):
        data = self.change({'action': 'create-folder', 'name': name})
        return next(row['id'] for row in data['folders'] if row['name'] == name)

    def test_individual_user_assignments_are_independent_including_zero(self):
        folder = self.folder()
        other = self.folder('Projects')
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
            {'kind': 'user', 'principalId': ALICE, 'level': 0},
            {'kind': 'user', 'principalId': BOB, 'level': 2}]})
        self.change({'action': 'set-permissions', 'id': other, 'permissions': [
            {'kind': 'user', 'principalId': ALICE, 'level': 3}]})
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 0, BOB: 2})
        self.assertEqual(access.effective_levels(self.conn, other), {ALICE: 3})
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': []})
        self.assertEqual(access.effective_levels(self.conn, folder), {})
        self.assertEqual(access.effective_levels(self.conn, other), {ALICE: 3})

    def test_group_actions_and_assignments_are_rejected(self):
        folder = self.folder()
        for action in ['save-group', 'delete-group']:
            with self.assertRaises(ValueError):
                self.change({'action': action, 'id': 'legacy', 'name': 'Editors', 'members': [ALICE]})
        with self.assertRaises(ValueError):
            self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
                {'kind': 'group', 'principalId': 'legacy', 'level': 3}]})
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute('INSERT INTO folder_permissions VALUES(?,?,?,?)', (folder, 'group', 'legacy', 3))
        self.conn.rollback()
        self.assertNotIn('groups', access.snapshot(self.conn))
        self.assertIsNone(self.conn.execute("SELECT 1 FROM sqlite_master WHERE name='access_groups'").fetchone())

    def legacy_schema(self):
        self.conn.executescript("""
            DROP TABLE folder_permissions;
            CREATE TABLE folder_permissions (
                folderId TEXT NOT NULL REFERENCES shares(objectGUID) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK(kind IN ('user','group')), principalId TEXT NOT NULL,
                level INTEGER NOT NULL CHECK(level BETWEEN 0 AND 3),
                PRIMARY KEY(folderId,kind,principalId));
            CREATE TABLE access_groups (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE);
            CREATE TABLE access_members (groupId TEXT NOT NULL REFERENCES access_groups(id) ON DELETE CASCADE,
                                         userSid TEXT NOT NULL,PRIMARY KEY(groupId,userSid));
            INSERT INTO access_settings VALUES('managed','1');
            INSERT INTO access_groups VALUES('editors','Editors'),('readers','Readers'),('empty','Empty');
        """)

    def test_existing_local_groups_flatten_once_preserving_overrides_and_archived_rules(self):
        folder = self.folder()
        archived = self.folder('Archived')
        self.change({'action': 'archive-folder', 'id': archived})
        self.legacy_schema()
        self.conn.executemany('INSERT INTO access_members VALUES(?,?)',
                              [('editors', ALICE), ('editors', BOB), ('readers', ALICE), ('readers', BOB)])
        self.conn.executemany('INSERT INTO folder_permissions VALUES(?,?,?,?)', [
            (folder, 'group', 'editors', 2), (folder, 'group', 'readers', 3),
            (folder, 'user', ALICE, 0), (folder, 'group', 'empty', 3),
            (archived, 'group', 'editors', 2), (archived, 'user', BOB, 1)])
        self.conn.commit()
        with mock.patch.object(access, 'read_directory') as read:
            access.migrate(self.conn)
            access.migrate(self.conn)
        read.assert_not_called()
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 0, BOB: 3})
        self.assertEqual(access.effective_levels(self.conn, archived), {ALICE: 2, BOB: 1})
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM access_changes WHERE action='migrate-individual-permissions'").fetchone()[0], 1)
        for table in ['access_groups', 'access_members']:
            self.assertIsNone(self.conn.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone())
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute('INSERT INTO folder_permissions VALUES(?,?,?,?)', (folder, 'group', 'old', 3))
        self.conn.rollback()
        self.change({'action': 'restore-folder', 'id': archived})
        self.assertEqual(access.effective_levels(self.conn, archived), {ALICE: 2, BOB: 1})

    def test_unresolved_stored_group_aborts_upgrade_without_losing_rules(self):
        folder = self.folder()
        self.legacy_schema()
        self.conn.execute('INSERT INTO folder_permissions VALUES(?,?,?,?)', (folder, 'group', 'missing', 3))
        self.conn.commit()
        with self.assertRaises(RuntimeError):
            access.ensure_schema(self.conn)
        self.assertEqual(self.conn.execute('SELECT principalId FROM folder_permissions').fetchone()[0], 'missing')
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM sqlite_master WHERE name='access_groups'").fetchone())
        self.assertIsNone(self.conn.execute("SELECT 1 FROM sqlite_master WHERE name='individual_permissions'").fetchone())

    def test_report_contains_only_individual_users_with_positive_access(self):
        folder = self.folder()
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
            {'kind': 'user', 'principalId': ALICE, 'level': 0},
            {'kind': 'user', 'principalId': BOB, 'level': 2}]})
        row = access.report_folders(self.conn)['groups'][0]
        self.assertEqual(row['userCount'], 1)
        self.assertEqual(row['groupCount'], 0)
        self.assertEqual([(node['id'], node['level']) for node in row['members']], [(BOB, 2)])

    def legacy_folder(self, active=True, name='Finance'):
        guid = 'dc537393-6882-4b94-bc08-e24966623d62'
        path = os.path.join(os.path.dirname(directory.GROUP_ROOT), guid)
        os.makedirs(os.path.join(path, 'Reports'))
        with open(os.path.join(path, 'Reports', 'retained.bin'), 'wb') as handle:
            handle.write(b'production data\x00\xff\n')
        self.conn.execute("INSERT INTO shares VALUES(?,?,?,?,?,?,?,'old-signature')",
                          (guid, 'FS_Finance', name, path, '2026-01-01', '2026-01-01', int(active)))
        self.conn.commit()
        return guid, path

    def mark_managed_with_rules(self, folder):
        self.conn.execute("INSERT INTO access_settings VALUES('managed','1')")
        access.cache_users(self.conn, USERS)
        self.conn.executemany('INSERT INTO folder_permissions VALUES(?,?,?,?)',
                              [(folder, 'user', ALICE, 2), (folder, 'user', BOB, 0)])
        self.conn.commit()

    def assert_retained_data(self, folder, original_inode):
        row = self.conn.execute('SELECT * FROM shares WHERE objectGUID=?', (folder,)).fetchone()
        path = os.path.join(row['path'], 'Reports', 'retained.bin')
        with open(path, 'rb') as handle:
            self.assertEqual(handle.read(), b'production data\x00\xff\n')
        self.assertEqual(os.stat(path).st_ino, original_inode)
        access.safe_folder_path(row)
        return row

    def test_already_migrated_guid_path_repaired_without_reimport_or_lost_data(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        inode = os.stat(os.path.join(source, 'Reports', 'retained.bin')).st_ino
        with self.assertRaisesRegex(RuntimeError, 'Unsafe managed folder path'):
            access.safe_folder_path(self.conn.execute('SELECT * FROM shares').fetchone())
        with mock.patch.object(access, 'read_directory') as ad:
            access.migrate(self.conn)
            access.migrate(self.conn)
        ad.assert_not_called()
        row = self.assert_retained_data(folder, inode)
        self.assertEqual(row['path'], os.path.join(directory.GROUP_ROOT, 'Finance'))
        self.assertEqual(row['shareName'], 'Finance')
        self.assertEqual(row['aclSignature'], '')
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 2, BOB: 0})
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM access_changes WHERE action='migrate-folder-layout'").fetchone()[0], 1)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM access_settings WHERE key='pendingFolderLayout'").fetchone())

    def test_initial_ad_import_also_moves_legacy_guid_data(self):
        folder, source = self.legacy_folder()
        inode = os.stat(os.path.join(source, 'Reports', 'retained.bin')).st_ino
        users = {ALICE: {**USERS[ALICE], 'dn': 'alice', 'primaryRid': 513}}
        groups = {'finance': {'dn': 'finance', 'sam': 'FS_Finance', 'sid': 'S-1-5-21-1-2-3-1200', 'members': ['alice']}}
        with mock.patch.object(access, 'read_directory', return_value=(users, groups)):
            access.migrate(self.conn)
        self.assert_retained_data(folder, inode)
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 3})

    def test_legacy_archived_data_moves_to_archive_and_stays_archived(self):
        folder, source = self.legacy_folder(active=False)
        self.mark_managed_with_rules(folder)
        inode = os.stat(os.path.join(source, 'Reports', 'retained.bin')).st_ino
        access.migrate(self.conn)
        row = self.assert_retained_data(folder, inode)
        self.assertFalse(row['isActive'])
        self.assertEqual(row['path'], os.path.join(directory.GROUP_ARCHIVE_ROOT, 'Finance'))
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 2, BOB: 0})

    def test_layout_collision_preserves_both_directory_contents(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        inode = os.stat(os.path.join(source, 'Reports', 'retained.bin')).st_ino
        existing = os.path.join(directory.GROUP_ROOT, 'FINANCE')
        os.mkdir(existing)
        with open(os.path.join(existing, 'other.txt'), 'w') as handle:
            handle.write('unrelated data')
        access.migrate(self.conn)
        row = self.assert_retained_data(folder, inode)
        self.assertEqual(row['shareName'], 'Finance_dc537393')
        with open(os.path.join(existing, 'other.txt')) as handle:
            self.assertEqual(handle.read(), 'unrelated data')

    def test_atomic_rename_refuses_existing_empty_destination(self):
        folder, source = self.legacy_folder()
        destination = os.path.join(directory.GROUP_ROOT, 'Finance')
        os.mkdir(destination)
        with self.assertRaises(FileExistsError):
            access.rename_without_overwrite(source, destination)
        self.assertTrue(os.path.isfile(os.path.join(source, 'Reports', 'retained.bin')))
        self.assertTrue(os.path.isdir(destination))

    def test_layout_retry_after_failure_before_move_keeps_data_and_rules(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        inode = os.stat(os.path.join(source, 'Reports', 'retained.bin')).st_ino
        with mock.patch.object(access, 'rename_without_overwrite', side_effect=OSError('interrupted before rename')):
            with self.assertRaises(OSError):
                access.migrate(self.conn)
        self.assertTrue(os.path.isfile(os.path.join(source, 'Reports', 'retained.bin')))
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM access_settings WHERE key='pendingFolderLayout'").fetchone())
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 2, BOB: 0})
        access.migrate(self.conn)
        self.assert_retained_data(folder, inode)

    def test_layout_retry_after_crash_between_rename_and_db_update(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        inode = os.stat(os.path.join(source, 'Reports', 'retained.bin')).st_ino
        rename = access.rename_without_overwrite
        def move_then_crash(old, new):
            rename(old, new)
            raise RuntimeError('crashed after rename')
        with mock.patch.object(access, 'rename_without_overwrite', side_effect=move_then_crash):
            with self.assertRaises(RuntimeError):
                access.migrate(self.conn)
        self.assertFalse(os.path.lexists(source))
        self.assertEqual(self.conn.execute('SELECT path FROM shares').fetchone()[0], source)
        # Reopen SQLite like a new container process; recovery uses the durable journal.
        reopened = directory.open_db()
        try:
            access.migrate(reopened)
        finally:
            reopened.close()
        self.assert_retained_data(folder, inode)
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 2, BOB: 0})

    def test_layout_recovery_ambiguous_collision_retains_both_paths(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        with mock.patch.object(access, 'rename_without_overwrite', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                access.migrate(self.conn)
        pending = json.loads(self.conn.execute("SELECT value FROM access_settings WHERE key='pendingFolderLayout'").fetchone()[0])
        os.mkdir(pending['destination'])
        with open(os.path.join(pending['destination'], 'other.txt'), 'w') as handle:
            handle.write('other data')
        with self.assertRaisesRegex(RuntimeError, 'both paths retained'):
            access.migrate(self.conn)
        self.assertTrue(os.path.isfile(os.path.join(source, 'Reports', 'retained.bin')))
        with open(os.path.join(pending['destination'], 'other.txt')) as handle:
            self.assertEqual(handle.read(), 'other data')
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM access_settings WHERE key='pendingFolderLayout'").fetchone())

    def test_missing_legacy_source_does_not_create_empty_replacement(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        os.rename(source, source + '.retained')
        with self.assertRaisesRegex(RuntimeError, 'Legacy folder is missing'):
            access.migrate(self.conn)
        self.assertFalse(os.path.lexists(os.path.join(directory.GROUP_ROOT, 'Finance')))
        self.assertTrue(os.path.isfile(os.path.join(source + '.retained', 'Reports', 'retained.bin')))
        self.assertEqual(self.conn.execute('SELECT path FROM shares').fetchone()[0], source)

    def test_layout_repair_rejects_symlinks_and_unregistered_paths(self):
        folder, source = self.legacy_folder()
        self.mark_managed_with_rules(folder)
        os.rename(source, source + '.retained')
        os.symlink(source + '.retained', source)
        with self.assertRaisesRegex(RuntimeError, 'Unsafe legacy folder path'):
            access.migrate(self.conn)
        self.assertTrue(os.path.islink(source))
        self.assertTrue(os.path.isfile(os.path.join(source + '.retained', 'Reports', 'retained.bin')))
        self.conn.execute('UPDATE shares SET path=?', (source + '.retained',))
        self.conn.commit()
        with self.assertRaisesRegex(RuntimeError, 'Unsafe legacy folder path'):
            access.migrate(self.conn)

    def test_invalid_permission_update_retains_existing_policy(self):
        folder = self.folder()
        original = [{'kind': 'user', 'principalId': ALICE, 'level': 1}]
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': original})
        for invalid in [True, -1, 4, '2', None]:
            with self.assertRaises(ValueError):
                self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
                    {'kind': 'user', 'principalId': ALICE, 'level': invalid}]})
            self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 1})
        with self.assertRaises(ValueError):
            self.change({'action': 'set-permissions', 'id': folder, 'permissions': original * 2})

    def test_unknown_user_rejected_and_unavailable_existing_assignment_removable(self):
        folder = self.folder()
        with self.assertRaises(ValueError):
            self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
                {'kind': 'user', 'principalId': 'S-1-5-21-1-2-3-9999', 'level': 3}]})
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
            {'kind': 'user', 'principalId': ALICE, 'level': 3}]})
        with mock.patch.object(access, 'sync_permissions'), mock.patch.object(directory, 'run_command', return_value=mock.Mock(returncode=0)):
            access.apply_change(self.conn, {'action': 'set-permissions', 'id': folder, 'permissions': [
                {'kind': 'user', 'principalId': ALICE, 'level': 0}]}, 'admin', {})
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 0})

    def test_folder_archive_restore_preserves_data_and_rules(self):
        folder = self.folder()
        source = os.path.join(directory.GROUP_ROOT, 'Finance')
        with open(os.path.join(source, 'report.txt'), 'w') as handle:
            handle.write('retained')
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
            {'kind': 'user', 'principalId': ALICE, 'level': 3}]})
        self.change({'action': 'archive-folder', 'id': folder})
        self.assertFalse(os.path.exists(source))
        self.change({'action': 'restore-folder', 'id': folder})
        with open(os.path.join(source, 'report.txt')) as handle:
            self.assertEqual(handle.read(), 'retained')
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 3})

    def test_folder_names_cannot_escape_or_collide_case_insensitively(self):
        for name in ['../escape', '.', '..', '.trash', '.TRASH', 'a/b', 'a\\b', 'bad\0name', 'NUL', 'COM1.txt', '']:
            with self.assertRaises(ValueError):
                self.change({'action': 'create-folder', 'name': name})
        self.folder()
        with self.assertRaises(ValueError):
            self.folder('FINANCE')

    def test_acl_failure_rolls_back_policy_and_repairs_old_acl(self):
        folder = self.folder()
        self.change({'action': 'set-permissions', 'id': folder, 'permissions': [
            {'kind': 'user', 'principalId': ALICE, 'level': 3}]})
        with mock.patch.object(access, 'sync_permissions', side_effect=[OSError('failed ACL'), None]) as sync:
            with self.assertRaises(OSError):
                access.apply_change(self.conn, {'action': 'set-permissions', 'id': folder, 'permissions': []}, 'admin', USERS)
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 3})
        self.assertTrue(sync.call_args.kwargs['force'])

    def test_created_folder_removed_if_acl_application_fails(self):
        with mock.patch.object(access, 'sync_permissions', side_effect=[OSError('failed ACL'), None]):
            with self.assertRaises(OSError):
                access.apply_change(self.conn, {'action': 'create-folder', 'name': 'Failed'}, 'admin', USERS)
        self.assertFalse(os.path.exists(os.path.join(directory.GROUP_ROOT, 'Failed')))
        self.assertEqual(access.snapshot(self.conn)['folders'], [])

    def test_access_change_records_actor_and_disconnects_cached_handles(self):
        with mock.patch.object(access, 'sync_permissions'), mock.patch.object(directory, 'run_command', return_value=mock.Mock(returncode=0)) as run:
            access.apply_change(self.conn, {'action': 'create-folder', 'name': 'Readers'}, 'EXAMPLE\\admin', USERS)
        run.assert_called_once_with(['smbcontrol', 'all', 'close-share', 'Data'], check=False)
        row = self.conn.execute('SELECT actor,action FROM access_changes').fetchone()
        self.assertEqual(tuple(row), ('EXAMPLE\\admin', 'create-folder'))

    def test_migration_snapshots_nested_and_primary_members_once(self):
        folder = self.folder()
        self.conn.execute("UPDATE shares SET samAccountName='FS_Finance' WHERE objectGUID=?", (folder,))
        self.conn.commit()
        users = {ALICE: {**USERS[ALICE], 'dn': 'alice', 'primaryRid': 513},
                 BOB: {**USERS[BOB], 'dn': 'bob', 'primaryRid': 513}}
        groups = {'finance': {'dn': 'finance', 'sam': 'FS_Finance', 'sid': 'S-1-5-21-1-2-3-1200', 'members': ['nested']},
                  'nested': {'dn': 'nested', 'sam': 'Nested', 'sid': 'S-1-5-21-1-2-3-513', 'members': ['finance']}}
        with mock.patch.object(access, 'read_directory', return_value=(users, groups)) as read:
            access.migrate(self.conn)
            access.migrate(self.conn)
        read.assert_called_once_with(include_groups=True)
        self.assertEqual(access.effective_levels(self.conn, folder), {ALICE: 3, BOB: 3})
        self.assertTrue(all(rule['kind'] == 'user' for rule in access.snapshot(self.conn)['folders'][0]['permissions']))
        self.assertNotIn('groups', access.snapshot(self.conn))

    def test_failed_migration_never_marks_initialized(self):
        folder = self.folder()
        with mock.patch.object(access, 'read_directory', return_value=({}, {})):
            with self.assertRaises(RuntimeError):
                access.migrate(self.conn)
        self.assertFalse(access.initialized(self.conn))
        self.assertEqual(access.effective_levels(self.conn, folder), {})

    def test_new_install_does_not_discover_fs_groups(self):
        with mock.patch.object(access, 'read_directory') as read:
            access.migrate(self.conn)
        read.assert_not_called()
        self.assertTrue(access.initialized(self.conn))

    def test_untracked_existing_folders_adopted_without_user_access(self):
        os.mkdir(os.path.join(directory.GROUP_ROOT, 'Existing'))
        os.mkdir(os.path.join(directory.GROUP_ROOT, '.trash'))
        access.migrate(self.conn)
        folders = access.snapshot(self.conn)['folders']
        self.assertEqual([folder['name'] for folder in folders], ['Existing'])
        self.assertEqual(access.effective_levels(self.conn, folders[0]['id']), {})

    def test_interrupted_acl_update_forces_repair_before_clearing_marker(self):
        self.conn.execute("INSERT INTO access_settings VALUES('pendingRepair','{}')")
        self.conn.commit()
        with mock.patch.object(access, 'sync_permissions') as sync:
            access.recover_pending(self.conn)
        sync.assert_called_once_with(self.conn, force=True)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM access_settings WHERE key='pendingRepair'").fetchone())

    def test_interrupted_archive_move_is_reversed_before_repair(self):
        folder = self.folder()
        source = os.path.join(directory.GROUP_ROOT, 'Finance')
        destination = os.path.join(directory.GROUP_ARCHIVE_ROOT, 'Finance')
        os.makedirs(directory.GROUP_ARCHIVE_ROOT)
        with open(os.path.join(source, 'report.txt'), 'w') as handle:
            handle.write('data')
        self.conn.execute("INSERT INTO access_settings VALUES('pendingRepair',?)", (json.dumps({'move': [source, destination]}),))
        self.conn.commit()
        os.rename(source, destination)
        with mock.patch.object(access, 'sync_permissions'):
            access.recover_pending(self.conn)
        self.assertTrue(os.path.isfile(os.path.join(source, 'report.txt')))
        self.assertFalse(os.path.exists(destination))
        self.assertEqual(self.conn.execute('SELECT path FROM shares WHERE objectGUID=?', (folder,)).fetchone()[0], source)

    def test_interrupted_creation_preserves_data_as_admin_only_folder(self):
        path = os.path.join(directory.GROUP_ROOT, 'Interrupted')
        os.mkdir(path)
        with open(os.path.join(path, 'report.txt'), 'w') as handle:
            handle.write('data')
        self.conn.execute("INSERT INTO access_settings VALUES('pendingRepair',?)", (json.dumps({'create': path}),))
        self.conn.commit()
        with mock.patch.object(access, 'sync_permissions'):
            access.recover_pending(self.conn)
        folder = access.snapshot(self.conn)['folders'][0]
        self.assertEqual(folder['name'], 'Interrupted')
        self.assertEqual(folder['permissions'], [])
        self.assertTrue(os.path.isfile(os.path.join(path, 'report.txt')))

    def test_failed_crash_repair_retains_marker_for_next_retry(self):
        self.conn.execute("INSERT INTO access_settings VALUES('pendingRepair','{}')")
        self.conn.commit()
        with mock.patch.object(access, 'sync_permissions', side_effect=OSError('failed repair')):
            with self.assertRaises(OSError):
                access.recover_pending(self.conn)
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM access_settings WHERE key='pendingRepair'").fetchone())


class WindowsDescriptorTests(unittest.TestCase):
    def test_modify_excludes_both_delete_rights_and_acl_ownership_changes(self):
        mask = access.MASKS[2]
        self.assertEqual(mask & (access.DELETE | access.DELETE_CHILD | 0x40000 | 0x80000), 0)
        self.assertTrue(mask & 2)  # FILE_WRITE_DATA / FILE_ADD_FILE.
        self.assertTrue(access.MASKS[3] & access.DELETE)
        self.assertTrue(access.MASKS[3] & access.DELETE_CHILD)
        self.assertEqual(access.MASKS[1] & 6, 0)

    def test_hidden_has_no_allow_and_creator_cannot_change_permissions(self):
        sddl = access.descriptor({ALICE: 0, BOB: 2}, ADMIN)
        self.assertNotIn(ALICE, sddl)
        self.assertIn('(A;OICI;RC;;;OW)', sddl)
        self.assertNotIn(';;;CO)', sddl)
        self.assertIn('D:P', sddl)

    def test_top_level_root_cannot_be_deleted_by_non_admins(self):
        sddl = access.descriptor({ALICE: 3}, ADMIN, top_level=True)
        self.assertIn(f'(A;;0x001201ff;;;{ALICE})', sddl)
        self.assertIn(f'(A;OICIIO;0x001301ff;;;{ALICE})', sddl)
