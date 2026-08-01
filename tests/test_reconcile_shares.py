import base64
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import reconcile_shares as rs


ROOT_DN = "CN=FS_Data,OU=Groups,DC=example,DC=com"
GROUP_A_DN = "CN=GroupA,OU=Groups,DC=example,DC=com"
GROUP_B_DN = "CN=GroupB,OU=Groups,DC=example,DC=com"
GROUP_C_DN = "CN=GroupC,OU=Groups,DC=example,DC=com"
USER_1_DN = "CN=Alice,OU=Users,DC=example,DC=com"
USER_2_DN = "CN=Bob,OU=Users,DC=example,DC=com"
USER_3_DN = "CN=Carol,OU=Users,DC=example,DC=com"
COMPUTER_DN = "CN=PC01,OU=Computers,DC=example,DC=com"


def principal(dn, sam, classes, members=(), member_of=(), sid=""):
    return {
        "dn": dn,
        "objectGUID": "",
        "objectSid": sid,
        "samAccountName": sam,
        "objectClasses": set(classes),
        "memberDns": list(members),
        "memberOfDns": list(member_of),
    }


class ReconcileStatusTests(unittest.TestCase):
    def test_status_tracks_web_trigger_progress_and_completion_in_utc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            status_path = os.path.join(tmpdir, "reconcile-status.json")
            status = rs.ReconcileStatus(status_path)

            status.begin("web")
            status.progress(57.5, "data-permissions", "Syncing permissions", "FS_Finance")
            status.complete("Reconciliation completed")

            with open(status_path, encoding="utf-8") as handle:
                payload = json.load(handle)

        self.assertEqual(payload["state"], "completed")
        self.assertEqual(payload["trigger"], "web")
        self.assertEqual(payload["phase"], "completed")
        self.assertEqual(payload["percent"], 100.0)
        self.assertEqual(payload["message"], "Reconciliation completed")
        self.assertIsNone(payload["currentItem"])
        self.assertRegex(payload["startedAt"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")
        self.assertRegex(payload["finishedAt"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")
        self.assertFalse(os.path.exists(f"{status_path}.tmp"))


class GroupFolderNameTests(unittest.TestCase):
    def test_sanitizer_preserves_leading_dot(self):
        self.assertEqual(rs.sanitize_group_folder_name(".Finance"), ".Finance")
        self.assertEqual(rs.sanitize_group_folder_name("..Finance"), "..Finance")

    def test_sanitizer_still_rejects_dot_only_names(self):
        self.assertEqual(rs.sanitize_group_folder_name("."), "")
        self.assertEqual(rs.sanitize_group_folder_name(".."), "")
        self.assertEqual(rs.sanitize_group_folder_name("Finance."), "Finance")


class SidParsingTests(unittest.TestCase):
    def test_parses_textual_and_binary_group_sid(self):
        expected = "S-1-5-21-111-222-333-513"
        raw = bytes((1, 5)) + (5).to_bytes(6, "big") + b"".join(
            value.to_bytes(4, "little")
            for value in (21, 111, 222, 333, 513)
        )

        self.assertEqual(rs.parse_sid(expected.lower(), False), expected)
        self.assertEqual(
            rs.parse_sid(base64.b64encode(raw).decode("ascii"), True),
            expected,
        )
        self.assertEqual(rs.sid_rid(expected), 513)


class LdapParsingTests(unittest.TestCase):
    def test_parser_keeps_repeated_members_and_unfolds_lines(self):
        display_name = base64.b64encode(b"Data Folder").decode("ascii")
        output = f"""
dn: {ROOT_DN}
objectGUID: 550e8400-e29b-41d4-a716-446655440000
objectClass: top
objectClass: group
sAMAccountName: FS_Data
displayName:: {display_name}
member: {USER_1_DN}
member: CN=Nested,OU=Groups,DC=example,
 DC=com
member;range=2-2: CN=Ranged,OU=Groups,DC=example,DC=com

"""

        entries = rs.parse_ldap_entries(output)

        self.assertEqual(len(entries), 1)
        self.assertEqual(rs.ldap_first(entries[0], "displayName"), "Data Folder")
        self.assertEqual(
            rs.ldap_values(entries[0], "member"),
            [
                USER_1_DN,
                "CN=Nested,OU=Groups,DC=example,DC=com",
                "CN=Ranged,OU=Groups,DC=example,DC=com",
            ],
        )
        self.assertEqual(rs.ldap_values(entries[0], "objectClass"), ["top", "group"])

    def test_parse_groups_includes_dn_members_and_classes(self):
        output = f"""
dn: {ROOT_DN}
objectGUID: 550e8400-e29b-41d4-a716-446655440000
objectSid: S-1-5-21-111-222-333-1001
objectClass: group
sAMAccountName: FS_Data
displayName: Data Folder
distinguishedName: {ROOT_DN}
member: {GROUP_A_DN}
memberOf: CN=Parent,OU=Groups,DC=example,DC=com

"""

        groups = rs.parse_groups_from_ldap_output(output)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["samAccountName"], "FS_Data")
        self.assertEqual(groups[0]["objectSid"], "S-1-5-21-111-222-333-1001")
        self.assertEqual(groups[0]["shareName"], "Data Folder")
        self.assertEqual(groups[0]["distinguishedName"], ROOT_DN)
        self.assertEqual(groups[0]["memberDns"], [GROUP_A_DN])
        self.assertEqual(
            groups[0]["memberOfDns"], ["CN=Parent,OU=Groups,DC=example,DC=com"]
        )
        self.assertEqual(groups[0]["objectClasses"], {"group"})

    def test_distinguished_name_filter_escapes_rfc4515_specials(self):
        dn = r"CN=A*B(C)\\Name,DC=example,DC=com"

        self.assertEqual(
            rs.build_distinguished_name_filter([dn]),
            r"(distinguishedName=CN=A\2aB\28C\29\5c\5cName,DC=example,DC=com)",
        )

    def test_nested_group_filter_uses_recursive_memberof_match(self):
        self.assertEqual(
            rs.build_nested_groups_filter(ROOT_DN),
            "(&(objectClass=group)"
            f"(memberOf:{rs.LDAP_MATCHING_RULE_IN_CHAIN}:={ROOT_DN}))",
        )

    def test_primary_group_filter_is_numeric_and_deduplicated(self):
        self.assertEqual(
            rs.build_primary_group_users_filter([513, 513, 515]),
            "(&(objectClass=user)(!(objectClass=computer))"
            "(|(primaryGroupID=513)(primaryGroupID=515)))",
        )


class MembershipExpansionTests(unittest.TestCase):
    def lookup_from(self, principals):
        indexed = {rs.normalize_dn(value["dn"]): value for value in principals}

        def lookup(root_dn):
            self.assertEqual(root_dn, ROOT_DN)
            return {
                key: value
                for key, value in indexed.items()
                if key != rs.normalize_dn(root_dn)
            }

        return lookup

    def test_recursive_expansion_dedupes_groups_and_detects_cycle(self):
        root_group = {
            "objectGUID": "root-guid",
            "samAccountName": "FS_Data",
            "distinguishedName": ROOT_DN,
            "memberDns": [USER_1_DN, GROUP_A_DN, GROUP_B_DN, COMPUTER_DN],
            "memberOfDns": [GROUP_A_DN],
            "objectClasses": {"group"},
        }
        lookup = self.lookup_from(
            [
                principal(GROUP_A_DN, "GroupA", {"group"}, member_of=[ROOT_DN], sid="S-1-5-21-1-2-3-1101"),
                principal(GROUP_B_DN, "GroupB", {"group"}, member_of=[GROUP_A_DN]),
            ]
        )

        expansion = rs.expand_group_membership(root_group, lookup_func=lookup)

        self.assertEqual(expansion.group_sams, ["GroupA", "GroupB"])
        self.assertEqual(
            expansion.group_sids,
            {"groupa": "S-1-5-21-1-2-3-1101"},
        )
        self.assertEqual(expansion.unresolved_dns, [])
        self.assertEqual(expansion.cycle_paths, [["FS_Data", "GroupA", "FS_Data"]])

    def test_self_cycle_is_reported_once(self):
        root_group = {
            "objectGUID": "root-guid",
            "samAccountName": "FS_Data",
            "distinguishedName": ROOT_DN,
            "memberDns": [GROUP_C_DN],
            "objectClasses": {"group"},
        }
        lookup = self.lookup_from(
            [principal(GROUP_C_DN, "GroupC", {"group"}, member_of=[GROUP_C_DN])]
        )

        expansion = rs.expand_group_membership(root_group, lookup_func=lookup)

        self.assertEqual(expansion.group_sams, ["GroupC"])
        self.assertEqual(expansion.cycle_paths, [["GroupC", "GroupC"]])

    def test_user_members_are_not_required_for_expansion(self):
        user_dns = [
            f"CN=User{index},OU=Users,DC=example,DC=com" for index in range(1000)
        ]
        root_group = {
            "objectGUID": "root-guid",
            "samAccountName": "FS_Data",
            "distinguishedName": ROOT_DN,
            "memberDns": [*user_dns, GROUP_A_DN],
            "objectClasses": {"group"},
        }
        lookup = self.lookup_from(
            [principal(GROUP_A_DN, "GroupA", {"group"}, member_of=[ROOT_DN])]
        )

        expansion = rs.expand_group_membership(root_group, lookup_func=lookup)

        self.assertEqual(expansion.group_sams, ["GroupA"])
        self.assertEqual(expansion.unresolved_dns, [])
        self.assertEqual(expansion.cycle_paths, [])

    def test_missing_root_dn_is_reported(self):
        root_group = {
            "objectGUID": "root-guid",
            "samAccountName": "FS_Data",
            "distinguishedName": "",
            "memberDns": [],
            "objectClasses": {"group"},
        }

        expansion = rs.expand_group_membership(root_group, lookup_func=lambda root_dn: {})

        self.assertEqual(expansion.unresolved_dns, ["<missing root group distinguishedName>"])
        self.assertEqual(expansion.group_sams, [])


class AclResolutionTests(unittest.TestCase):
    def test_sid_resolution_handles_localized_primary_group_name(self):
        names_seen = []

        def name_resolver(workgroup, group_name):
            names_seen.append((workgroup, group_name))
            return None

        gids, unresolved = rs.resolve_group_gids_for_acl(
            "BEISPIEL",
            ["FS_Daten", "Domänen-Benutzer"],
            name_resolver,
            group_sids=[
                "S-1-5-21-111-222-333-1200",
                "S-1-5-21-111-222-333-513",
            ],
            sid_resolver=lambda sid: {
                "S-1-5-21-111-222-333-1200": 11200,
                "S-1-5-21-111-222-333-513": 10513,
            }.get(sid),
        )

        self.assertEqual(gids, [11200, 10513])
        self.assertEqual(unresolved, [])
        self.assertEqual(names_seen, [])

    def test_gid_resolution_preserves_order_dedupes_and_reports_missing(self):
        mapping = {"FS_Data": 1001, "Nested": 1002}

        def resolver(workgroup, group_name):
            self.assertEqual(workgroup, "EXAMPLE")
            return mapping.get(group_name)

        gids, unresolved = rs.resolve_group_gids_for_acl(
            "EXAMPLE", ["FS_Data", "Nested", "nested", "Missing"], resolver
        )

        self.assertEqual(gids, [1001, 1002])
        self.assertEqual(unresolved, ["Missing"])


class DataAclSyncTests(unittest.TestCase):
    def make_conn(self, share_path, acl_signature=""):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE shares (
                objectGUID TEXT PRIMARY KEY,
                samAccountName TEXT NOT NULL,
                shareName TEXT NOT NULL,
                path TEXT NOT NULL,
                createdAt TIMESTAMP NOT NULL,
                lastSeenAt TIMESTAMP NOT NULL,
                isActive INTEGER NOT NULL,
                aclSignature TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            INSERT INTO shares (objectGUID, samAccountName, shareName, path, createdAt, lastSeenAt, isActive, aclSignature)
            VALUES ('guid', 'FS_Data', 'Data', ?, 'now', 'now', 1, ?)
            """,
            (share_path, acl_signature),
        )
        conn.commit()
        return conn

    def ad_group(self):
        return {
            "objectGUID": "guid",
            "samAccountName": "FS_Data",
            "distinguishedName": ROOT_DN,
            "memberDns": [],
            "memberOfDns": [],
            "objectClasses": {"group"},
        }

    def fetch_signature(self, conn):
        row = conn.execute(
            "SELECT aclSignature FROM shares WHERE objectGUID = 'guid'"
        ).fetchone()
        return row["aclSignature"]

    def sync_patches(self, tempdir, env=None):
        env_values = {"WORKGROUP": "EXAMPLE"}
        if env:
            env_values.update(env)
        return (
            mock.patch.dict(os.environ, env_values, clear=True),
            mock.patch.object(rs, "GROUP_ROOT", os.path.join(tempdir, "root")),
            mock.patch.object(
                rs,
                "expand_group_membership",
                return_value=rs.MembershipExpansion(group_sams=["Nested"]),
            ),
            mock.patch.object(
                rs,
                "resolve_group_gids_for_acl",
                return_value=([1001, 1002], []),
            ),
            mock.patch.object(rs.os, "chown"),
            mock.patch.object(rs.os, "chmod"),
            mock.patch.object(
                rs,
                "run_command",
                return_value=rs.subprocess.CompletedProcess([], 0, "", ""),
            ),
        )

    def test_data_acl_signature_is_stable_and_deduped(self):
        self.assertEqual(
            rs.build_data_acl_signature(20, [30, 20, 30], 10),
            rs.build_data_acl_signature(20, [20, 30], 10),
        )
        self.assertNotEqual(
            rs.build_data_acl_signature(20, [20, 30], 10),
            rs.build_data_acl_signature(20, [20, 30], None),
        )

    def test_repair_env_truthy(self):
        for value in ("1", "true", "YES", "on"):
            with mock.patch.dict(os.environ, {rs.DATA_ACL_REPAIR_ENV: value}, clear=True):
                self.assertTrue(rs.should_repair_data_acls())

        with mock.patch.dict(os.environ, {rs.DATA_ACL_REPAIR_ENV: "0"}, clear=True):
            self.assertFalse(rs.should_repair_data_acls())

    def test_open_db_migrates_acl_signature_column(self):
        with tempfile.TemporaryDirectory() as tempdir:
            db_path = os.path.join(tempdir, "shares.db")
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE shares (
                    objectGUID TEXT PRIMARY KEY,
                    samAccountName TEXT NOT NULL,
                    shareName TEXT NOT NULL,
                    path TEXT NOT NULL,
                    createdAt TIMESTAMP NOT NULL,
                    lastSeenAt TIMESTAMP NOT NULL,
                    isActive INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO shares (objectGUID, samAccountName, shareName, path, createdAt, lastSeenAt, isActive)
                VALUES ('guid', 'FS_Data', 'Data', '/tmp/data', 'now', 'now', 1)
                """
            )
            conn.commit()
            conn.close()

            with mock.patch.object(rs, "DB_PATH", db_path):
                migrated = rs.open_db()
                try:
                    columns = {
                        row["name"]
                        for row in migrated.execute("PRAGMA table_info(shares)")
                    }
                    row = migrated.execute(
                        "SELECT aclSignature FROM shares WHERE objectGUID = 'guid'"
                    ).fetchone()
                finally:
                    migrated.close()

        self.assertIn("aclSignature", columns)
        self.assertEqual(row["aclSignature"], "")

    def test_sync_data_permissions_uses_root_only_when_signature_matches(self):
        expected_signature = rs.build_data_acl_signature(1001, [1001, 1002], None)
        with tempfile.TemporaryDirectory() as tempdir:
            share_path = os.path.join(tempdir, "share")
            os.makedirs(share_path)
            conn = self.make_conn(share_path, expected_signature)
            patches = self.sync_patches(tempdir)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
                mock.patch.object(rs, "apply_group_permissions", return_value=True) as apply_root, \
                mock.patch.object(rs, "enforce_group_tree_permissions") as enforce_tree:
                rs.sync_dynamic_directory_permissions(conn, [self.ad_group()])

            apply_root.assert_called_once_with(
                share_path, 1001, [1001, 1002], None, is_dir=True
            )
            enforce_tree.assert_not_called()
            self.assertEqual(self.fetch_signature(conn), expected_signature)
            conn.close()

    def test_sync_data_permissions_repairs_and_stores_signature_when_changed(self):
        expected_signature = rs.build_data_acl_signature(1001, [1001, 1002], None)
        with tempfile.TemporaryDirectory() as tempdir:
            share_path = os.path.join(tempdir, "share")
            os.makedirs(share_path)
            conn = self.make_conn(share_path, "old")
            patches = self.sync_patches(tempdir)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
                mock.patch.object(rs, "apply_group_permissions") as apply_root, \
                mock.patch.object(
                    rs, "enforce_group_tree_permissions", return_value=(3, 4, True)
                ) as enforce_tree:
                rs.sync_dynamic_directory_permissions(conn, [self.ad_group()])

            apply_root.assert_not_called()
            enforce_tree.assert_called_once_with(share_path, 1001, [1001, 1002], None)
            self.assertEqual(self.fetch_signature(conn), expected_signature)
            conn.close()

    def test_sync_data_permissions_keeps_old_signature_after_failed_repair(self):
        with tempfile.TemporaryDirectory() as tempdir:
            share_path = os.path.join(tempdir, "share")
            os.makedirs(share_path)
            conn = self.make_conn(share_path, "old")
            patches = self.sync_patches(tempdir)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
                mock.patch.object(
                    rs, "enforce_group_tree_permissions", return_value=(3, 4, False)
                ):
                rs.sync_dynamic_directory_permissions(conn, [self.ad_group()])

            self.assertEqual(self.fetch_signature(conn), "old")
            conn.close()

    def test_sync_data_permissions_force_repairs_when_signature_matches(self):
        expected_signature = rs.build_data_acl_signature(1001, [1001, 1002], None)
        with tempfile.TemporaryDirectory() as tempdir:
            share_path = os.path.join(tempdir, "share")
            os.makedirs(share_path)
            conn = self.make_conn(share_path, expected_signature)
            patches = self.sync_patches(tempdir, {rs.DATA_ACL_REPAIR_ENV: "1"})
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], \
                mock.patch.object(rs, "apply_group_permissions") as apply_root, \
                mock.patch.object(
                    rs, "enforce_group_tree_permissions", return_value=(3, 4, True)
                ) as enforce_tree:
                rs.sync_dynamic_directory_permissions(conn, [self.ad_group()])

            apply_root.assert_not_called()
            enforce_tree.assert_called_once_with(share_path, 1001, [1001, 1002], None)
            self.assertEqual(self.fetch_signature(conn), expected_signature)
            conn.close()


if __name__ == "__main__":
    unittest.main()
