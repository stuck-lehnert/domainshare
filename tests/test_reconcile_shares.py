import base64
import unittest

from app import reconcile_shares as rs


ROOT_DN = "CN=FS_Data,OU=Groups,DC=example,DC=com"
GROUP_A_DN = "CN=GroupA,OU=Groups,DC=example,DC=com"
GROUP_B_DN = "CN=GroupB,OU=Groups,DC=example,DC=com"
GROUP_C_DN = "CN=GroupC,OU=Groups,DC=example,DC=com"
USER_1_DN = "CN=Alice,OU=Users,DC=example,DC=com"
USER_2_DN = "CN=Bob,OU=Users,DC=example,DC=com"
USER_3_DN = "CN=Carol,OU=Users,DC=example,DC=com"
COMPUTER_DN = "CN=PC01,OU=Computers,DC=example,DC=com"


def principal(dn, sam, classes, members=(), member_of=()):
    return {
        "dn": dn,
        "objectGUID": "",
        "samAccountName": sam,
        "objectClasses": set(classes),
        "memberDns": list(members),
        "memberOfDns": list(member_of),
    }


class GroupFolderNameTests(unittest.TestCase):
    def test_sanitizer_preserves_leading_dot(self):
        self.assertEqual(rs.sanitize_group_folder_name(".Finance"), ".Finance")
        self.assertEqual(rs.sanitize_group_folder_name("..Finance"), "..Finance")

    def test_sanitizer_still_rejects_dot_only_names(self):
        self.assertEqual(rs.sanitize_group_folder_name("."), "")
        self.assertEqual(rs.sanitize_group_folder_name(".."), "")
        self.assertEqual(rs.sanitize_group_folder_name("Finance."), "Finance")


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
                principal(GROUP_A_DN, "GroupA", {"group"}, member_of=[ROOT_DN]),
                principal(GROUP_B_DN, "GroupB", {"group"}, member_of=[GROUP_A_DN]),
            ]
        )

        expansion = rs.expand_group_membership(root_group, lookup_func=lookup)

        self.assertEqual(expansion.group_sams, ["GroupA", "GroupB"])
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


if __name__ == "__main__":
    unittest.main()
