import unittest

from app.account_policy import is_excluded_user


class AccountPolicyTests(unittest.TestCase):
    def test_excludes_exact_krbtgt_and_msol_prefix_case_insensitively(self):
        for name in ("krbtgt", "KRBTGT", "MSOL_", "mSoL_123", "DOMAIN\\MSOL_sync",
                     "krbtgt@example.test", "  DOMAIN\\KrBtGt  "):
            with self.subTest(name=name):
                self.assertTrue(is_excluded_user(name))

    def test_keeps_human_and_other_service_accounts(self):
        for name in ("alice", "Administrator", "report_svc", "MsolSupport", "krbtgt_support", ""):
            with self.subTest(name=name):
                self.assertFalse(is_excluded_user(name))
