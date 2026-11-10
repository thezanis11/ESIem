import unittest
from tools.test_full_stack import select_agent_key


class KeyIsolationTests(unittest.TestCase):
    def test_endpoint_receives_only_its_own_key(self):
        contents = "001 gateway any " + "a" * 64 + "\n002 files any " + "b" * 64 + "\n"
        selected = select_agent_key(contents, "files")
        self.assertEqual(1, len(selected.splitlines()))
        self.assertNotIn("gateway", selected)
        self.assertTrue(selected.startswith("002 files "))

    def test_ambiguous_identity_is_rejected(self):
        for contents in ("", "001 files any aaa\n002 files any bbb\n"):
            with self.assertRaises(ValueError):
                select_agent_key(contents, "files")
