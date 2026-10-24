"""Adversarial guards for exploratory AST-derived verification candidates."""
import unittest
from scripts.d24e_guard_seeds import candidates


class SourceDerivedGuardTests(unittest.TestCase):
    def test_extract_literal_guard_with_rejection(self):
        code = '''
def check(path):
    if path.startswith("../") or path.startswith("/"):
        return None
    return path
'''
        c = candidates(code, only_function="check")
        self.assertEqual([x.prefix for x in c], ["../", "/"])
        self.assertTrue(all(x.decision == "UNVERIFIED_SOURCE_DERIVED_TEST_CANDIDATE" for x in c))
        self.assertTrue(all(x.witness.endswith("d24e-probe") for x in c))

    def test_guard_without_direct_rejection_is_not_a_candidate(self):
        code = '''
def check(path):
    if path.startswith("../"):
        print("report")
    return path
'''
        self.assertEqual(candidates(code), [])

    def test_dynamic_predicate_is_not_claimed_rejected(self):
        code = '''
def check(path, prefix):
    if path.startswith(prefix):
        return None
    return path
'''
        self.assertEqual(candidates(code), [])

    def test_nested_unrelated_return_is_not_direct_rejection(self):
        code = '''
def check(path, flag):
    if path.startswith("../"):
        if flag:
            return None
    return path
'''
        self.assertEqual(candidates(code), [])

    def test_unknown_target_remains_unverified_not_safe(self):
        code = "def scan(s):\n    if s.startswith('../'):\n        return None\n"
        self.assertEqual(candidates(code, only_function="other"), [])
        self.assertEqual(len(candidates(code, only_function="scan")), 1)

    def test_malformed_source_aborts(self):
        with self.assertRaises(SyntaxError):
            candidates("def check(:")
    

if __name__ == "__main__":
    unittest.main()
