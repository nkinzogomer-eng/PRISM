"""Adversarial tests for the strictly bounded Bandit B307 cache study."""
import unittest

from prism.property_certificate import (
    ast_reference_certificate, merge_or_fail, select_reanalysis, suffix_certificate,
)
from scripts.measure_phase43c import mutate


class SuffixCertificateTests(unittest.TestCase):
    def test_allows_only_an_exact_appended_comment_line(self):
        original = b"eval('a')\n"
        updated = original + b"# SCM43C-INERT-123\n"
        result = suffix_certificate(original, updated)
        self.assertTrue(result.reusable)
        self.assertEqual(result.reason, "exact_prefix_and_single_inert_comment")

    def test_reject_new_eval_or_other_executable_code(self):
        original = b"x=1\n"
        for addition in (
            b"eval('x')\n", b"# SCM43C-INERT-1\neval('x')\n",
            b"\n# SCM43C-INERT-1\n",
        ):
            with self.subTest(addition=addition):
                self.assertFalse(suffix_certificate(original, original+addition).reusable)

    def test_reject_pretend_nosec_comment(self):
        original = b"eval('x')\n"
        for suffix in (b"# nosec B307\n", b"# SCM43C-INERT-1 # nosec\n",
                       b"# SCM43C-INERT-1\r\n"):
            with self.subTest(suffix=suffix):
                self.assertFalse(suffix_certificate(original, original + suffix).reusable)

    def test_refuses_prefix_change_or_line_shift(self):
        original = b"eval('x')\n"
        for modified in (b"\n" + original,
                         b"eval('y')\n# SCM43C-INERT-1\n",
                         b"eval('x') # nosec B307\n# SCM43C-INERT-1\n"):
            with self.subTest(modified=modified):
                self.assertFalse(suffix_certificate(original, modified).reusable)

    def test_missing_terminal_newline_denied(self):
        self.assertFalse(suffix_certificate(b"eval('x')",
                         b"eval('x')# SCM43C-INERT-1\n").reusable)

    def test_safe_inert_extension_does_not_authorize_arbitrary_comments(self):
        original = b"eval('x')\n"
        self.assertFalse(suffix_certificate(original, original+b"# TODO issue\n").reusable)


class ASTBaselineTests(unittest.TestCase):
    def test_identical_ast_and_locations_allows_inert_append(self):
        a = b"eval('x')\n"
        b = a + b"# SCM43C-INERT-5\n"
        self.assertTrue(ast_reference_certificate(a, b).reusable)

    def test_ast_same_but_nosec_changed_refused(self):
        a = b"eval('x') # unchanged\n"
        b = b"eval('x') # nosec B307\n"
        self.assertFalse(ast_reference_certificate(a, b).reusable)
        self.assertEqual(ast_reference_certificate(a, b).reason,
                         "scanner_directives_changed")

    def test_ast_equivalence_cannot_ignore_offsets(self):
        self.assertFalse(ast_reference_certificate(b"eval('x')\n",
                                                   b"\neval('x')\n").reusable)

    def test_changed_code_rejected(self):
        self.assertFalse(ast_reference_certificate(b"eval('x')\n",
                                                   b"eval('y')\n").reusable)


class InventoryTests(unittest.TestCase):
    def test_unknown_fails_safe_by_reanalysis(self):
        before = {"a": b"x=1\n", "b": b"eval('a')\n"}
        after = {"a": b"x=1\n# SCM43C-INERT-1\n",
                 "b": b"eval('a')\neval('x')\n"}
        exact, _ = select_reanalysis("hash", before, after)
        narrow, reasons = select_reanalysis("scm_suffix", before, after)
        ast, _ = select_reanalysis("ast_reference", before, after)
        self.assertEqual(exact, {"a", "b"})
        self.assertEqual(narrow, {"b"})
        self.assertEqual(ast, {"b"})
        self.assertIn("extension_not_allowlisted_inert_comment", reasons)

    def test_cannot_use_incomplete_cache_or_partial_scan(self):
        old = {"a": (("B307", 1),), "b": ()}
        with self.assertRaises(ValueError):
            merge_or_fail({"a", "b"}, {"a"}, {"a": ()}, {"a": ()})
        with self.assertRaises(ValueError):
            merge_or_fail({"a", "b"}, {"a"}, old, {})
        result = merge_or_fail({"a", "b"}, {"a"}, old,
                               {"a": (("B307", 5),)})
        self.assertEqual(result["a"], (("B307", 5),))
        self.assertEqual(result["b"], ())

    def test_mutation_scenarios_are_label_blind_and_deterministic(self):
        before = {str(i): b"x=1\n" for i in range(1230)}
        a, m = mutate(before, "mixed")
        b, _ = mutate(before, "mixed")
        self.assertEqual(a, b)
        self.assertEqual(m["actions"]["new_eval_call"], 123)
        self.assertEqual(m["actions"]["inert_suffix"], 1107)
        selected, reasons = select_reanalysis("scm_suffix", before, a)
        self.assertEqual(selected.__len__(), 123)
        self.assertEqual(reasons["exact_prefix_and_single_inert_comment"], 1107)

    def test_line_shift_force_reanalysis(self):
        before = {"a": b"eval('a')\n"}
        after = {"a": b"\neval('a')\n"}
        selected, _ = select_reanalysis("scm_suffix", before, after)
        self.assertEqual(selected, {"a"})


if __name__ == "__main__":
    unittest.main()
