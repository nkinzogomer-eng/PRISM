"""Guard the independent cached conventional AST competitor against weak setup."""
import unittest
from scripts.d24e_classical_baseline import ast_callgraph_baseline
from prism.cyber_source_frontends import python_surface, closure


class ClassicalBaselineTests(unittest.TestCase):
    def test_cached_classical_baseline_matches_source_frontend(self):
        source = """
def check(s):
    return normalize(s)
def normalize(s):
    return s.strip()
def other():
    return 42
"""
        base = ast_callgraph_baseline(source, {"security": ("check",),
                                                "other": ("other",)})
        graph = python_surface(source)
        for label, roots in (("security", ("check",)), ("other", ("other",))):
            self.assertEqual(base["queries"][label]["closure"],
                             closure(graph, roots)["function_frontier"])
        self.assertEqual(base["function_count"], 3)
        self.assertFalse(base["technical_advantage_of_scm_claimed"])

    def test_missing_root_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing baseline"):
            ast_callgraph_baseline("def a(): pass", {"x": ("missing",)})

    def test_rebound_function_does_not_silently_pass(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ast_callgraph_baseline("def a(): pass\ndef a(x): return x", {"x": ("a",)})

    def test_malformed_source_propagates(self):
        with self.assertRaises(SyntaxError):
            ast_callgraph_baseline("def broken(:", {"x": ("a",)})


if __name__ == "__main__":
    unittest.main()
