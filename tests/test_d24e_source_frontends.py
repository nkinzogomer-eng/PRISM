"""D2.4E syntax-security boundary and independent conventional graph baseline."""
import ast
import unittest

from prism.cyber_source_frontends import closure, python_surface, solidity_surface
from scripts.d24e_real_source import CASES, MUTATION_NEEDLE, independent_containment


def classical_ast_bfs(text: str, roots: tuple[str, ...]) -> set[str]:
    """Independent conventional AST reachability baseline, no SCM magic."""
    tree = ast.parse(text)
    funcs = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)}
    pending = list(roots)
    seen = set(roots)
    while pending:
        node = funcs[pending.pop()]
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                if sub.func.id in funcs and sub.func.id not in seen:
                    seen.add(sub.func.id)
                    pending.append(sub.func.id)
    return seen


class D24EFrontends(unittest.TestCase):
    sample = """
def safe_join(path):
    return norm(path)
def norm(path):
    return path
def password_hash(value):
    return hashed(value)
def hashed(value):
    return value
def irrelevant(): return 3
"""

    def test_python_ast_closure_matches_independent_classical(self):
        surf = python_surface(self.sample)
        for roots in (("safe_join",), ("password_hash",), ("safe_join", "password_hash")):
            selected = set(closure(surf, roots)["function_frontier"])
            expected = classical_ast_bfs(self.sample, roots)
            self.assertEqual(selected, expected)
        self.assertLess(closure(surf, ("safe_join",))["selected"], len(surf.functions))

    def test_python_unknown_imports_not_security_certificate(self):
        code = "import external\n\ndef check(x):\n    return external.validate(x)\n"
        scan = closure(python_surface(code), ("check",))
        self.assertIn("external.validate", scan["unresolved_calls"])
        self.assertEqual(scan["external_semantics"], "UNKNOWN")
        self.assertFalse(scan["certifies_security"])

    def test_python_dynamic_calls_unresolved(self):
        src = "def a(f):\n return f(42)\n"
        result = closure(python_surface(src), ("a",))
        self.assertIn("f", result["unresolved_calls"])

    def test_python_invalid_syntax_fails_closed(self):
        with self.assertRaises(SyntaxError):
            python_surface("def broken(:")

    def test_python_rebound_name_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "rebound"):
            python_surface("def a(): pass\ndef a(x): return x")

    def test_root_missing_rejected(self):
        with self.assertRaisesRegex(ValueError, "root set"):
            closure(python_surface(self.sample), ("missing",))

    def test_solidity_external_and_local_function_calls(self):
        src = """
        contract Token {
            function transferFrom(address from, address to) external {
                _move(from,to);
                externalToken.transfer(to,3);
            }
            function _move(address from,address to) internal {}
            function noise() external {}
        }
        """
        x = solidity_surface(src)
        got = closure(x, ("transferFrom",))
        self.assertEqual(set(got["function_frontier"]), {"transferFrom", "_move"})
        self.assertIn("transfer", got["unresolved_calls"])
        self.assertFalse(got["certifies_security"])

    def test_source_local_mutation_fixture_not_a_discovery(self):
        self.assertEqual(len(CASES), 7)
        self.assertTrue(independent_containment("/srv/base/a", "/srv/base"))
        self.assertFalse(independent_containment("/srv/base/../sensitive", "/srv/base"))
        self.assertIn("../", MUTATION_NEEDLE)

    def test_no_fake_supremacy_from_slice(self):
        one = closure(python_surface(self.sample), ("safe_join",))
        self.assertEqual(one["total"], 5)
        self.assertEqual(one["selected"], 2)
        self.assertFalse(one["certifies_security"])


if __name__ == "__main__":
    unittest.main()
