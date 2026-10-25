"""Unit guards for real third-party filesystem proof adapter."""
import ast
from pathlib import Path
import tempfile
import unittest

from scripts.d24f_starlette_real_regression import (
    derive_static_path_probes, source_lookup_callable,
)


class StarletteRealProofGuards(unittest.TestCase):
    def test_generated_sibling_prefix_inputs(self):
        cases = derive_static_path_probes("public")
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({p.id for p in cases}), 6)
        self.assertEqual(sum(p.expects_rejection for p in cases), 4)
        self.assertIn("../public2.txt", [x.input for x in cases])
        self.assertFalse(any("CVE" in x.provenance for x in cases))

    def test_missing_external_method_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp)/"src.py"
            file.write_text("class Other:\n    def method(self):\n        pass\n")
            with self.assertRaisesRegex(ValueError,"missing/ambiguous"):
                source_lookup_callable(file)

    def test_method_extraction_and_exact_body_is_executed(self):
        original = """
class StaticFiles:
    def lookup_path(self, path: str):
        if path == "bad":
            return "", None
        return path, 1
"""
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp)/"src.py"
            file.write_text(original)
            fn, digest = source_lookup_callable(file)
            self.assertEqual(fn(None,"bad"), ("",None))
            self.assertEqual(fn(None,"ok"), ("ok",1))
            self.assertEqual(len(digest),64)
            self.assertEqual(file.read_text(),original)

    def test_decorated_method_is_unknown(self):
        original = """
class StaticFiles:
    @unknown
    def lookup_path(self, path):
        return "", None
"""
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp)/"src.py"
            file.write_text(original)
            with self.assertRaisesRegex(ValueError, "decorated"):
                source_lookup_callable(file)

    def test_malformed_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp)/"src.py"
            file.write_text("class A(:")
            with self.assertRaises(SyntaxError):
                source_lookup_callable(file)


if __name__ == "__main__":
    unittest.main()
