"""D2.4G current-source independent Django adapter controls."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.d24g_source_only_discover import django_scan


SAFE_SOURCE = """
def safe_join(base, *paths):
    final_path = abspath(join(base,*paths))
    base_path = abspath(base)
    if (not normcase(final_path).startswith(normcase(base_path + sep))
        and normcase(final_path) != normcase(base_path)
        and dirname(normcase(base_path)) != normcase(base_path)):
        raise SuspiciousFileOperation("outside")
    return final_path
"""

VULNERABLE_EXAMPLE = """
def safe_join(base, *paths):
    final_path = abspath(join(base,*paths))
    base_path = abspath(base)
    if not normcase(final_path).startswith(normcase(base_path)):
        raise SuspiciousFileOperation("outside")
    return final_path
"""


class DjangoAdapterTests(unittest.TestCase):
    def local(self, text):
        with TemporaryDirectory() as tmp:
            source=Path(tmp)/"module.py"
            source.write_text(text)
            return django_scan(source,limit=16)

    def test_property_conserves_safe_lexical_boundary(self):
        result=self.local(SAFE_SOURCE)
        self.assertEqual(result["status"],"NO_WITNESS_NOT_SAFE")
        self.assertEqual(result["hypotheses_generated"],7)
        self.assertFalse(result["verification"]["overall_program_safety_proved"])

    def test_same_property_detects_sibling_prefix_in_unsafe_fixture(self):
        result=self.local(VULNERABLE_EXAMPLE)
        self.assertEqual(result["status"],"LOCAL_PROPERTY_WITNESS")
        self.assertGreaterEqual(result["observed_property_violations"],1)
        self.assertFalse(result["verification"]["previously_unknown_vulnerability_confirmed"])

    def test_missing_function_is_unknown_not_safe(self):
        with self.assertRaisesRegex(ValueError,"unsupported/ambiguous"):
            self.local("def other(a): return a")

    def test_budget_fail_closed(self):
        with TemporaryDirectory() as tmp:
            source=Path(tmp)/"module.py"
            source.write_text(SAFE_SOURCE)
            with self.assertRaisesRegex(ValueError,"exceeds"):
                django_scan(source,limit=2)


if __name__=="__main__":
    unittest.main()
