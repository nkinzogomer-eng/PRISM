"""Adversarial and boundary tests for the Phase 4.3A binary OR contract."""
import unittest
from pathlib import Path

from prism.cost_policy import (
    CostEstimate, checked_or, choose_plan, second_stage_inventory,
)
from scripts.measure_phase43 import file_id, verify_pair


class CostPolicyTests(unittest.TestCase):
    def test_positive_calibration_selects_sequential(self):
        estimate = CostEstimate(5.41, 21, 352 / 1230)
        plan = choose_plan(estimate)
        self.assertEqual(plan["mode"], "sequential")
        self.assertGreater(plan["predicted_fractional_gain"], 0.1)

    def test_no_gain_selects_full(self):
        self.assertEqual(choose_plan(CostEstimate(10, 1, 0))["mode"], "full")
        self.assertEqual(choose_plan(CostEstimate(0, 0, 1))["mode"], "full")
        self.assertEqual(choose_plan(CostEstimate(2, 1, 1, planning_seconds=3))["mode"], "full")

    def test_bad_cost_assumptions_rejected(self):
        for args in [(-1, 1, 0.5), (1, float("nan"), 0.5),
                     (1, 2, -0.1), (1, 2, 1.1)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                CostEstimate(*args)
        with self.assertRaises(ValueError):
            choose_plan(CostEstimate(1, 2, 0.5), 1)

    def test_exact_inventory_and_or(self):
        universe = {"a", "b", "c"}
        stage1 = {"a"}
        needed = second_stage_inventory(universe, stage1)
        self.assertEqual(needed, {"b", "c"})
        self.assertEqual(checked_or(universe, stage1, {"c"}, needed, True),
                         {"a", "c"})
        self.assertEqual(checked_or(universe, stage1, {"c"}, universe, False),
                         {"a", "c"})

    def test_missing_second_scan_fails_closed(self):
        with self.assertRaises(ValueError):
            checked_or({"a", "b", "c"}, {"a"}, set(), {"b"}, True)
        with self.assertRaises(ValueError):
            checked_or({"a"}, set(), {"a"}, set(), True)
        with self.assertRaises(ValueError):
            second_stage_inventory({"a"}, {"missing"})

    def test_unchecked_extra_stage_also_fails(self):
        with self.assertRaises(ValueError):
            checked_or({"a", "b"}, {"a"}, set(), {"a", "b"}, True)
        with self.assertRaises(ValueError):
            checked_or({"a"}, set(), set(), set(), False)


class MeasurementVerificationTests(unittest.TestCase):
    def test_case_path_is_strict(self):
        self.assertEqual(file_id("/tmp/BenchmarkTest00008.py"), "BenchmarkTest00008")
        self.assertEqual(file_id(r"C:\test\BenchmarkTest00008.py"), "BenchmarkTest00008")
        self.assertIsNone(file_id("/tmp/BenchmarkTest00008.py.bak"))
        self.assertIsNone(file_id("/tmp/unexpected.py"))

    def test_pair_retains_binary_or_but_not_other_findings(self):
        full = {
            "positive_case_ids": ["a", "c"],
            "second_scanned_ids": ["a", "b", "c"],
            "second_evidence": {"a": [["s1", 5]], "c": [["s2", 8]]},
            "second_findings": 2,
        }
        sequential = {
            "positive_case_ids": ["a", "c"],
            "second_scanned_ids": ["b", "c"],
            "second_evidence": {"c": [["s2", 8]]},
            "second_findings": 1,
        }
        result = verify_pair(full, sequential)
        self.assertTrue(result["decision_equal"])
        self.assertTrue(result["second_stage_findings_equal_on_scanned_cases"])
        self.assertEqual(result["semgrep_findings_intentionally_not_retained_in_first_positive_cases"], 1)

    def test_false_equivalence_is_caught(self):
        full = {
            "positive_case_ids": ["a", "c"], "second_scanned_ids": ["a", "b", "c"],
            "second_evidence": {"c": [["s2", 8]]}, "second_findings": 1,
        }
        candidate = {
            "positive_case_ids": ["a"], "second_scanned_ids": ["b", "c"],
            "second_evidence": {}, "second_findings": 0,
        }
        result = verify_pair(full, candidate)
        self.assertFalse(result["decision_equal"])
        self.assertFalse(result["second_stage_findings_equal_on_scanned_cases"])
        self.assertEqual(result["missing_positive_cases"], ["c"])


if __name__ == "__main__":
    unittest.main()
