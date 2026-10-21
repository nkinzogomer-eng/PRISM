"""Adversarial tests: strict source/rules provenance and full finding integrity."""
from __future__ import annotations
from collections import Counter
import unittest

from prism.incremental import (
    changed_files, content_hash, finding_fingerprint, merge_findings, plan_update
)
from scripts.measure_phase43b import decode_scan, diff_finding_counts, normalized_finding


class IncrementalCoreTests(unittest.TestCase):
    def setUp(self):
        self.old_hashes = {"A": content_hash(b"original"), "B": content_hash(b"unchanged")}
        self.changed_hashes = {"A": content_hash(b"changed"), "B": self.old_hashes["B"]}
        self.old_ledger = {
            "A": (("bandit", "B307", 3),),
            "B": (("semgrep", "rule", 7),),
        }

    def test_only_changed_file_scanned(self):
        self.assertEqual(changed_files(self.old_hashes, self.changed_hashes, True), {"A"})
        plan = plan_update("hash_cache", self.old_hashes, self.changed_hashes,
                           "rules-v1", "rules-v1", 20)
        self.assertEqual(plan.strategy, "incremental")
        self.assertEqual(set(plan.execute), {"A"})

    def test_merge_keeps_all_alerts_with_multiplicity(self):
        updates = {"A": (("bandit", "B307", 4), ("semgrep", "new", 5))}
        combined = merge_findings(self.changed_hashes, self.old_hashes,
                                  "v1", "v1", self.old_ledger, updates, {"A"})
        self.assertEqual(combined["B"], self.old_ledger["B"])
        self.assertEqual(combined["A"], updates["A"])
        self.assertEqual(diff_finding_counts(combined, combined),
                         {"missing": 0, "extra": 0, "affected_modules": 0})

    def test_detects_any_dropped_finding_and_duplicates(self):
        left = {"A": (("x", 1), ("x", 1), ("y", 2))}
        right = {"A": (("x", 1), ("y", 2))}
        self.assertEqual(diff_finding_counts(left, right)["missing"], 1)
        self.assertNotEqual(finding_fingerprint(left), finding_fingerprint(right))

    def test_deny_cache_reuse_when_bytes_changed(self):
        with self.assertRaisesRegex(ValueError, "stale source"):
            merge_findings(self.changed_hashes, self.old_hashes, "v1", "v1",
                           self.old_ledger, {}, set())

    def test_deny_cache_reuse_when_rules_changed(self):
        with self.assertRaisesRegex(ValueError, "stale scanner"):
            merge_findings(self.old_hashes, self.old_hashes, "v1", "v2",
                           self.old_ledger, {"A": ()}, {"A"})

    def test_detect_missing_and_extraneous_results(self):
        for updates in ({}, {"A": (), "B": ()}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                merge_findings(self.changed_hashes, self.old_hashes, "v1", "v1",
                               self.old_ledger, updates, {"A"})

    def test_new_module_and_removed_module(self):
        incoming = {"B": self.old_hashes["B"], "C": content_hash(b"added")}
        plan = plan_update("hash_cache", self.old_hashes, incoming, "v1", "v1", 30)
        self.assertEqual(set(plan.execute), {"C"})
        out = merge_findings(incoming, self.old_hashes, "v1", "v1",
                             self.old_ledger, {"C": ()}, {"C"})
        self.assertEqual(set(out), {"B", "C"})

    def test_all_changed_and_environment_change(self):
        all_changed = {k: content_hash(v.encode()) for k, v in [("A", "new"), ("B", "next")]}
        p = plan_update("prism", self.old_hashes, all_changed, "v1", "v1", 20)
        self.assertEqual(p.strategy, "full")
        q = plan_update("prism", self.old_hashes, self.old_hashes, "v1", "v2", 20)
        self.assertEqual(q.strategy, "full")
        self.assertEqual(set(q.execute), set(self.old_hashes))

    def test_no_changes_no_subprocess(self):
        p = plan_update("prism", self.old_hashes, self.old_hashes, "v1", "v1", 20)
        self.assertEqual(set(p.execute), set())
        self.assertEqual(p.strategy, "incremental")

    def test_bad_calibration(self):
        with self.assertRaises(ValueError):
            plan_update("prism", {}, {}, "v1", "v1", float("nan"))
        with self.assertRaises(ValueError):
            plan_update("prism", {}, {}, "v1", "v1", 10, minimum_fractional_gain=1.0)


class NormalizerTests(unittest.TestCase):
    def test_bandit_line_and_id_are_in_identity(self):
        obj = {"filename": "/tmp/BenchmarkTest00003.py", "test_id": "B307",
               "line_number": 12, "col_offset": 2,
               "issue_text": "eval", "issue_severity": "MEDIUM",
               "issue_confidence": "HIGH"}
        case, identity = normalized_finding("bandit", obj)
        self.assertEqual(case, "BenchmarkTest00003")
        self.assertIn(12, identity)
        obj["line_number"] = 13
        self.assertNotEqual(identity, normalized_finding("bandit", obj)[1])

    def test_semgrep_line_rule_and_message_are_in_identity(self):
        obj = {"path": "BenchmarkTest00003.py", "check_id": "py.x",
               "start": {"line": 7, "col": 2},
               "end": {"line": 7, "col": 8},
               "extra": {"message": "problem", "severity": "WARNING"}}
        case, identity = normalized_finding("semgrep", obj)
        self.assertEqual(case, "BenchmarkTest00003")
        self.assertIn("py.x", identity)
        obj["extra"]["message"] = "different"
        self.assertNotEqual(identity, normalized_finding("semgrep", obj)[1])

    def test_partial_scans_rejected(self):
        raw = {"results": [], "metrics": {"/tmp/BenchmarkTest00003.py": {}},
               "errors": []}
        with self.assertRaisesRegex(ValueError, "inventory"):
            decode_scan("bandit", raw, 0, {"BenchmarkTest00003", "BenchmarkTest00004"})
        good = decode_scan("bandit", raw, 0, {"BenchmarkTest00003"})
        self.assertEqual(good, {"BenchmarkTest00003": ()})
        semgrep = {"results": [], "paths": {"scanned": ["/tmp/BenchmarkTest00003.py"],
                                             "skipped": ["/tmp/BenchmarkTest00004.py"]},
                   "errors": []}
        with self.assertRaises(ValueError):
            decode_scan("semgrep", semgrep, 0, {"BenchmarkTest00003"})

    def test_result_from_unscanned_module_rejected(self):
        raw = {"results": [{"filename": "/tmp/BenchmarkTest00005.py",
                            "test_id": "B307", "line_number": 3}],
               "metrics": {"/tmp/BenchmarkTest00003.py": {}}, "errors": []}
        with self.assertRaises(ValueError):
            decode_scan("bandit", raw, 1, {"BenchmarkTest00003"})


if __name__ == "__main__":
    unittest.main()
