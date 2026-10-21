"""Fail-closed tests for observed-only sandbox replay evidence.

Runtime proof still requires the real pinned Flask benchmark, exercised by CI.
"""
import unittest
from pathlib import Path
import tempfile

from scripts.phase44_replay import replay_one
from scripts.phase44_replay_evaluate import evaluate


class ReplayEvidenceTests(unittest.TestCase):
    def test_refuse_arbitrary_module_and_path(self):
        with self.assertRaises(ValueError):
            replay_one(Path("/tmp"), "../../../myserver.py")
        with self.assertRaises(ValueError):
            replay_one(Path("/tmp"), "not-a-benchmark-id")

    def test_runtime_errors_never_become_safety_negatives(self):
        data = {
            "tested": 1,
            "cases": {
                "BenchmarkTest00001": {
                    "status": "unknown", "verified_outside_root": False,
                    "operations": []
                }
            },
        }
        # Reference CSV deliberately supplied only by post-hoc evaluation.
        with tempfile.TemporaryDirectory() as tmp:
            labels = Path(tmp) / "expected.csv"
            labels.write_text("BenchmarkTest00001,pathtraver,true,22\n", encoding="utf8")
            result = evaluate(data, labels)
        self.assertEqual(result["runtime_unknown"], 1)
        self.assertEqual(result["matched_positive_replay_count"], 0)

    def test_negative_label_disagreement_is_preserved(self):
        data = {"tested": 1, "cases": {
            "BenchmarkTest00001": {
                "status": "verified_sandbox_path_escape",
                "verified_outside_root": True,
                "operations": [{"operation": "codecs_open", "completed": True}]
            }
        }}
        with tempfile.TemporaryDirectory() as tmp:
            labels = Path(tmp) / "expected.csv"
            labels.write_text("BenchmarkTest00001,pathtraver,false,22\n", encoding="utf8")
            result = evaluate(data, labels)
        self.assertEqual(result["replayed_but_labelled_negative"], 1)
        self.assertEqual(result["matched_positive_replay_count"], 0)

    def test_forged_unsupported_proof_must_fail(self):
        data = {"tested": 1, "cases": {
            "BenchmarkTest00001": {
                "status": "verified_sandbox_path_escape",
                "verified_outside_root": False, "operations": []
            }
        }}
        with tempfile.TemporaryDirectory() as tmp:
            labels = Path(tmp) / "expected.csv"
            labels.write_text("BenchmarkTest00001,pathtraver,true,22\n", encoding="utf8")
            with self.assertRaises(ValueError):
                evaluate(data, labels)


if __name__ == "__main__":
    unittest.main()
