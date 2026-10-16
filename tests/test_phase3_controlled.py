import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Phase3ControlledDominanceTests(unittest.TestCase):
    def test_100_seed_controlled_regimes_and_hard_gates(self):
        with tempfile.TemporaryDirectory() as output_dir:
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "run_phase3_controlled.py"),
                 "--runs", "100", "--outdir", output_dir],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=180, check=False,
            )
            print(completed.stdout)
            if completed.returncode:
                print(completed.stderr)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            json_path = Path(output_dir) / "phase-3-controlled-dominance.json"
            md_path = Path(output_dir) / "phase-3-controlled-dominance.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["protocol_version"], 1)
            self.assertEqual(report["runs_per_regime"], 100)
            self.assertTrue(all(report["hard_gates"].values()))
            self.assertEqual(set(report["regimes"]), {
                "favorable", "cost_reversal", "unrelated", "equal_cost_duplicate", "chain"
            })
            self.assertTrue(report["omitted_world_counterexample"]["declared_class_verifier_passed"])
            self.assertTrue(report["omitted_world_counterexample"]["omitted_world_violates_declared_dominance_relation"])


if __name__ == "__main__":
    unittest.main()
