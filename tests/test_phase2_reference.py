import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Phase2ReferenceBenchmarkTests(unittest.TestCase):
    def test_100_seed_reference_suite_and_hard_gates(self):
        with tempfile.TemporaryDirectory() as output_dir:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "run_phase2_reference.py"),
                    "--runs",
                    "100",
                    "--outdir",
                    output_dir,
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
                check=False,
            )
            # Preserve the generated summary in CI logs for later audit.
            print(completed.stdout)
            if completed.returncode:
                print(completed.stderr)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            json_path = Path(output_dir) / "phase-2-reference-benchmark.json"
            md_path = Path(output_dir) / "phase-2-reference-benchmark.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["protocol_version"], 1)
            self.assertEqual(report["runs_per_seeded_family"], 100)
            self.assertTrue(all(report["hard_gates"].values()))
            self.assertEqual(
                report["policy_comparison"]["families"]["sparse_binary"]["fixed_cost"]["runs"],
                100,
            )
            self.assertEqual(
                report["policy_comparison"]["families"]["misspecified"]["adaptive_greedy"]["runs"],
                100,
            )
            self.assertIn("incomplete declared", " ".join(report["limitations"]))


if __name__ == "__main__":
    unittest.main()
