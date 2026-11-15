import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "prism", *args],
            check=False,
            capture_output=True,
            text=True,
        )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.problem = self.root / "problem.json"
        self.problem.write_text(
            json.dumps(
                {
                    "hypotheses": [
                        {"id": "h0", "observations": {"a": "0"}, "decision": "safe"},
                        {"id": "h1", "observations": {"a": "1"}, "decision": "unsafe"},
                    ],
                    "observations": [{"id": "a", "cost": 1.0}],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_emits_certified_json(self):
        completed = self.run_cli("run", str(self.problem), "--evidence", '{"a":"0"}')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "CERTIFIED_DECISION")
        self.assertEqual(payload["decision"], "safe")

    def test_run_abstains_when_decision_is_not_sufficient(self):
        completed = self.run_cli("run", str(self.problem))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ABSTAIN")

    def test_verify_rejects_unknown_evidence(self):
        certificate = self.root / "certificate.json"
        certificate.write_text(
            json.dumps(
                {
                    "hypothesis_ids": ["h0"],
                    "evidence": [["unknown", "0"]],
                    "decision": "safe",
                }
            ),
            encoding="utf-8",
        )
        completed = self.run_cli("verify-certificate", str(self.problem), str(certificate))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "INVALID")

    def test_malformed_problem_returns_error_json(self):
        malformed = self.root / "malformed.json"
        malformed.write_text("[]", encoding="utf-8")
        completed = self.run_cli("run", str(malformed))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
