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

    def test_verify_certificate_positive_path(self):
        run = self.run_cli("run", str(self.problem), "--evidence", '{"a":"0"}')
        certificate = self.root / "certificate.json"
        certificate.write_text(json.dumps(json.loads(run.stdout)["certificate"]), encoding="utf-8")
        completed = self.run_cli("verify-certificate", str(self.problem), str(certificate))
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout), {"status": "VERIFIED", "valid": True})

    def test_run_abstains_when_decision_is_not_sufficient(self):
        completed = self.run_cli("run", str(self.problem))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ABSTAIN")

    def test_run_rejects_non_object_evidence(self):
        completed = self.run_cli("run", str(self.problem), "--evidence", "[]")
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")
        self.assertNotIn("Traceback", completed.stderr)

    def test_run_rejects_non_string_evidence_value(self):
        completed = self.run_cli("run", str(self.problem), "--evidence", '{"a":1}')
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")

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

    def test_verify_rejects_modified_and_wrong_problem_certificates(self):
        valid = json.loads(self.run_cli("run", str(self.problem), "--evidence", '{"a":"0"}').stdout)["certificate"]
        modified = dict(valid, decision="unsafe")
        modified_path = self.root / "modified.json"
        modified_path.write_text(json.dumps(modified), encoding="utf-8")
        self.assertEqual(self.run_cli("verify-certificate", str(self.problem), str(modified_path)).returncode, 2)

        other_problem = self.root / "other.json"
        other_problem.write_text(self.problem.read_text(encoding="utf-8").replace("safe", "other"), encoding="utf-8")
        valid_path = self.root / "valid.json"
        valid_path.write_text(json.dumps(valid), encoding="utf-8")
        wrong = self.run_cli("verify-certificate", str(other_problem), str(valid_path))
        self.assertEqual(wrong.returncode, 2)
        self.assertEqual(json.loads(wrong.stdout)["status"], "INVALID")

    def test_verify_rejects_duplicate_ids_and_unsupported_scope(self):
        for name, certificate in {
            "duplicate": {"hypothesis_ids": ["h0", "h0"], "evidence": [["a", "0"]], "decision": "safe"},
            "scope": {"hypothesis_ids": ["h0"], "evidence": [["a", "0"]], "decision": "safe", "scope": "external_world"},
        }.items():
            path = self.root / f"{name}.json"
            path.write_text(json.dumps(certificate), encoding="utf-8")
            completed = self.run_cli("verify-certificate", str(self.problem), str(path))
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(json.loads(completed.stdout)["status"], "INVALID")

    def test_missing_and_invalid_files_return_controlled_error(self):
        missing = self.run_cli("run", str(self.root / "missing.json"))
        self.assertEqual(missing.returncode, 2)
        self.assertEqual(json.loads(missing.stdout)["status"], "ERROR")
        self.assertNotIn("Traceback", missing.stderr)

        invalid = self.root / "invalid.json"
        invalid.write_text("{", encoding="utf-8")
        completed = self.run_cli("run", str(invalid))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")

    def test_malformed_problem_returns_error_json(self):
        malformed = self.root / "malformed.json"
        malformed.write_text("[]", encoding="utf-8")
        completed = self.run_cli("run", str(malformed))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")

    def test_missing_certificate_returns_controlled_error(self):
        completed = self.run_cli("verify-certificate", str(self.problem), str(self.root / "none.json"))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
