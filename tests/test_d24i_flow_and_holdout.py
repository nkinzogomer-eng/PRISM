"""D2.4I: separate source hypothesis inference from safe AST interpretation."""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism.cyber_flow_model import model_source_flow
from prism.cyber_hypotheses import compile_python_hypotheses
from scripts.d24i_holdout import evaluate_holdout


def check(source: str, family: str, **options) -> dict:
    candidates = [h for h in compile_python_hypotheses(source)["candidates"]
                  if h["family"] == family]
    if not candidates:
        raise AssertionError("expected source-derived candidate")
    return model_source_flow(source, candidates[0], **options)


class TestSafeSourceModels(unittest.TestCase):
    def test_command_sink_modeled_without_executing_os_system(self):
        source = "def run(payload):\n    command = 'echo ' + payload\n    os.system(command)\n"
        record = check(source,"untrusted_execution")
        self.assertEqual(record["status"],"MODEL_POSSIBLE_FLOW_NOT_VULNERABILITY")
        self.assertEqual(record["modeled_witnesses"][0]["source_parameters"],["payload"])
        self.assertFalse(record["model_is_original_runtime"])
        self.assertEqual(record["vulnerabilities_confirmed"],0)

    def test_taint_heuristic_false_positive_refuted_by_model(self):
        source = "def run(payload):\n    command = payload\n    command = 'fixed'\n    os.system(command)\n"
        record = check(source,"untrusted_execution")
        self.assertEqual(record["status"],"NO_MODELED_FLOW_NOT_SAFE")
        self.assertEqual(record["modeled_witnesses"],[])

    def test_secret_fstring_reaches_log_model(self):
        source = "def request(password):\n    msg = f'secret={password}'\n    logger.info(msg)\n"
        record = check(source,"secret_logging")
        self.assertEqual(len(record["modeled_witnesses"]),1)
        self.assertEqual(record["modeled_witnesses"][0]["source_parameters"],["password"])

    def test_logging_deferred_percent_format_is_modeled(self):
        source = "def request(token):\n    logger.warning('token=%s', token)\n"
        record = check(source,"secret_logging")
        self.assertEqual(record["status"],"MODEL_POSSIBLE_FLOW_NOT_VULNERABILITY")

    def test_unknown_branches_never_claim_feasibility(self):
        source = "def request(password, toggle):\n    if toggle:\n        logger.info(password)\n"
        record = check(source,"secret_logging")
        self.assertEqual(record["modeled_witnesses"][0]["path_feasibility"],"UNKNOWN")

    def test_import_or_arbitrary_side_effect_causes_abstention(self):
        source = "def request(token):\n    imported = external_call()\n    logger.info(token)\n"
        record = check(source,"secret_logging")
        self.assertEqual(record["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(record["modeled_witnesses"],[])

    def test_actual_source_is_not_executed_even_if_hostile(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp)/"side_effect"
            source = ("def request(secret):\n"
                      "    import pathlib\n"
                      f"    pathlib.Path({str(output)!r}).write_text('EXECUTED')\n"
                      "    logger.info(secret)\n")
            record = check(source,"secret_logging")
            self.assertEqual(record["status"],"INCOMPLETE_UNKNOWN")
            self.assertFalse(output.exists())

    def test_statement_budget_is_honored(self):
        source = "def request(password):\n    data = password\n    logger.info(data)\n"
        record = check(source,"secret_logging",max_statements=1)
        self.assertEqual(record["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(record["reason"],"UNKNOWN_STATEMENT_BUDGET")

    def test_no_shell_no_candidate(self):
        source = "def run(payload):\n    subprocess.run(['echo', payload], shell=False)\n"
        self.assertEqual(compile_python_hypotheses(source)["counts_by_family"]["untrusted_execution"],0)


class TestHoldoutAccounting(unittest.TestCase):
    def test_manifest_lock_and_conservative_results(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            manifest = base/"holdout.json"
            source = base/"sample.py"
            source.write_text("def request(secret):\n    logger.info(secret)\n",encoding="utf-8")
            manifest.write_text(json.dumps({
                "schema":"scm.prism.d24i.preregistered.source-holdout.v1",
                "entries":[{"id":"sample","repository":"example/fictional",
                            "commit":"0123456789abcdef","path":"sample.py"}]
            }),encoding="utf-8")
            result=evaluate_holdout(manifest,base)
            self.assertEqual(result["total_candidates"],1)
            self.assertEqual(result["modeled_flow_witnesses"],1)
            self.assertEqual(result["verified_novel_vulnerabilities"],0)
            self.assertFalse(result["sources_are_executed"])
            self.assertFalse(result["precision_recall_measured"])
            self.assertGreater(result["total_source_bytes"],0)

    def test_manifest_path_traversal_is_rejected(self):
        with TemporaryDirectory() as tmp:
            manifest = Path(tmp)/"manifest.json"
            manifest.write_text(json.dumps({
                "schema":"scm.prism.d24i.preregistered.source-holdout.v1",
                "entries":[{"id":"../escape"}]
            }))
            with self.assertRaisesRegex(ValueError,"invalid source inventory"):
                evaluate_holdout(manifest,Path(tmp))


if __name__ == "__main__":
    unittest.main()
