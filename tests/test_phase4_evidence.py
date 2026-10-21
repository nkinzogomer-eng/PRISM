import unittest
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from scripts.phase4_evidence import case_from_uri, cwes, decision_context, validate_scan
from scripts.audit_phase4 import findings
from scripts.run_phase4_static_baseline import run_tool


class EvidenceTests(unittest.TestCase):
    def test_missing_module_is_not_successful_negative(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def scanner(*args, **kwargs):
                kwargs['stdout'].write(json.dumps({'results': [], 'metrics': {'BenchmarkTest00001.py': {}}}))
                return SimpleNamespace(returncode=0, stderr='')
            with patch('scripts.run_phase4_static_baseline.subprocess.run', side_effect=scanner):
                result = run_tool('bandit', ['unused'], root / 'raw.json', root, {},
                                  expected_ids={'BenchmarkTest00001', 'BenchmarkTest00002'})
            self.assertFalse(result['output_valid_json'])
            self.assertIn('missing_scanned_modules', result['completion_problems'])

    def test_case_boundary_and_encoded_uri(self):
        self.assertIsNone(case_from_uri('fakeBenchmarkTest00001.py'))
        self.assertEqual(case_from_uri('file:///test/BenchmarkTest00001%2Epy'), 'BenchmarkTest00001')

    def test_partial_json_never_means_clean(self):
        self.assertTrue(validate_scan('semgrep', 2, {'results': []}))
        self.assertTrue(validate_scan('bandit', 0, {'results': [], 'errors': ['syntax']}))
        self.assertTrue(validate_scan('semgrep', 0, {'results': [], 'paths': {'scanned': ['a'], 'skipped': ['b']}}))
        self.assertEqual(validate_scan('bandit', 1, {'results': [], 'errors': []}), [])

    def test_backward_dependency_and_no_safety_claim(self):
        result = decision_context('def f(request):\n x = request.args\n y = x\n unrelated = 3\n sink(y)\n', 5)
        self.assertEqual(result['lines'], [2, 3, 5])
        self.assertFalse(result['certifies_safety'])

    def test_cwe_metadata(self):
        self.assertEqual(cwes(['external/cwe/cwe-089']), {89})
        self.assertEqual(cwes(22), {22})

    def test_sarif_extension_rule_and_artifact_index(self):
        data = {'runs': [{'tool': {'driver': {'rules': []}, 'extensions': [
            {'rules': [{'id': 'r', 'properties': {'tags': ['external/cwe/cwe-079']}}]}]},
            'artifacts': [{'location': {'uri': 'testcode/BenchmarkTest00001.py'}}],
            'results': [{'ruleId': 'r', 'rule': {'toolComponent': {'index': 0}},
                         'locations': [{'physicalLocation': {'artifactLocation': {'index': 0},
                                                            'region': {'startLine': 5}}}]}]}]}
        row = list(findings('codeql-default', data))[0]
        self.assertEqual(row[3], {79})
        self.assertEqual(row[2], 5)
