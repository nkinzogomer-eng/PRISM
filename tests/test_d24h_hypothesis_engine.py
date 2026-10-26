"""D2.4H targeted adversarial tests: automatic hypotheses, uncertainty and budgets."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism.cyber_hypotheses import compile_python_hypotheses
from scripts.d24h_autonomous_discover import inspect_source


PATH_OLD = '''
import os
class StaticFiles:
    def lookup_path(self, path):
        joined = os.path.join(self.root,path)
        if os.path.commonprefix([joined,self.root]) != self.root:
            return "", None
        return joined, os.stat(joined)
'''
PATH_NEW = PATH_OLD.replace("os.path.commonprefix","os.path.commonpath")

SHELL_BAD = '''
import subprocess
def compile_name(user_data):
    command = "echo " + user_data
    subprocess.run(command, shell=True)
'''
SHELL_SAFE = '''
import subprocess
def compile_name(user_data):
    command = ["echo", user_data]
    subprocess.run(command, shell=False)
'''
LOG_BAD = '''
import logging
def auth(password):
    tmp = "password=" + password
    logging.info(tmp)
'''
LOG_SAFE = '''
import logging
def auth(password):
    logging.info("attempt")
'''

class HypothesisCompiler(unittest.TestCase):
    def test_path_security_candidate_is_inferred_without_given_property(self):
        scan=compile_python_hypotheses(PATH_OLD)
        h=scan["candidates"]
        self.assertEqual(scan["counts_by_family"]["path_boundary"],1)
        self.assertEqual(h[0]["function"],"StaticFiles.lookup_path")
        self.assertEqual(h[0]["verification"],"UNVERIFIED")
        self.assertTrue(any("commonprefix" in s for s in h[0]["source_signals"]))
        self.assertEqual(scan["new_vulnerabilities_confirmed"],0)

    def test_different_implementation_same_security_property(self):
        old=compile_python_hypotheses(PATH_OLD)["candidates"][0]
        fixed=compile_python_hypotheses(PATH_NEW)["candidates"][0]
        self.assertEqual(old["family"],fixed["family"])
        self.assertEqual(old["probe_contract"],fixed["probe_contract"])
        self.assertGreater(old["priority"],fixed["priority"])

    def test_shell_true_tainted_input_creates_separate_risk_family(self):
        scan=compile_python_hypotheses(SHELL_BAD)
        self.assertEqual(scan["counts_by_family"]["untrusted_execution"],1)
        self.assertEqual(scan["counts_by_family"]["path_boundary"],0)
        self.assertEqual(scan["candidates"][0]["verification"],"UNVERIFIED")

    def test_parameterized_shell_false_is_not_falsely_accepted_as_a_bug(self):
        scan=compile_python_hypotheses(SHELL_SAFE)
        self.assertEqual(scan["counts_by_family"]["untrusted_execution"],0)

    def test_secret_data_flow_to_log_is_hypothesis_not_violation(self):
        r=compile_python_hypotheses(LOG_BAD)
        self.assertEqual(r["counts_by_family"]["secret_logging"],1)
        self.assertEqual(r["new_vulnerabilities_confirmed"],0)

    def test_nonsecret_log_not_flagged_by_secret_taint(self):
        self.assertEqual(compile_python_hypotheses(LOG_SAFE)["counts_by_family"]["secret_logging"],0)

    def test_no_vulnerabilities_inferred_on_unrelated_code(self):
        r=compile_python_hypotheses("def do_math(x):\n return x+1\n")
        self.assertEqual(r["candidates"],[])
        self.assertTrue(r["all_candidates_are_unverified"])

    def test_unknown_syntax_fails_closed(self):
        with self.assertRaises(SyntaxError):
            compile_python_hypotheses("def corrupt(:\n")


class SourceExecutionControl(unittest.TestCase):
    def run_text(self, txt, **options):
        with TemporaryDirectory() as folder:
            p=Path(folder)/"safe.py"
            p.write_text(txt)
            return inspect_source(p,authorized_local=True,**options)

    def test_unhandled_shell_is_not_claimed_confirmed_or_safe(self):
        r=self.run_text(SHELL_BAD,enable_execution=False)
        self.assertEqual(r["compiler"]["families"]["untrusted_execution"],1)
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(r["local_behavior_witnesses"],0)
        self.assertEqual(r["unresolved_hypotheses"],1)

    def test_budget_or_missing_adapter_cannot_prove_safety(self):
        r=self.run_text(LOG_BAD,max_probes=1)
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(r["budget"]["used_probes"],0)

    def test_unknown_source_never_equals_safe(self):
        r=self.run_text("def harmless():return 1\n")
        self.assertEqual(r["status"],"NO_HYPOTHESIS_UNKNOWN")

    def test_invalid_budget_and_explicit_permission(self):
        with TemporaryDirectory() as folder:
            p=Path(folder)/"safe.py"
            p.write_text("def ok(): pass\n")
            with self.assertRaises(PermissionError):
                inspect_source(p)
            with self.assertRaisesRegex(ValueError,"budget"):
                inspect_source(p,authorized_local=True,max_probes=0)
            with self.assertRaisesRegex(ValueError,"budget"):
                inspect_source(p,authorized_local=True,max_candidates=0)

    def test_source_malformed_fails_not_zero_findings(self):
        with self.assertRaises(SyntaxError):
            self.run_text("def broken(:")


if __name__=="__main__":
    unittest.main()
