"""Frozen hypotheses must never be mislabeled as confirmed flaws."""
import json
from pathlib import Path
import unittest

from scripts.d24n_blind import evaluate,validate
from tests.test_d24l_typed_graph import compilation


ROOT=Path(__file__).resolve().parents[1]


class FrozenNTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=json.loads((ROOT/"benchmarks/defi/d24n/prospective_holdout.json").read_text())
        cls.engine=(ROOT/"prism/d24m_cfg.py").read_bytes()
        cls.compilers=(ROOT/"scripts/d24n_compiler_matrix.py").read_bytes()

    def test_frozen_source_and_compiler_unchanged(self):
        validate(self.m,self.engine,self.compilers)
        with self.assertRaisesRegex(ValueError,"ENGINE"):
            validate(self.m,self.engine+b"#tuned",self.compilers)
        with self.assertRaisesRegex(ValueError,"POLICY"):
            validate(self.m,self.engine,self.compilers+b"#tuned")

    def test_target_removal_and_swap_rejected(self):
        changes=json.loads(json.dumps(self.m))
        changes["cohort"][0]["path"]="contracts/CandidateAfterSeeingIt.sol"
        with self.assertRaisesRegex(ValueError,"TARGETS"):
            validate(changes,self.engine,self.compilers)

    def test_missing_unseen_source_kept_in_denominator(self):
        def no_source(target):
            raise FileNotFoundError("upstream missing")
        r=evaluate(self.m,self.engine,self.compilers,fetch=no_source)
        self.assertEqual(r["cohort_size"],2)
        self.assertEqual(r["abstentions"],2)
        self.assertEqual(r["new_vulnerabilities_confirmed"],0)

    def test_source_only_dependency_detected_without_false_attribution(self):
        r=evaluate(self.m,self.engine,self.compilers,
          fetch=lambda t:{t["path"]:b"pragma solidity >=0.4.22 <0.9.0;"},
          compile_source=lambda *_:compilation())
        self.assertEqual(r["compiled_targets"],2)
        self.assertEqual(r["unverified_target_hypotheses"],0)
        self.assertGreaterEqual(r["unverified_dependency_hypotheses"],2)
        self.assertEqual(r["zero_days_confirmed"],0)


if __name__=="__main__":
    unittest.main()
