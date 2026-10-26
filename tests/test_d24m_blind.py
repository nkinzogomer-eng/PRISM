"""Frozen prospective source metrics cannot be re-labeled or post-tuned."""
from pathlib import Path
import json
import unittest

from scripts.d24m_blind import run_blind,validate_frozen
from tests.test_d24l_typed_graph import compilation


ROOT=Path(__file__).resolve().parents[1]


class FrozenRealTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg=json.loads((ROOT/"benchmarks/defi/d24m/prospective_holdout.json").read_text())
        cls.cfg=(ROOT/"prism/d24m_cfg.py").read_bytes()
        cls.selector=(ROOT/"scripts/d24m_compiler_matrix.py").read_bytes()

    def test_original_engine_and_candidate_budget_are_immutable(self):
        validate_frozen(self.reg,self.cfg,self.selector)
        with self.assertRaisesRegex(ValueError,"ENGINE CHANGED"):
            validate_frozen(self.reg,self.cfg+b"# hindsight",self.selector)
        with self.assertRaisesRegex(ValueError,"POLICY CHANGED"):
            validate_frozen(self.reg,self.cfg,self.selector+b"# hindsight")

    def test_swapped_target_is_a_protocol_violation(self):
        changed=json.loads(json.dumps(self.reg))
        changed["cohort"][0]["path"]="contracts/AfterResult.sol"
        with self.assertRaisesRegex(ValueError,"target list"):
            validate_frozen(changed,self.cfg,self.selector)

    def test_source_failure_is_not_silently_removed(self):
        def fail(_target):
            raise FileNotFoundError("UNAVAILABLE")
        out=run_blind(self.reg,self.cfg,self.selector,fetch_closure=fail)
        self.assertEqual(out["target_count"],2)
        self.assertEqual(out["abstention_count"],2)
        self.assertEqual(out["target_hypotheses_total"],0)
        self.assertEqual(out["confirmed_zero_days"],0)

    def test_dependency_candidates_are_not_attributed_to_target(self):
        def minimal(row):
            return {row["path"]:b"pragma solidity ^0.8.20; contract Lab {}"}
        result=run_blind(self.reg,self.cfg,self.selector,fetch_closure=minimal,
                         compile_source=lambda *_:compilation())
        self.assertEqual(result["compiled_count"],2)
        self.assertEqual(result["target_hypotheses_total"],0)
        self.assertGreaterEqual(result["dependency_hypotheses_total"],2)
        self.assertEqual(result["native_oracles_executed"],0)


if __name__=="__main__":
    unittest.main()
