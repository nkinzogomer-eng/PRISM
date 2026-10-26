"""Unseen-cohort freeze and negative/UNKNOWN accounting guards."""
from pathlib import Path
import json
import unittest

from scripts.d24l_prospective import evaluate, validate_registration, retrieve_closure
from tests.test_d24l_typed_graph import compilation


ROOT=Path(__file__).resolve().parents[1]


class ProspectiveFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry=json.loads((ROOT/"benchmarks/defi/d24l/prospective_holdout.json").read_text())
        cls.engine=(ROOT/"prism/d24l_typed_graph.py").read_bytes()

    def test_published_frozen_graph_matches_registration(self):
        validate_registration(self.registry,self.engine)

    def test_editing_engine_or_targets_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"frozen"):
            validate_registration(self.registry,self.engine+b"\n# after-cohort rule")
        clone=json.loads(json.dumps(self.registry))
        clone["targets"][0]["path"]="contracts/other/after-seeing.sol"
        with self.assertRaisesRegex(ValueError,"cohort"):
            validate_registration(clone,self.engine)

    def test_compiler_failure_keeps_both_in_denominator(self):
        outcome=evaluate(self.registry,self.engine,
              fetch=lambda *_:b"pragma solidity ^0.8.24; contract X {}",
              compiler=lambda *_: (_ for _ in ()).throw(ValueError("INVALID_SOLC")))
        self.assertEqual(outcome["frozen_targets"],2)
        self.assertEqual(outcome["abstained_count"],2)
        self.assertEqual(outcome["confirmed_zero_days"],0)

    def test_source_only_candidate_cannot_claim_new_flaw(self):
        result=evaluate(self.registry,self.engine,
             fetch=lambda *_:b"pragma solidity ^0.8.24; contract X {}",
             compiler=lambda *_:compilation())
        self.assertEqual(result["compiled_count"],2)
        self.assertEqual(result["unverified_candidate_total"],4)
        self.assertEqual(result["unverified_target_candidate_total"],0)
        self.assertEqual(result["unverified_dependency_candidate_total"],4)
        self.assertTrue(all(x["status"]=="DEPENDENCY_ONLY_HYPOTHESES_TARGET_UNKNOWN"
                            for x in result["target_results"]))
        self.assertEqual(result["confirmed_new_vulnerabilities"],0)
        self.assertEqual(result["real_evm_oracles_executed"],0)

    def test_import_budget_and_external_dependency_are_labeled(self):
        row=self.registry["targets"][0]
        with self.assertRaisesRegex(ValueError,"UNRESOLVED_PACKAGE_IMPORT"):
            retrieve_closure(row,fetch=lambda *_:b'import "@external/package.sol";')
        with self.assertRaisesRegex(ValueError,"SOURCE_INVALID"):
            retrieve_closure(row,fetch=lambda *_:b"")


if __name__=="__main__":
    unittest.main()
