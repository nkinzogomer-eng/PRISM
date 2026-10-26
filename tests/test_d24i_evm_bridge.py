"""Adversarial negative controls for the real Foundry evidence ingestion."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.d24i_evm_bridge import (CASE_CONTRACTS, INVENTORY, PROPERTIES,
    REASONS, EXPECTED_CASE, parse_native_evm, score_native_matrix,
    verify_native_matrix, run_seeded_stress, _run_forge)


def synthetic_json(failed=(), *, omit=(), wrong_reason=False,
                   fail_conservation=False):
    rows={key:{"status":"Success","reason":None,"gas_used":1000}
          for key in INVENTORY if key not in omit}
    for family in failed:
        key=PROPERTIES[family]
        rows[key]={"status":"Failure",
                   "reason":"OTHER_UNRELATED_FAILURE" if wrong_reason else REASONS[family],
                   "gas_used":5000}
    if fail_conservation:
        rows["invariant_TokenConservation()"]={"status":"Failure",
                                                 "reason":"token supply mismatch"}
    return json.dumps({"D22Stateful.t.sol:Test":{"test_results":rows}})


class EVMProofControls(unittest.TestCase):
    def test_expected_labeled_lab_mutant_matrix(self):
        records={}
        for case in CASE_CONTRACTS:
            failed=[family for family,wanted in EXPECTED_CASE.items() if case==wanted]
            records[case]=parse_native_evm(synthetic_json(failed),case=case,
                                           returncode=1 if failed else 0)
        with TemporaryDirectory() as tmp:
            source=Path(tmp)/"MultiRisk.sol"
            source.write_text("pragma solidity ^0.8.24; contract LocalTest {}\n")
            report=verify_native_matrix(records,source)
            self.assertFalse(report["discovery_blind"])
            self.assertEqual(report["new_vulnerabilities_confirmed"],0)
            self.assertEqual(score_native_matrix(records)["missed_known_mutants"],[])
            self.assertEqual(score_native_matrix(records)["spurious_counterexamples"],[])
            for family,case in EXPECTED_CASE.items():
                result=report["hypotheses"][family]
                self.assertEqual(result["observation"]["status"],
                                 "LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY")
                self.assertEqual(result["observation"]["witness"]["event_id"],case)
                self.assertEqual(result["ciel_verification_state"],"UNVERIFIED")

    def test_misses_are_exposed_not_hidden_by_other_mutants(self):
        records={case:parse_native_evm(synthetic_json([]),case=case,returncode=0)
                 for case in CASE_CONTRACTS}
        scored=score_native_matrix(records)
        self.assertEqual(set(scored["missed_known_mutants"]),set(PROPERTIES))
        self.assertEqual(scored["known_mutants_detected"],0)

    def test_spurious_mutant_property_is_detected(self):
        records={case:parse_native_evm(synthetic_json([]),case=case,returncode=0)
                 for case in CASE_CONTRACTS}
        records["oracle_bug"]["properties"]["solvency"]["property_holds"]=False
        self.assertIn(("solvency","oracle_bug"),score_native_matrix(records)["spurious_counterexamples"])

    def test_missing_test_inventory_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"inventory"):
            parse_native_evm(synthetic_json(omit=["invariant_RepaymentFunded()"]),
                             case="safe",returncode=0)

    def test_duplicate_test_name_and_malformed_schema_fail_closed(self):
        original=json.loads(synthetic_json())
        original["SECOND_SUITE"]={"test_results":deepcopy(next(iter(original.values()))["test_results"])}
        with self.assertRaisesRegex(ValueError,"duplicated"):
            parse_native_evm(json.dumps(original),case="safe",returncode=0)
        with self.assertRaisesRegex(ValueError,"valid JSON"):
            parse_native_evm("<not-json>",case="safe",returncode=0)

    def test_unrelated_revert_must_not_count_as_property_violation(self):
        with self.assertRaisesRegex(ValueError,"wrong reason"):
            parse_native_evm(synthetic_json(["oracle"],wrong_reason=True),
                             case="oracle_bug",returncode=1)

    def test_token_conservation_failure_is_an_unknown_harness_failure(self):
        with self.assertRaisesRegex(ValueError,"conservation"):
            parse_native_evm(synthetic_json(fail_conservation=True),
                             case="oracle_bug",returncode=1)

    def test_exit_code_mismatch_must_not_be_reinterpreted_as_success(self):
        with self.assertRaisesRegex(ValueError,"falsely"):
            parse_native_evm(synthetic_json(["repayment"]),case="repay_bug",returncode=0)
        with self.assertRaisesRegex(ValueError,"without verified"):
            parse_native_evm(synthetic_json([]),case="repay_bug",returncode=1)

    def test_no_false_positive_on_safe_evm_variant(self):
        with self.assertRaisesRegex(ValueError,"negative control"):
            parse_native_evm(synthetic_json(["repayment"]),case="safe",returncode=1)

    def test_adaptive_seed_ladder_keeps_early_misses(self):
        def fake_run(root,output,case,*,runs,depth,seed):
            props={family:{"property_holds": not(case==expected and runs>=64)}
                   for family,expected in EXPECTED_CASE.items()}
            return {"properties":props,"stdout_sha256":"0"*64,
                    "wall_seconds":0.01,"child_cpu_seconds":0.01}
        with TemporaryDirectory() as tmp, patch(
            "scripts.d24i_evm_bridge._run_forge",side_effect=fake_run
        ):
            r=run_seeded_stress(Path(tmp),Path(tmp),seeds=(1,2,3))
        self.assertEqual(r["status"],"ENGINEERING_SEED_GATE_PASS")
        self.assertEqual(r["initial_profile_full_detection"],0)
        self.assertEqual(r["seeds_recovered"],3)
        for row in r["results"]:
            self.assertEqual(len(row["attempts"]),2)
            self.assertEqual(len(row["attempts"][0]["missed_known_mutants"]),3)
            self.assertEqual(row["attempts"][1]["missed_known_mutants"],[])

    def test_seed_stress_hard_fail_is_recorded(self):
        def blind(root,output,case,*,runs,depth,seed):
            return {"properties":{family:{"property_holds":True}
                                  for family in EXPECTED_CASE},
                    "stdout_sha256":"0"*64,"wall_seconds":0.01,"child_cpu_seconds":0.01}
        with TemporaryDirectory() as tmp, patch(
            "scripts.d24i_evm_bridge._run_forge",side_effect=blind
        ):
            r=run_seeded_stress(Path(tmp),Path(tmp),seeds=(1,))
        self.assertEqual(r["status"],"KNOWN_MUTANT_SEED_RECALL_NOT_COMPLETE")
        self.assertEqual(r["seeds_recovered"],0)
        self.assertEqual(len(r["results"][0]["attempts"]),3)

    def test_seed_inventory_rejects_duplicates(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError,"non-duplicated"):
                run_seeded_stress(Path(tmp),Path(tmp),seeds=(1,1))

    def test_native_trials_never_replay_another_seed_counterexample(self):
        dirs=[]
        def fake_forge(*args,**kwargs):
            env=kwargs["env"]
            persist=Path(env["FOUNDRY_INVARIANT_FAILURE_PERSIST_DIR"])
            fuzz=Path(env["FOUNDRY_FUZZ_FAILURE_PERSIST_DIR"])
            self.assertTrue(persist.parent.is_dir())
            self.assertFalse(persist.exists())
            self.assertEqual(fuzz.parent,persist.parent)
            self.assertEqual(env["FOUNDRY_FUZZ_SEED"],"0x1")
            dirs.append(persist.parent)
            persist.mkdir()
            (persist/"failure").write_text("previous witness")
            return SimpleNamespace(stdout=synthetic_json(["oracle"]),stderr="",returncode=1)
        with TemporaryDirectory() as tmp, patch(
            "scripts.d24i_evm_bridge.subprocess.run", side_effect=fake_forge
        ):
            for _ in range(2):
                result=_run_forge(Path(tmp),Path(tmp),"oracle_bug",runs=32,depth=16,seed=1)
                self.assertFalse(result["properties"]["oracle"]["property_holds"])
        self.assertEqual(len(set(dirs)),2)
        self.assertTrue(all(not path.exists() for path in dirs))


if __name__ == "__main__":
    unittest.main()
