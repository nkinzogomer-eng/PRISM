"""D2.4 fail-closed evaluation protocol tests.

All mock events here are synthetic TESTS OF THE SCORER. They are NOT measured
PRISM discoveries and must never be included in external benchmark metrics.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import tempfile
import unittest

from prism.defi_external_catalog import TARGET_IDS, ingest, normalize_events
from scripts.d24_external_prepare import CATALOG_SHA, prepare

COMMITS = {
    "aave-v4": "a"*40,
    "superform-v2-periphery": "b"*40,
    "liquity-v2-governance": "c"*40,
    "origin-dollar": "d"*40,
    "drips": "e"*40,
}
REPOS={
    "aave-v4":"aave-v4-scfuzzbench",
    "superform-v2-periphery":"superform-v2-periphery-scfuzzbench",
    "liquity-v2-governance":"liquity-V2-gov-scfuzzbench",
    "origin-dollar":"origin-dollar-scfuzzbench",
    "drips":"drips-fuzzing-scfuzzbench",
}


def make_catalog():
    targets={"schema_version":1, "targets":[]}
    known={"schema_version":1, "targets":[]}
    for ident,revision in COMMITS.items():
        root=f"https://github.com/scfuzzbench/{REPOS[ident]}"
        targets["targets"].append({
            "id":ident,"commit":revision,"repo":root,
            "properties_path":"test/recon/Properties.sol",
        })
        def issue(code,kind,method):
            return {"id":code,
                    "evidence":[{"url":f"{root}/blob/{revision}/test/properties.sol#L1"}],
                    "aliases":[{"event":method,"fuzzers":["foundry","echidna"]}]}
        known["targets"].append({
            "target_id":ident,"target_commit":revision,
            "known_bugs":[issue("bug1","known_bugs","testLoss")] if ident=="origin-dollar" else [],
            "canaries":[issue("canary","canaries","invariant_canary")],
        })
    return targets,known


class D24ExternalTruthTests(unittest.TestCase):
    def setUp(self):
        self.targets,self.truth=make_catalog()

    def test_mock_known_bug_and_canary_separated(self):
        r=ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)
        self.assertEqual(r.statistics["target_count"],5)
        self.assertEqual(r.statistics["externally_documented_issue_count"],1)
        self.assertEqual(r.statistics["canary_count"],5)
        self.assertEqual(r.statistics["execution_status"],"NOT_RUN")
        self.assertIsNone(r.statistics["confirmed_prism_discoveries"])
        self.assertNotIn("testLoss",json.dumps(r.public))
        self.assertNotIn("bug1",json.dumps(r.public))
        e=normalize_events(r.judge,target_id="origin-dollar",fuzzer="foundry",
                           observed_events=["testLoss","testLoss","invariant_canary",
                                            "nonexistent"])
        self.assertEqual(e["known_event_ids"],["bug1"])
        self.assertEqual(e["canary_ids_excluded"],["canary"])
        self.assertEqual(e["unmapped_events"],["nonexistent"])
        self.assertIn("NOT_INDEPENDENTLY",e["observation_claim"])

    def test_external_pins_are_frozen_and_revision_drift_fails(self):
        self.truth["targets"][0]["target_commit"]="f"*40
        with self.assertRaisesRegex(ValueError,"revision drift"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_reject_unknown_target(self):
        self.targets["targets"][0]["id"]="untrusted-vault"
        with self.assertRaisesRegex(ValueError,"unknown target"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_reject_target_repo_substitution(self):
        self.targets["targets"][0]["repo"]="https://evil.invalid/repo"
        with self.assertRaisesRegex(ValueError,"unapproved"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_reject_path_traversal(self):
        self.targets["targets"][0]["properties_path"]="../secrets.py"
        with self.assertRaisesRegex(ValueError,"unsafe"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_evidence_must_point_to_target_commit(self):
        self.truth["targets"][-1]["canaries"][0]["evidence"][0]["url"]=(
            "https://github.com/scfuzzbench/drips-fuzzing-scfuzzbench/blob/main/foo.sol")
        with self.assertRaisesRegex(ValueError,"unpinned"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_cross_category_duplicate_alias_rejected(self):
        self.truth["targets"][3]["known_bugs"][0]["aliases"][0]["event"]="invariant_canary"
        with self.assertRaisesRegex(ValueError,"ambiguous alias"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_known_bug_and_canary_must_have_distinct_id(self):
        self.truth["targets"][3]["known_bugs"][0]["id"]="canary"
        with self.assertRaisesRegex(ValueError,"duplicate or invalid root-cause"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_missing_root_cause_evidence_is_invalid(self):
        self.truth["targets"][3]["known_bugs"][0]["evidence"]=[]
        with self.assertRaisesRegex(ValueError,"missing reviewed"):
            ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)

    def test_event_different_fuzzer_is_unmapped_not_discovered(self):
        r=ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)
        o=normalize_events(r.judge,target_id="origin-dollar",fuzzer="halmos",
                           observed_events=["testLoss"])
        self.assertEqual(o["known_event_ids"],[])
        self.assertEqual(o["unmapped_events"],["testLoss"])

    def test_unverified_event_is_not_counted_as_confirmed(self):
        r=ingest(self.targets,self.truth,catalog_commit=CATALOG_SHA)
        o=normalize_events(r.judge,target_id="origin-dollar",fuzzer="foundry",
                           observed_events=["testLoss"])
        self.assertNotIn("confirmed_discoveries",o)
        self.assertEqual(o["observation_claim"],
                         "EVENT_MAPPING_ONLY_NOT_INDEPENDENTLY_EVM_CONFIRMED")

    def test_prepare_writes_public_and_judge_separately(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            prepare(root,json.dumps(self.targets).encode(),json.dumps(self.truth).encode())
            public=json.loads((root/"detector-public-targets.json").read_text())
            judge=json.loads((root/"judge-only-known-bugs.json").read_text())
            ledger=json.loads((root/"readiness.json").read_text())
            self.assertNotIn("testLoss",json.dumps(public))
            self.assertIn("testLoss",json.dumps(judge))
            self.assertEqual(ledger["inventory"]["execution_status"],"NOT_RUN")
            self.assertTrue(ledger["no_discovery_claim"])

    def test_invalid_commit_syntax(self):
        with self.assertRaisesRegex(ValueError,"invalid immutable SHA"):
            ingest(self.targets,self.truth,catalog_commit="main")


if __name__=="__main__":
    unittest.main()
