"""Prospective no-retuning controls: unknowns and misses are first-class."""
import json
from pathlib import Path
import unittest

from scripts.d24j_prospective_trial import (run_prospective, FROZEN_TARGETS,
    FROZEN_MANIFEST_SHA256)


ROOT=Path(__file__).resolve().parents[1]


class ProspectiveTrialGuards(unittest.TestCase):
    def setUp(self):
        self.manifest_path=ROOT/"benchmarks/defi/d24j/prospective_holdout.json"
        self.manifest=json.loads(self.manifest_path.read_text())
        self.engine=(ROOT/"prism/defi_blind_proposer.py").read_bytes()

    def test_freeze_precedes_results_and_engine_matches(self):
        from hashlib import sha256
        self.assertEqual(sha256(self.manifest_path.read_bytes()).hexdigest(),
                         FROZEN_MANIFEST_SHA256)
        self.assertEqual(tuple((r["id"],r["repository"],r["commit"],r["path"])
                     for r in self.manifest["corpus"]),FROZEN_TARGETS)

    def test_valid_negative_results_are_preserved(self):
        samples={
            "P1":b"pragma solidity ^0.8.0; contract V { function previewMove(uint x) public {} function move(uint x) public {} }",
            "P2":b"pragma solidity ^0.8.0; contract V { function noop() public {} }",
            "P3":b"pragma solidity ^0.8.0; contract V { function f(uint x) public {} function f(address x) public {} }",
        }
        r=run_prospective(self.manifest,frozen_engine_source=self.engine,
                          fetch=lambda row:samples[row["id"]])
        self.assertEqual([x["status"] for x in r["results"]],
            ["HYPOTHESES_UNVERIFIED","NO_CANDIDATES_UNKNOWN","UNKNOWN_NOT_SAFE"])
        self.assertEqual(r["candidates_total"],1)
        self.assertEqual(r["abstained_or_unavailable"],1)
        self.assertEqual(r["no_candidate_unknown"],1)
        self.assertEqual(r["new_zero_days_confirmed"],0)

    def test_unavailable_target_not_silently_dropped(self):
        def inaccessible(row):
            raise FileNotFoundError("upstream unavailable")
        r=run_prospective(self.manifest,frozen_engine_source=self.engine,fetch=inaccessible)
        self.assertEqual(r["cohort_count"],3)
        self.assertEqual(r["abstained_or_unavailable"],3)
        self.assertEqual(r["candidates_total"],0)

    def test_source_or_engine_changes_require_a_new_experiment(self):
        with self.assertRaisesRegex(ValueError,"frozen proposer"):
            run_prospective(self.manifest,frozen_engine_source=self.engine+b"#tuned",
                            fetch=lambda row:b"empty")
        m=json.loads(json.dumps(self.manifest))
        m["corpus"][1]["commit"]="0"*40
        with self.assertRaisesRegex(ValueError,"source list"):
            run_prospective(m,frozen_engine_source=self.engine,fetch=lambda row:b"empty")


if __name__=="__main__":
    unittest.main()
