"""No source manipulation, label leakage, or missing-source-as-safe results."""
import json
from pathlib import Path
import unittest

from scripts.d24j_label_free_trial import (
    evaluate_frozen_sources, git_blob_digest, validate_target
)


ROOT=Path(__file__).resolve().parents[1]


class FrozenHoldoutGuard(unittest.TestCase):
    def test_three_sources_are_frozen_before_evaluation(self):
        m=json.loads((ROOT/"benchmarks/defi/d24j/preregistration.json").read_text())
        self.assertEqual([r["id"] for r in m["cohort"]],["A","B","C"])
        self.assertEqual(len({r["commit"] for r in m["cohort"]}),3)
        self.assertTrue(m["locked_before_inspecting_selected_source"])
        self.assertNotIn("vulnerability_label",m["decision_rule"]["engine_inputs"])
        for target in m["cohort"]:
            validate_target(target)

    def test_frozen_source_digest_is_a_precondition(self):
        text=b"pragma solidity ^0.8.0; contract X { function f() public {} }"
        m=json.loads((ROOT/"benchmarks/defi/d24j/preregistration.json").read_text())
        m["cohort"]=[dict(m["cohort"][0],git_blob_sha1=git_blob_digest(text))]
        r=evaluate_frozen_sources(m,{"A":text})
        self.assertEqual(r["source_count"],1)
        self.assertEqual(r["candidates_total"],0)
        self.assertEqual(r["cases"][0]["status"],"NO_HYPOTHESES_UNKNOWN")
        self.assertFalse(r["classical_baseline_compared"])
        with self.assertRaisesRegex(ValueError,"digest mismatch"):
            evaluate_frozen_sources(m,{"A":text+b"//tampered"})

    def test_missing_frozen_source_never_means_no_findings(self):
        m=json.loads((ROOT/"benchmarks/defi/d24j/preregistration.json").read_text())
        with self.assertRaisesRegex(ValueError,"incomplete"):
            evaluate_frozen_sources(m,{})

    def test_repository_and_path_cannot_escape_pinned_public_scope(self):
        m=json.loads((ROOT/"benchmarks/defi/d24j/preregistration.json").read_text())
        row=m["cohort"][0]
        for invalid in (dict(row,path="../../privkey.sol"),
                        dict(row,repository="evil.net/a"),
                        dict(row,commit="main"),
                        dict(row,source_kind="private_contract")):
            with self.assertRaises(ValueError):
                validate_target(invalid)


if __name__=="__main__":
    unittest.main()
