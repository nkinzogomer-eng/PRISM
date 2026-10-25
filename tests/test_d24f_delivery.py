"""Adversarial guards for stakeholder-ready historical proof bundle."""
from copy import deepcopy
import unittest

from scripts.d24f_delivery import aggregate

W = {"status": "HISTORICAL_THIRD_PARTY_BEHAVIORAL_REGRESSION_REPRODUCED",
     "external_library": "pallets/werkzeug", "novel_vulnerability_confirmed": False,
     "after_property_failures": [], "minimal_observed_witness": {"input": "docs/AUX"},
     "probe_count": 17, "historical_regression_candidates": 8,
     "revisions": {"before": "3.1.5", "after": "3.1.6"},
     "deterministic_replay_sha256": "0"*64}
S = {"status": "HISTORICAL_THIRD_PARTY_REAL_FILE_BOUNDARY_REPRODUCED",
     "external_library": "Kludex/starlette", "novel_vulnerability_confirmed": False,
     "after_property_failures": [],
     "minimal_observed_witness": {"input": "../public2.txt"},
     "probe_count": 6, "historical_regression_candidates": 3,
     "revisions": {"before": "0.26.1", "after": "0.27.0"},
     "deterministic_replay_sha256": "f"*64}


class BundleGate(unittest.TestCase):
    def test_delivery_two_distinct_historical_causes_not_eleven_cves(self):
        r = aggregate(W,S)
        self.assertEqual(r["counts"]["distinct_historical_root_causes_reproduced"], 2)
        self.assertEqual(r["counts"]["total_confirmed_before_after_witnesses"], 11)
        self.assertEqual(r["counts"]["total_behavioral_inputs"], 23)
        self.assertEqual(r["novel_cves_discovered"], 0)
        self.assertFalse(r["demonstrated_general_superiority"])

    def test_fail_closed_substituted_root_cause(self):
        bad=deepcopy(S)
        bad["external_library"]="fake"
        with self.assertRaisesRegex(ValueError,"substituted"):
            aggregate(W,bad)

    def test_fail_closed_fabricated_novelty(self):
        bad=deepcopy(W)
        bad["novel_vulnerability_confirmed"]=True
        with self.assertRaisesRegex(ValueError,"novelty"):
            aggregate(bad,S)

    def test_fail_closed_patched_property_failure(self):
        bad=deepcopy(S)
        bad["after_property_failures"]=[{"input": "miss"}]
        with self.assertRaisesRegex(ValueError,"security evidence"):
            aggregate(W,bad)

    def test_no_regression_witness_cannot_be_claimed(self):
        bad=deepcopy(W)
        bad["historical_regression_candidates"]=0
        bad["minimal_observed_witness"]=None
        with self.assertRaisesRegex(ValueError,"security evidence"):
            aggregate(bad,S)


if __name__ == "__main__":
    unittest.main()
