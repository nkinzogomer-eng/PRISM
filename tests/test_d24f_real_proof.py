"""Adversarial verification of proof evidence and source-derived candidates."""
import unittest

from prism.cyber_proof import Probe, run_revision_pair
from scripts.d24f_historical_real_regression import source_derived_probes


class ProofKernelTests(unittest.TestCase):
    def setUp(self):
        self.cases = (
            Probe("normal", "docs/readme", False, "independent benign input"),
            Probe("hazard", "assets/NUL", True, "independent device boundary"),
        )

    def test_actual_behavior_drives_witness_not_label(self):
        def pre(s):
            return "accepted"  # vulnerable to accidental acceptance
        def post(s):
            return None if s == "assets/NUL" else "accepted"
        r = run_revision_pair(self.cases, before=pre, after=post)
        self.assertEqual(r["status"], "REVISION_PAIR_OBSERVED_UNADJUDICATED")
        self.assertEqual(r["historical_regression_candidates"], 1)
        self.assertEqual(r["minimal_observed_witness"]["input"], "assets/NUL")
        self.assertEqual(r["after_property_failures"], [])
        self.assertFalse(r["independent_real_world_exploit_proved"])
        self.assertFalse(r["novel_discovery_proved"])

    def test_patch_failure_is_not_converted_to_success(self):
        def always_accept(value):
            return "accepted"
        r = run_revision_pair(self.cases,
                              before=always_accept, after=always_accept)
        self.assertIsNone(r["minimal_observed_witness"])
        self.assertEqual(len(r["after_property_failures"]), 1)

    def test_duplicate_ids_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicated"):
            run_revision_pair(self.cases + self.cases, before=lambda _: None,
                              after=lambda _: None)

    def test_missing_provenance_refused(self):
        with self.assertRaisesRegex(ValueError, "provenance"):
            run_revision_pair([Probe("x", "x", False, "")],
                              before=lambda _: None, after=lambda _: None)

    def test_invalid_execution_output_refused(self):
        with self.assertRaisesRegex(TypeError, "invalid first"):
            run_revision_pair(self.cases, before=lambda _: 42,
                              after=lambda _: None)

    def test_derivation_only_from_declared_device_symbols(self):
        probes = source_derived_probes(frozenset({"CON", "AUX", "NUL", "PRN"}))
        nested = [p for p in probes if p.id.startswith("nested:")]
        self.assertEqual(len(nested), 8)
        self.assertTrue(all(p.expects_rejection for p in nested))
        self.assertTrue(all(p.provenance for p in probes))
        self.assertEqual(len({p.id for p in probes}), len(probes))
        self.assertFalse(any("CVE" in p.provenance for p in probes))

    def test_missing_device_symbols_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "no comparable"):
            source_derived_probes(frozenset({"x"}))

    def test_replay_hash_deterministic(self):
        def f(s):
            return None if s.startswith("assets/") else "ok"
        a = run_revision_pair(self.cases, before=f, after=f)
        b = run_revision_pair(self.cases, before=f, after=f)
        self.assertEqual(a["deterministic_replay_sha256"],
                         b["deterministic_replay_sha256"])


if __name__ == "__main__":
    unittest.main()
