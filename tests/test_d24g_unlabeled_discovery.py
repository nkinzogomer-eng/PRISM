"""D2.4G source-only discovery adversarial guards and Ciel JSON boundary."""
from dataclasses import replace
import unittest
from prism.cyber_discovery import SecurityProbe, discover, ciel_capability_result


class SourceOnlyContract(unittest.TestCase):
    def setUp(self):
        self.cases = [
            SecurityProbe("normal", "public/index.html", "ALLOW", "generic valid path"),
            SecurityProbe("outside", "../outside.txt", "DENY", "generic containment"),
        ]
        self.kwargs = dict(project="example/third-party", source_sha256="a"*64,
                           property_id="path_root_boundary", max_probes=4)

    def test_local_violation_requires_observed_bad_behavior(self):
        r=discover(probes=self.cases,
                   observe=lambda p: ("ALLOW", p), **self.kwargs)
        self.assertEqual(r["status"], "LOCAL_PROPERTY_WITNESS")
        self.assertEqual(r["observed_property_violations"],1)
        self.assertEqual(r["minimal_observed_witness"]["payload"],"../outside.txt")
        self.assertFalse(r["verification"]["previously_unknown_vulnerability_confirmed"])
        self.assertFalse(r["verification"]["overall_program_safety_proved"])

    def test_no_witness_never_means_safe(self):
        r=discover(probes=self.cases,
                   observe=lambda p: ("DENY", None) if p.startswith("../")
                                      else ("ALLOW",p), **self.kwargs)
        self.assertEqual(r["status"],"NO_WITNESS_NOT_SAFE")
        self.assertIsNone(r["minimal_observed_witness"])
        self.assertFalse(r["verification"]["overall_program_safety_proved"])

    def test_probe_budget_is_a_hard_bound(self):
        with self.assertRaisesRegex(ValueError,"exceeds"):
            discover(probes=self.cases,observe=lambda _:("DENY",None),
                     **{**self.kwargs,"max_probes":1})

    def test_empty_candidates_refused(self):
        with self.assertRaisesRegex(ValueError,"empty"):
            discover(probes=[],observe=lambda _:("DENY",None),**self.kwargs)

    def test_duplicate_or_unattributed_refused(self):
        with self.assertRaisesRegex(ValueError,"repeated"):
            discover(probes=[self.cases[0],self.cases[0]],
                     observe=lambda _:("DENY",None),**self.kwargs)
        with self.assertRaisesRegex(ValueError,"unattributed"):
            discover(probes=[replace(self.cases[0],derivation="")],
                     observe=lambda _:("DENY",None),**self.kwargs)

    def test_nondeterministic_oracle_is_not_silent_safe(self):
        with self.assertRaisesRegex(ValueError,"non-discrete"):
            discover(probes=self.cases,observe=lambda _:("UNKNOWN",None),
                     **self.kwargs)

    def test_untrusted_source_digest_refused(self):
        with self.assertRaisesRegex(ValueError,"digest"):
            discover(probes=self.cases,observe=lambda _:("DENY",None),
                     **{**self.kwargs,"source_sha256":"oops"})

    def test_proof_digest_is_stable_across_replays(self):
        f=lambda p:("ALLOW",p)
        a=discover(probes=self.cases,observe=f,**self.kwargs)
        b=discover(probes=self.cases,observe=f,**self.kwargs)
        self.assertEqual(a["replay_sha256"],b["replay_sha256"])

    def test_ciel_receives_unverified_observation_not_truth(self):
        record=discover(probes=self.cases,
                        observe=lambda p:("ALLOW",p),**self.kwargs)
        r=ciel_capability_result(record,mission_id="m",task_id="t",authorized=True)
        self.assertEqual(r["schema"],"scm.prism.ciel-capability.v1")
        self.assertEqual(r["ciel_verification_state"],"UNVERIFIED")
        self.assertEqual(r["mission_id"],"m")
        self.assertTrue(r["needs_independent_attestation"])
        self.assertFalse(r["claim_of_new_vulnerability"])

    def test_ciel_rejects_unauthorized_or_unknown_contract(self):
        record=discover(probes=self.cases,
                        observe=lambda p:("ALLOW",p),**self.kwargs)
        with self.assertRaises(PermissionError):
            ciel_capability_result(record,mission_id="m",task_id="t",authorized=False)
        with self.assertRaisesRegex(ValueError,"schema"):
            ciel_capability_result({"schema":"fake"},mission_id="m",
                                   task_id="t",authorized=True)
        with self.assertRaisesRegex(ValueError,"correlation"):
            ciel_capability_result(record,mission_id="",task_id="t",authorized=True)


if __name__ == "__main__":
    unittest.main()
