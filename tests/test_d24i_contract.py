"""Ciel proposals may be arbitrary, but PRISM's observations and checks are not."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism.hypothesis_contract import (SCHEMA, CIEL_CAPABILITY_MANIFEST,
                                       ciel_hypothesis_capability_result,
                                       verify_hypothesis)


class HypothesisProofBoundary(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root/"contract.sol"
        self.source.write_text("pragma solidity ^0.8.0; contract Vault {}\n")
        self.digest = sha256(self.source.read_bytes()).hexdigest()
        self.request = {
            "schema":SCHEMA,"mission_id":"mission:1","task_id":"task:1",
            "hypothesis_id":"hypothesis:collateral","proposer":{"kind":"CIEL","id":"ciel.planner"},
            "source":{"path":"contract.sol","sha256":self.digest,"language":"solidity"},
            "property":{"kind":"FINITE_TRACE_INVARIANT","family":"collateralization",
                        "predicate":{"op":"ge","left":{"var":"assets"},
                                     "right":{"var":"liabilities"}}},
            "budget":{"max_observations":3},"execution_policy":"LOCAL_READ_ONLY",
        }

    def tearDown(self):
        self.temp.cleanup()

    def run_request(self, observer=None, request=None):
        return verify_hypothesis(self.request if request is None else request,
                                 authorized_root=self.root,authorized_local=True,
                                 independent_observer=observer)

    def observed(self, rows):
        return lambda ctx: {"observer_id":"prism.fixture.observer",
                            "source_sha256":ctx["source_sha256"],
                            "observations":rows}

    def test_arbitrary_new_family_finite_trace_violation(self):
        r=self.run_request(self.observed([
            {"event_id":"before","values":{"assets":100,"liabilities":90}},
            {"event_id":"after","values":{"assets":80,"liabilities":95}},
        ]))
        self.assertEqual(r["status"],"LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY")
        self.assertEqual(r["witness"]["event_id"],"after")
        self.assertNotIn("values",r["witness"])
        self.assertEqual(r["ciel_verification_state"],"UNVERIFIED")
        self.assertFalse(r["claim_of_new_vulnerability"])
        self.assertTrue(r["needs_independent_attestation"])
        self.assertEqual(r["observations_checked"],2)

    def test_satisfied_finite_trace_does_not_prove_safety(self):
        r=self.run_request(self.observed([
            {"event_id":"one","values":{"assets":100,"liabilities":90}}]))
        self.assertEqual(r["status"],"NO_COUNTEREXAMPLE_OBSERVED_NOT_SAFE")
        self.assertIsNone(r["witness"])

    def test_ciel_output_envelope_never_upgrades_verification(self):
        r=self.run_request(self.observed([
            {"event_id":"x","values":{"assets":0,"liabilities":1}}
        ]))
        exported=ciel_hypothesis_capability_result(r)
        self.assertEqual(exported["schema"],"scm.prism.ciel-capability.v2")
        self.assertEqual(exported["ciel_verification_state"],"UNVERIFIED")
        self.assertEqual(exported["observation"]["status"],
                         "LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY")
        self.assertFalse(exported["claim_of_new_vulnerability"])
        self.assertEqual(CIEL_CAPABILITY_MANIFEST["requires_runtime"],"EXTERNAL")
        self.assertTrue(CIEL_CAPABILITY_MANIFEST["idempotent"])
        forged=deepcopy(r)
        forged["ciel_verification_state"]="VERIFIED"
        with self.assertRaisesRegex(ValueError,"inflated"):
            ciel_hypothesis_capability_result(forged)

    def test_no_injected_trusted_observer_means_unknown(self):
        r=self.run_request()
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(r["reason"],"NO_INDEPENDENT_OBSERVATION_ADAPTER")

    def test_model_may_not_supply_oracle_expected_verdict_or_observations(self):
        for field in ("observations","oracle","expected_verdict","executable_code","proof"):
            with self.subTest(field=field):
                request=deepcopy(self.request)
                request[field]={"malicious":"fake evidence"}
                with self.assertRaisesRegex(ValueError,"unexpected fields"):
                    self.run_request(request=request)

    def test_no_source_authorization_no_read(self):
        with self.assertRaises(PermissionError):
            verify_hypothesis(self.request,authorized_root=self.root)

    def test_hash_mismatch_rejected(self):
        request=deepcopy(self.request)
        request["source"]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"fingerprint changed"):
            self.run_request(request=request)

    def test_relative_escape_and_symlink_rejected(self):
        request=deepcopy(self.request)
        request["source"]["path"]="../contract.sol"
        with self.assertRaisesRegex(ValueError,"path escapes"):
            self.run_request(request=request)
        (self.root/"alias.sol").symlink_to(self.source)
        request["source"]["path"]="alias.sol"
        with self.assertRaisesRegex(ValueError,"symlinks"):
            self.run_request(request=request)

    def test_same_ciel_observer_is_rejected(self):
        def fake(ctx):
            return {"observer_id":"ciel.planner","source_sha256":self.digest,
                    "observations":[{"event_id":"x","values":{"assets":0,"liabilities":1}}]}
        with self.assertRaisesRegex(ValueError,"observer not distinct"):
            self.run_request(fake)

    def test_bogus_observer_hash_and_duplicate_event_rejected(self):
        def wrong(ctx):
            return {"observer_id":"prism.observer","source_sha256":"1"*64,
                    "observations":[{"event_id":"x","values":{}}]}
        with self.assertRaisesRegex(ValueError,"source fingerprint changed"):
            self.run_request(wrong)
        with self.assertRaisesRegex(ValueError,"duplicate"):
            self.run_request(self.observed([
                {"event_id":"x","values":{"assets":0,"liabilities":1}},
                {"event_id":"x","values":{"assets":1,"liabilities":1}},
            ]))

    def test_budget_cannot_be_exceeded(self):
        request=deepcopy(self.request)
        request["budget"]["max_observations"]=1
        with self.assertRaisesRegex(ValueError,"over-budget"):
            self.run_request(self.observed([
                {"event_id":"a","values":{"assets":0,"liabilities":0}},
                {"event_id":"b","values":{"assets":0,"liabilities":0}},
            ]),request=request)

    def test_invalid_predicates_abstain_or_reject_not_execute(self):
        request=deepcopy(self.request)
        request["property"]["predicate"]["op"]="__import__"
        with self.assertRaisesRegex(ValueError,"predicate"):
            self.run_request(request=request)
        r=self.run_request(self.observed([
            {"event_id":"x","values":{"assets":2}}
        ]))
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")
        self.assertIsNone(r["witness"])

    def test_arbitrary_constant_false_predicate_is_not_evidence(self):
        request=deepcopy(self.request)
        request["property"]["predicate"]={
            "op":"eq","left":{"const":0},"right":{"const":1}}
        with self.assertRaisesRegex(ValueError,"observation-dependent"):
            self.run_request(request=request)

    def test_integer_arithmetic_not_float_or_unbounded_code(self):
        request=deepcopy(self.request)
        request["property"]["predicate"]={
            "op":"eq",
            "left":{"op":"add","left":{"var":"a"},"right":{"var":"b"}},
            "right":{"var":"total"},
        }
        r=self.run_request(self.observed([
            {"event_id":"e","values":{"a":5,"b":6,"total":12}}
        ]),request=request)
        self.assertEqual(r["status"],"LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY")
        with self.assertRaisesRegex(ValueError,"unsupported observation"):
            self.run_request(self.observed([
                {"event_id":"e","values":{"a":1.2,"b":2,"total":3}}
            ]),request=request)


if __name__ == "__main__":
    unittest.main()
