"""Metamorphic/differential hardening of goal-independent finite-trace proof checks."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import random
from tempfile import TemporaryDirectory
import unittest

from prism.hypothesis_contract import SCHEMA, verify_hypothesis


class PredicateStress(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.source=self.root/"tiny.sol"
        self.source.write_text("pragma solidity ^0.8.24; contract Model {}\n")
        self.digest=sha256(self.source.read_bytes()).hexdigest()
        self.base={
            "schema":SCHEMA,"mission_id":"stress:mission","task_id":"stress:task",
            "hypothesis_id":"stress:property",
            "proposer":{"kind":"DETERMINISTIC","id":"prism.generator"},
            "source":{"path":"tiny.sol","sha256":self.digest,"language":"solidity"},
            "property":{"kind":"FINITE_TRACE_INVARIANT","family":"arbitrary_integer_invariant",
                        "predicate":{"op":"eq","left":{"var":"a"},
                                     "right":{"var":"b"}}},
            "budget":{"max_observations":128},"execution_policy":"LOCAL_READ_ONLY",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def perform(self,rows,request=None):
        def observer(ctx):
            return {"observer_id":"independent.fixture.observer",
                    "source_sha256":ctx["source_sha256"],"observations":rows}
        return verify_hypothesis(request or self.base,authorized_root=self.root,
                                 authorized_local=True,independent_observer=observer)

    def test_hundreds_of_seeded_arithmetic_oracles_and_metamorphic_swaps(self):
        rng=random.Random(20261026)
        for seed in range(320):
            a=rng.randrange(0,10**9)
            b=rng.randrange(0,10**9)
            operation=rng.choice(("add","sub","mul"))
            expected={"add":a+b,"sub":a-b,"mul":a*b}[operation]
            actual=expected+(1 if seed % 3 == 0 else 0)
            request=deepcopy(self.base)
            request["property"]["predicate"]={
                "op":"eq","left":{"op":operation,"left":{"var":"a"},
                                   "right":{"var":"b"}},"right":{"var":"observed"}}
            rows=[{"event_id":"trial","values":{"a":a,"b":b,"observed":actual}}]
            outcome=self.perform(rows,request)
            self.assertEqual(outcome["status"],
                "LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY" if actual!=expected
                else "NO_COUNTEREXAMPLE_OBSERVED_NOT_SAFE",seed)
            self.assertFalse(outcome["claim_of_new_vulnerability"])

    def test_max_budget_and_last_event_counterexample(self):
        rows=[{"event_id":f"e{i}","values":{"a":i,"b":i}}
              for i in range(128)]
        rows[-1]["values"]["b"]=-1
        result=self.perform(rows)
        self.assertEqual(result["observations_checked"],128)
        self.assertEqual(result["witness"]["event_id"],"e127")

    def test_numeric_bound_and_boolean_type_confusion_are_unknown_not_safe(self):
        request=deepcopy(self.base)
        request["property"]["predicate"]={
            "op":"eq","left":{"op":"add","left":{"var":"a"},
                                 "right":{"var":"b"}},"right":{"var":"c"}}
        r=self.perform([{"event_id":"overflow","values":{"a":10**30,"b":1,"c":0}}],request)
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")
        r=self.perform([{"event_id":"boolean","values":{"a":True,"b":1,"c":2}}],request)
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")

    def test_precondition_mutation_during_observation_fails(self):
        def adversarial_observer(ctx):
            self.source.write_text("pragma solidity ^0.8.24; contract Replaced {}\n")
            return {"observer_id":"external.observer", "source_sha256":self.digest,
                    "observations":[{"event_id":"e","values":{"a":1,"b":1}}]}
        with self.assertRaisesRegex(ValueError,"fingerprint changed"):
            verify_hypothesis(self.base,authorized_root=self.root,authorized_local=True,
                              independent_observer=adversarial_observer)

    def test_missing_held_out_variable_and_real_false_never_conflated(self):
        rows=[{"event_id":"unreadable","values":{"a":5}},
              {"event_id":"counterexample","values":{"a":5,"b":7}}]
        result=self.perform(rows)
        self.assertEqual(result["status"],"LOCAL_TRACE_COUNTEREXAMPLE_NOT_VULNERABILITY")
        self.assertEqual(result["witness"]["event_id"],"counterexample")


if __name__ == "__main__":
    unittest.main()
