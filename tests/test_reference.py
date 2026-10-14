import unittest

from prism.reference import FiniteProblem, Hypothesis, Observation, abstain, certified_stop


def problem():
    return FiniteProblem(
        hypotheses=[
            Hypothesis("h00", {"a": "0", "b": "0"}, "right"),
            Hypothesis("h01", {"a": "0", "b": "1"}, "right"),
            Hypothesis("h10", {"a": "1", "b": "0"}, "left"),
            Hypothesis("h11", {"a": "1", "b": "1"}, "left"),
        ],
        observations=[Observation("a", 1.0), Observation("b", 2.0)],
    )


class ReferenceTests(unittest.TestCase):
    def test_initial_state_is_not_sufficient(self):
        p = problem()
        self.assertIsNone(certified_stop(p, p.initial_state()))

    def test_decision_sufficiency_does_not_require_model_identification(self):
        p = problem()
        r = certified_stop(p, p.apply(p.initial_state(), "a", "0"))
        self.assertEqual(r.status, "CERTIFIED_DECISION")
        self.assertEqual(r.decision, "right")
        self.assertEqual(set(r.certificate.hypothesis_ids), {"h00", "h01"})
        self.assertEqual(r.certificate.scope, "declared_hypothesis_class")
        self.assertTrue(p.verify(r.certificate))

    def test_certificate_rejects_wrong_decision(self):
        p = problem()
        c = p.certificate(p.apply(p.initial_state(), "a", "0"))
        self.assertFalse(p.verify(c.__class__(c.hypothesis_ids, c.evidence, "left")))

    def test_certificate_rejects_unsupported_external_scope(self):
        p = problem()
        c = p.certificate(p.apply(p.initial_state(), "a", "0"))
        external_claim = c.__class__(
            c.hypothesis_ids, c.evidence, c.decision, scope="external_world"
        )
        self.assertFalse(p.verify(external_claim))

    def test_evidence_can_reduce_to_one_model(self):
        p = problem()
        s = p.apply(p.apply(p.initial_state(), "a", "0"), "b", "0")
        self.assertEqual(s.compatible, frozenset({"h00"}))
        self.assertEqual(certified_stop(p, s).decision, "right")

    def test_abstention_is_explicit(self):
        p = problem()
        r = abstain(p, p.initial_state(), "budget_exhausted")
        self.assertEqual((r.status, r.decision, r.reason), ("ABSTAIN", None, "budget_exhausted"))

    def test_unknown_observation_is_rejected(self):
        p = problem()
        with self.assertRaises(KeyError):
            p.apply(p.initial_state(), "unknown", "0")

    def test_duplicate_observation_is_rejected(self):
        p = problem()
        s = p.apply(p.initial_state(), "a", "0")
        with self.assertRaises(ValueError):
            p.apply(s, "a", "0")


if __name__ == "__main__":
    unittest.main()
