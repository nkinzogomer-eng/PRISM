import itertools
import unittest

from prism.optimal import solve_expected
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.transformations import (
    decision_equivalence_quotient,
    verify_decision_equivalence_quotient,
)


def problem_with_duplicate_hypotheses():
    return FiniteProblem(
        hypotheses=[
            Hypothesis("h0", {"a": "0", "b": "0"}, "safe"),
            Hypothesis("h1", {"a": "0", "b": "0"}, "safe"),
            Hypothesis("h2", {"a": "0", "b": "1"}, "unsafe"),
            Hypothesis("h3", {"a": "1", "b": "0"}, "unsafe"),
        ],
        observations=[Observation("a", 1.0), Observation("b", 1.0)],
    )


class DecisionEquivalenceQuotientTests(unittest.TestCase):
    def test_quotient_reduces_only_observation_and_decision_duplicates(self):
        original = problem_with_duplicate_hypotheses()
        quotient = decision_equivalence_quotient(original)

        self.assertEqual(quotient.original_hypothesis_count, 4)
        self.assertEqual(quotient.quotient_hypothesis_count, 3)
        self.assertEqual(quotient.removed_hypothesis_count, 1)
        self.assertEqual(quotient.mapping["h0"], quotient.mapping["h1"])
        self.assertNotEqual(quotient.mapping["h0"], quotient.mapping["h2"])
        self.assertTrue(quotient.preserves_decision_sets)
        self.assertFalse(quotient.preserves_uniform_hypothesis_prior)
        self.assertTrue(verify_decision_equivalence_quotient(original, quotient))

    def test_decision_set_is_preserved_for_every_small_evidence_assignment(self):
        original = problem_with_duplicate_hypotheses()
        quotient = decision_equivalence_quotient(original)
        observation_ids = sorted(original.observations)

        for count in range(len(observation_ids) + 1):
            for subset in itertools.combinations(observation_ids, count):
                domains = [
                    sorted({
                        hypothesis.observations[obs_id]
                        for hypothesis in original.hypotheses.values()
                    })
                    for obs_id in subset
                ]
                for values in itertools.product(*domains):
                    evidence = dict(zip(subset, values))
                    original_decisions = {
                        h.decision for h in original.hypotheses.values()
                        if all(h.observations[k] == v for k, v in evidence.items())
                    }
                    quotient_decisions = {
                        h.decision for h in quotient.problem.hypotheses.values()
                        if all(h.observations[k] == v for k, v in evidence.items())
                    }
                    self.assertEqual(original_decisions, quotient_decisions, evidence)

    def test_same_observations_with_different_decisions_are_not_merged(self):
        original = FiniteProblem(
            hypotheses=[
                Hypothesis("safe", {"x": "0"}, "safe"),
                Hypothesis("unsafe", {"x": "0"}, "unsafe"),
            ],
            observations=[Observation("x", 1.0)],
        )
        quotient = decision_equivalence_quotient(original)
        self.assertEqual(quotient.quotient_hypothesis_count, 2)
        self.assertNotEqual(quotient.mapping["safe"], quotient.mapping["unsafe"])

    def test_uniform_prior_expected_cost_can_change_after_quotient(self):
        original = problem_with_duplicate_hypotheses()
        quotient = decision_equivalence_quotient(original)
        original_cost = solve_expected(original).expected_cost
        quotient_cost = solve_expected(quotient.problem).expected_cost

        self.assertAlmostEqual(original_cost, 1.75)
        self.assertAlmostEqual(quotient_cost, 5.0 / 3.0)
        self.assertNotEqual(original_cost, quotient_cost)

    def test_verifier_rejects_incomplete_mapping(self):
        from dataclasses import replace

        original = problem_with_duplicate_hypotheses()
        quotient = decision_equivalence_quotient(original)
        tampered = replace(
            quotient,
            original_to_representative=quotient.original_to_representative[:-1],
        )
        self.assertFalse(verify_decision_equivalence_quotient(original, tampered))


if __name__ == "__main__":
    unittest.main()
