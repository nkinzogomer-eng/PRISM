import unittest

from prism.optimal import solve_expected
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.transformations import (
    prune_dominated_observations,
    verify_dominated_observation_pruning,
)


def rich_and_coarse_problem(rich_cost=1.0, coarse_cost=2.0):
    hypotheses = []
    for first in ("0", "1"):
        for second in ("0", "1"):
            rich = first + second
            hypotheses.append(Hypothesis(
                f"h{rich}",
                {"rich": rich, "coarse": first},
                second,
            ))
    return FiniteProblem(
        hypotheses,
        [Observation("rich", rich_cost), Observation("coarse", coarse_cost)],
    )


class DominatedObservationPruningTests(unittest.TestCase):
    def test_removes_only_observation_dominated_by_no_more_expensive_richer_one(self):
        original = rich_and_coarse_problem()
        pruning = prune_dominated_observations(original)

        self.assertEqual(set(pruning.retained_observation_ids), {"rich"})
        self.assertEqual(pruning.dominators, {"coarse": "rich"})
        self.assertEqual(pruning.removed_observation_count, 1)
        self.assertTrue(pruning.preserves_decision_semantics)
        self.assertTrue(pruning.preserves_uniform_hypothesis_prior)
        self.assertTrue(pruning.preserves_optimal_expected_cost)
        self.assertTrue(verify_dominated_observation_pruning(original, pruning))

    def test_exact_expected_execution_cost_is_preserved(self):
        original = rich_and_coarse_problem()
        pruning = prune_dominated_observations(original)
        self.assertAlmostEqual(solve_expected(original).expected_cost, 1.0)
        self.assertAlmostEqual(solve_expected(pruning.problem).expected_cost, 1.0)

    def test_does_not_remove_cheaper_coarse_observation_for_expensive_rich_one(self):
        original = rich_and_coarse_problem(rich_cost=3.0, coarse_cost=1.0)
        pruning = prune_dominated_observations(original)
        self.assertEqual(set(pruning.retained_observation_ids), {"rich", "coarse"})
        self.assertEqual(pruning.removed_by, ())
        self.assertTrue(verify_dominated_observation_pruning(original, pruning))

    def test_keeps_observations_that_do_not_dominate_each_other(self):
        original = FiniteProblem(
            [
                Hypothesis("h00", {"a": "0", "b": "0"}, "safe"),
                Hypothesis("h01", {"a": "0", "b": "1"}, "unsafe"),
                Hypothesis("h10", {"a": "1", "b": "0"}, "unsafe"),
                Hypothesis("h11", {"a": "1", "b": "1"}, "safe"),
            ],
            [Observation("a", 1.0), Observation("b", 1.0)],
        )
        pruning = prune_dominated_observations(original)
        self.assertEqual(set(pruning.retained_observation_ids), {"a", "b"})
        self.assertEqual(pruning.removed_observation_count, 0)

    def test_verifier_rejects_wrong_dominator(self):
        from dataclasses import replace

        original = rich_and_coarse_problem()
        pruning = prune_dominated_observations(original)
        tampered = replace(pruning, removed_by=(("coarse", "coarse"),))
        self.assertFalse(verify_dominated_observation_pruning(original, tampered))


if __name__ == "__main__":
    unittest.main()
