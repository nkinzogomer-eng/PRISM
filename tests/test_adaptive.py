import unittest

from prism.generators import sparse_binary
from prism.policies import fixed_cost
from prism.adaptive import Selection, run_adaptive


class AdaptiveRunnerTests(unittest.TestCase):
    def test_selector_is_recalled_after_each_observation(self):
        generated = sparse_binary(seed=0, n=3, support=1)
        calls = []

        def selector(problem, state, remaining):
            calls.append((dict(state.evidence), frozenset(remaining)))
            if "x0" in remaining:
                return Selection("x0", planning_cost=0.25)
            if not remaining:
                return None
            return Selection(sorted(remaining)[0], planning_cost=0.25)

        outcome = run_adaptive(generated, selector)
        self.assertGreaterEqual(len(calls), 1)
        self.assertEqual(calls[0][0], {})
        self.assertEqual(outcome.operations[0], "x0")
        self.assertEqual(
            outcome.result.state.cost.planning, 0.25 * len(outcome.operations)
        )

    def test_rejects_negative_planning_cost(self):
        generated = sparse_binary(seed=0, n=3, support=1)
        outcome = run_adaptive(
            generated,
            lambda problem, state, remaining: Selection(sorted(remaining)[0], -1.0),
        )
        self.assertEqual(outcome.result.status, "INVALID_INSTANCE")
        self.assertEqual(outcome.result.reason, "invalid_planning_cost")

    def test_rejects_unavailable_operation(self):
        generated = sparse_binary(seed=0, n=3, support=1)
        outcome = run_adaptive(
            generated,
            lambda problem, state, remaining: Selection("not-an-operation", 0.0),
        )
        self.assertEqual(outcome.result.status, "INVALID_INSTANCE")
        self.assertEqual(outcome.result.reason, "operation_not_available")

    def test_in_class_adaptive_run_never_certifies_wrong_decision(self):
        for seed in range(12):
            generated = sparse_binary(seed=seed, n=4, support=2)
            truth = generated.world_table[generated.hidden_id]["decision"]

            def selector(problem, state, remaining):
                for candidate in fixed_cost(generated):
                    if candidate in remaining:
                        return Selection(candidate, planning_cost=0.01)
                return None

            outcome = run_adaptive(generated, selector)
            if outcome.result.status == "CERTIFIED_DECISION":
                self.assertEqual(outcome.result.decision, truth)

    def test_planning_cost_is_not_silently_free(self):
        generated = sparse_binary(seed=1, n=3, support=1)
        outcome = run_adaptive(
            generated,
            lambda problem, state, remaining: (
                Selection(sorted(remaining)[0], 2.0) if remaining else None
            ),
        )
        self.assertEqual(
            outcome.result.state.cost.planning, 2.0 * len(outcome.operations)
        )


if __name__ == "__main__":
    unittest.main()
