import unittest

from prism.adaptive import Selection, run_adaptive
from prism.generators import sparse_binary


class AdaptiveStateUpdateTests(unittest.TestCase):
    def test_next_selection_receives_actual_prior_observation(self):
        generated = sparse_binary(seed=4, n=3, support=2)
        calls = []

        def selector(problem, state, remaining):
            calls.append((dict(state.evidence), frozenset(remaining)))
            if "x0" in remaining:
                return Selection("x0", planning_cost=0.1)
            if "x1" in remaining:
                return Selection("x1", planning_cost=0.1)
            return None

        outcome = run_adaptive(generated, selector)
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[0][0], {})
        self.assertIn("x0", calls[1][0])
        self.assertNotIn("x0", calls[1][1])
        self.assertEqual(outcome.operations[:2], ("x0", "x1"))


if __name__ == "__main__":
    unittest.main()
