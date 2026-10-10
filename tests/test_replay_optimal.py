import unittest

from prism.optimal import solve_expected
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.replay import Trace, replay


class ReplayOptimalTests(unittest.TestCase):
    def test_replay_reconstructs_state(self):
        p = FiniteProblem([Hypothesis("h0", {"x": "0"}, "safe"),
                           Hypothesis("h1", {"x": "1"}, "unsafe")],
                          [Observation("x", 2.0)])
        s = replay(p, Trace.from_pairs([("x", "0")]))
        self.assertEqual(dict(s.evidence), {"x": "0"})
        self.assertEqual(s.compatible, frozenset({"h0"}))
        self.assertEqual(s.cost.execution, 2.0)

    def test_replay_rejects_duplicate_steps(self):
        p = FiniteProblem([Hypothesis("h0", {"x": "0"}, "safe")], [Observation("x", 1.0)])
        with self.assertRaises(ValueError):
            replay(p, Trace.from_pairs([("x", "0"), ("x", "0")]))

    def test_exact_solver_chooses_cheapest_decisive_observation(self):
        p = FiniteProblem([Hypothesis("h0", {"cheap": "0", "expensive": "0"}, "safe"),
                           Hypothesis("h1", {"cheap": "1", "expensive": "1"}, "unsafe")],
                          [Observation("cheap", 1.0), Observation("expensive", 4.0)])
        r = solve_expected(p)
        self.assertEqual(r.expected_cost, 1.0)
        self.assertEqual(r.policy.observation_id, "cheap")

    def test_exact_solver_allows_non_identification(self):
        p = FiniteProblem([Hypothesis("h0", {"x": "0"}, "safe"),
                           Hypothesis("h1", {"x": "0"}, "safe")],
                          [Observation("x", 1.0)])
        r = solve_expected(p)
        self.assertEqual(r.expected_cost, 0.0)
        self.assertIsNone(r.policy)


if __name__ == "__main__":
    unittest.main()
