import unittest

from prism.generators import misspecified, parity, sparse_binary
from prism.optimal import solve_expected
from prism.policies import decision_disagreement, fixed_cost, random_order
from prism.replay import Trace, replay
from prism.runner import run_order


class RunnerTests(unittest.TestCase):
    def test_declared_problem_cannot_see_hidden_world(self):
        g = sparse_binary(seed=1, n=3, support=2)
        self.assertFalse(hasattr(g.declared, "world_table"))
        self.assertIn(g.hidden_id, g.world_table)

    def test_generator_is_reproducible(self):
        a = sparse_binary(seed=5, n=4, support=2)
        b = sparse_binary(seed=5, n=4, support=2)
        self.assertEqual(a.hidden_id, b.hidden_id)
        self.assertEqual(a.world_table, b.world_table)

    def test_misspecified_world_absent_from_declared_class(self):
        g = misspecified(seed=3)
        self.assertNotIn(g.hidden_id, g.declared.hypotheses)
        self.assertIn(g.hidden_id, g.world_table)

    def test_in_class_policies_never_certify_wrong_decision(self):
        for seed in range(20):
            g = sparse_binary(seed=seed, n=4, support=2)
            truth = g.world_table[g.hidden_id]["decision"]
            for policy in (fixed_cost, decision_disagreement):
                out = run_order(g, policy(g))
                if out.result.status == "CERTIFIED_DECISION":
                    self.assertEqual(out.result.decision, truth)

    @unittest.expectedFailure
    def test_KNOWN_FAILURE_misspecified_world_must_not_be_certified_wrongly(self):
        # Gate from docs/benchmark.md. Currently FAILS: certificates are sound only
        # relative to the declared class, so a true world outside that class can
        # still be certified with the wrong decision. Kept as an expected failure
        # so the gap stays visible and the suite is honest.
        wrong = 0
        for seed in range(50):
            g = misspecified(seed=seed, n=3, support=2)
            truth = g.world_table[g.hidden_id]["decision"]
            out = run_order(g, fixed_cost(g))
            if out.result.status == "CERTIFIED_DECISION" and out.result.decision != truth:
                wrong += 1
        self.assertEqual(wrong, 0)

    def test_parity_needs_every_bit(self):
        g = parity(n=3)
        out = run_order(g, fixed_cost(g))
        self.assertEqual(out.result.status, "CERTIFIED_DECISION")
        self.assertEqual(len(out.operations), 3)

    def test_random_order_is_seeded(self):
        g = sparse_binary(seed=2, n=4, support=2)
        self.assertEqual(random_order(g, seed=9), random_order(g, seed=9))

    def test_exact_solver_is_finite_on_small_instance(self):
        g = sparse_binary(seed=4, n=3, support=2)
        cost = solve_expected(g.declared).expected_cost
        self.assertGreaterEqual(cost, 0)
        self.assertLess(cost, float("inf"))

    def test_replay_matches_runner_evidence(self):
        g = sparse_binary(seed=0, n=3, support=1)
        order = fixed_cost(g)[:2]
        out = run_order(g, order)
        pairs = [(o, g.world_table[g.hidden_id]["observations"][o]) for o in order]
        st = replay(g.declared, Trace.from_pairs(pairs))
        self.assertEqual(dict(st.evidence), dict(out.result.state.evidence))


if __name__ == "__main__":
    unittest.main()
