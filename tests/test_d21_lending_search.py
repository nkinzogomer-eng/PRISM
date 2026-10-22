"""D2.1 financial-model regression and negative controls."""
import unittest
from prism.defi_lending import State, ACTION_SPACE, search, transition, replay, violates_solvency


class D21SearchTests(unittest.TestCase):
    def test_unsafe_model_has_both_bfs_and_guided_witness(self):
        for p in ("breadth_first", "goal_first"):
            with self.subTest(policy=p):
                r = search(policy=p, guarded_oracle=False)
                self.assertTrue(r.found)
                self.assertLessEqual(len(r.plan), 4)
                model, rejected = replay(r.plan, guarded_oracle=False)
                self.assertIsNone(rejected)
                self.assertTrue(violates_solvency(model))
                self.assertTrue(model.invariant_balances())

    def test_guarded_model_refuses_attacker_price_changes(self):
        for p in ("breadth_first", "goal_first"):
            r = search(policy=p, guarded_oracle=True)
            self.assertFalse(r.found)
            self.assertFalse(r.budget_exhausted)

    def test_guarded_replay_rejects_generated_plan(self):
        r = search(policy="goal_first")
        s, rejected = replay(r.plan, guarded_oracle=True)
        self.assertIsNotNone(rejected)
        self.assertEqual(r.plan[rejected][0], "change_price")
        self.assertFalse(violates_solvency(s))

    def test_model_collateral_and_stable_conservation(self):
        s = State()
        actions = (("deposit", 10), ("change_price", 20),
                   ("borrow", 100), ("change_price", 2))
        for action in actions:
            s = transition(s, action, False)
            self.assertIsNotNone(s)
            self.assertTrue(s.invariant_balances())
        self.assertTrue(violates_solvency(s))

    def test_borrow_without_collateral_is_invalid(self):
        self.assertIsNone(transition(State(), ("borrow", 100), False))

    def test_borrow_exceeding_reported_limit_is_invalid(self):
        s = transition(State(), ("deposit", 10), False)
        self.assertIsNotNone(s)
        self.assertIsNone(transition(s, ("borrow", 100), False))

    def test_unauthorized_price_change_rejected(self):
        self.assertIsNone(transition(State(), ("change_price", 20), True))

    def test_budget_exhaustion_never_implies_safe(self):
        r = search(policy="breadth_first", state_budget=1)
        self.assertFalse(r.found)
        self.assertTrue(r.budget_exhausted)

    def test_illegal_limits(self):
        with self.assertRaises(ValueError):
            search(policy="unknown")
        with self.assertRaises(ValueError):
            search(policy="goal_first", depth=-1)

    def test_unknown_action_rejected(self):
        with self.assertRaises(ValueError):
            transition(State(), ("oracle_remote", 20), False)

    def test_finite_action_alphabet(self):
        self.assertEqual(len(ACTION_SPACE), 6)


if __name__ == "__main__":
    unittest.main()
