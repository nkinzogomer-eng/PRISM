"""D2.1 multi-contract candidate-model checks and adversarial controls."""
import unittest

from prism.defi_d21_search import (
    ACTIONS, CreditState, DEPTH, explore, replay, step, violation,
)
from scripts.d21_explore import action_solidity, render


class D21ModelTests(unittest.TestCase):
    def setUp(self):
        self.plan = (("pump", 100), ("pledge", 20),
                     ("borrow", 60), ("unwind", 50))

    def test_local_four_action_reference_scenario(self):
        state, rejected = replay(self.plan, guarded=False)
        self.assertIsNone(rejected)
        self.assertEqual(state.q_wallet, 260)
        self.assertEqual(state.c_wallet, 80)
        self.assertEqual((state.q_reserve, state.c_reserve), (100, 100))
        self.assertEqual(state.pledged, 20)
        self.assertEqual(state.debt, 60)
        self.assertEqual(state.lender_q, 440)
        self.assertTrue(state.conserved())
        self.assertTrue(violation(state))

    def test_guarded_rejects_model_borrow_before_unwind(self):
        state, at = replay(self.plan, guarded=True)
        self.assertEqual(at, 2)
        self.assertEqual(state.debt, 0)
        self.assertEqual(state.q_wallet, 100)
        self.assertEqual(state.pledged, 20)

    def test_non_manipulated_loan_is_allowed_and_fair(self):
        state, at = replay((("pledge", 20), ("borrow", 10)), guarded=False)
        self.assertIsNone(at)
        self.assertEqual(state.debt, 10)
        self.assertFalse(violation(state))

    def test_market_manipulation_is_not_itself_a_finding(self):
        state, at = replay((("pump", 100),), guarded=False)
        self.assertIsNone(at)
        self.assertEqual(state.price100(), 400)
        self.assertFalse(violation(state))

    def test_restored_price_without_debt_is_not_a_finding(self):
        state, at = replay((("pump", 100), ("unwind", 50)), guarded=False)
        self.assertIsNone(at)
        self.assertFalse(violation(state))

    def test_liquidity_cap_and_collateral_cap_are_enforced(self):
        self.assertIsNone(step(CreditState(), ("borrow", 60), guarded=False))
        self.assertIsNone(step(CreditState(), ("pledge", 200), guarded=False))
        self.assertIsNone(step(CreditState(), ("pump", 1000), guarded=False))
        self.assertIsNone(step(CreditState(), ("unwind", 0), guarded=False))

    def test_conserved_on_all_one_step_actions(self):
        for action in ACTIONS:
            with self.subTest(action=action):
                nxt = step(CreditState(), action, guarded=False)
                if nxt is not None:
                    self.assertTrue(nxt.conserved())

    def test_search_rejects_unknown_policies_and_invalid_budgets(self):
        for policy, budget in (("invalid", 100), ("goal_first", 0)):
            with self.subTest(policy=policy, budget=budget):
                with self.assertRaises(ValueError):
                    explore(policy=policy, budget=budget)

    def test_zero_depth_returns_no_witness(self):
        x = explore(depth=0)
        self.assertFalse(x.found)
        self.assertFalse(x.exhausted)
        self.assertEqual(x.expanded, 1)

    def test_bfs_can_find_the_bounded_violation(self):
        x = explore(policy="breadth_first", depth=DEPTH)
        self.assertTrue(x.found)
        self.assertLessEqual(len(x.plan), DEPTH)
        state, reject = replay(x.plan, guarded=False)
        self.assertIsNone(reject)
        self.assertTrue(violation(state))

    def test_protected_model_cannot_exceed_reference_credit_under_actions(self):
        result = explore(policy="breadth_first", guarded=True, depth=DEPTH)
        self.assertFalse(result.found)
        self.assertFalse(result.exhausted)

    def test_candidate_plan_is_reproducible(self):
        a = explore(policy="goal_first")
        b = explore(policy="goal_first")
        self.assertTrue(a.found)
        self.assertEqual(a.plan, b.plan)

    def test_solidity_generator_uses_plan_and_enforces_exact_balances(self):
        ending, _ = replay(self.plan, guarded=False)
        safe, reject = replay(self.plan, guarded=True)
        generated = render(self.plan, ending, safe, reject)
        self.assertIn("trader.pump(pool, 100)", generated)
        self.assertIn("trader.unwind(pool, 50)", generated)
        self.assertIn("model-eVM-lender-reserve-diverged", generated)
        self.assertIn("patched-market-accepted-underwater-loan", generated)
        self.assertIn("assertConservation", generated)

    def test_renderer_rejects_non_borrow_guard_failure(self):
        ending, _ = replay(self.plan, guarded=False)
        with self.assertRaises(ValueError):
            render(self.plan, ending, CreditState(), 0)

    def test_unmodeled_action_must_be_rejected(self):
        with self.assertRaises(ValueError):
            action_solidity(("evil_call", 1))
        with self.assertRaises(ValueError):
            step(CreditState(), ("evil_call", 1), guarded=False)


if __name__ == "__main__":
    unittest.main()
