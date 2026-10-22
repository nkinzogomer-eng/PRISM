"""D2.2 adversarial tests: do not infer labels from reduced model alerts."""
import unittest
from prism.defi_multi import (
    CASES, PROPERTIES, ACTIONS, State, Flags, flags_for,
    transition, search, replay, violated,
)
from scripts.d22_explore import POSITIVE_CASES, create_test, generate_evm_source


class D22ModelTests(unittest.TestCase):
    def test_full_cross_product_and_ground_truth_controls(self):
        for case in CASES:
            for prop in PROPERTIES:
                with self.subTest(case=case, prop=prop):
                    bfs = search(case, prop, policy="breadth_first")
                    goal = search(case, prop, policy="goal_first")
                    self.assertFalse(bfs.exhausted)
                    self.assertFalse(goal.exhausted)
                    self.assertEqual(bfs.found, goal.found)
                    expected = POSITIVE_CASES.get(case) == prop
                    self.assertEqual(goal.found, expected)
                    if expected:
                        state, rejected = replay(case, goal.trace)
                        self.assertIsNone(rejected)
                        self.assertTrue(violated(state, prop))
                        self.assertTrue(state.conserved())

    def test_only_one_bug_flag_per_unsafe_case(self):
        self.assertEqual(flags_for("oracle_bug"), Flags(False, True, True))
        self.assertEqual(flags_for("withdraw_bug"), Flags(True, False, True))
        self.assertEqual(flags_for("repay_bug"), Flags(True, True, False))
        self.assertEqual(flags_for("safe"), Flags(True, True, True))

    def test_unsafe_price_write_never_authorized(self):
        self.assertIsNone(transition(State(), ("price", 20), flags_for("safe")))
        self.assertTrue(transition(State(), ("price", 20),
                                   flags_for("oracle_bug")).unauthorized_price_write)

    def test_correct_withdraw_check_refuses_insolvency(self):
        state = State()
        for action in (("deposit", 10), ("borrow", 10)):
            state = transition(state, action, flags_for("safe"))
        self.assertIsNone(transition(state, ("withdraw", 10), flags_for("safe")))
        bad = transition(state, ("withdraw", 10), flags_for("withdraw_bug"))
        self.assertTrue(violated(bad, PROPERTIES[1]))

    def test_repay_variant_is_no_transfer_and_guarded_is_funded(self):
        good, bad = State(), State()
        for action in (("deposit", 10), ("borrow", 10), ("repay", 10)):
            good = transition(good, action, flags_for("safe"))
            bad = transition(bad, action, flags_for("repay_bug"))
        self.assertEqual(good.debt, bad.debt)
        self.assertFalse(good.unfunded_repayment)
        self.assertTrue(bad.unfunded_repayment)
        self.assertEqual(good.pool_stable, 1000)
        self.assertEqual(bad.pool_stable, 990)

    def test_both_assets_conserved_through_updates(self):
        state = State()
        for action in (("deposit", 10), ("borrow", 10), ("repay", 10),
                       ("withdraw", 10)):
            state = transition(state, action, flags_for("safe"))
            self.assertIsNotNone(state)
            self.assertTrue(state.conserved())

    def test_no_borrow_without_collateral(self):
        self.assertIsNone(transition(State(), ("borrow", 100), flags_for("safe")))

    def test_invalid_parameters_and_property_names(self):
        with self.assertRaises(ValueError):
            flags_for("custom")
        with self.assertRaises(ValueError):
            transition(State(), ("other", 1), Flags())
        with self.assertRaises(ValueError):
            search("safe", "unregistered_property")
        with self.assertRaises(ValueError):
            search("safe", PROPERTIES[0], budget=0)

    def test_budget_exhaustion_not_safety_certificate(self):
        result = search("withdraw_bug", PROPERTIES[1], budget=1)
        self.assertFalse(result.found)
        self.assertTrue(result.exhausted)

    def test_corrected_controls_decline_candidate_or_change_outcome(self):
        for case, prop in POSITIVE_CASES.items():
            with self.subTest(case=case):
                candidate = search(case, prop, policy="goal_first")
                self.assertTrue(candidate.found)
                safe, rejected = replay("safe", candidate.trace)
                self.assertFalse(violated(safe, prop))
                if case == "repay_bug":
                    self.assertIsNone(rejected)
                else:
                    self.assertIsNotNone(rejected)

    def test_generated_tests_have_separate_positive_and_negative_checks(self):
        candidates = {}
        for case, prop in POSITIVE_CASES.items():
            candidate = search(case, prop, policy="goal_first")
            solidity = create_test(case, prop, candidate.trace)
            self.assertIn("BugWitness()", solidity)
            self.assertIn("SafeControl()", solidity)
            candidates[case] = (prop, candidate.trace)
        compiled_source = generate_evm_source(candidates)
        self.assertEqual(compiled_source.count("BugWitness()"), 3)
        self.assertEqual(compiled_source.count("SafeControl()"), 3)
        self.assertIn("D22_UNFUNDED_REPAY_WITNESS", compiled_source)
        self.assertIn("D22_ORACLE_AUTH_WITNESS", compiled_source)
        self.assertIn("D22_WITHDRAW_SOLVENCY_WITNESS", compiled_source)

    def test_action_space_finite_and_reproducible(self):
        self.assertEqual(len(ACTIONS), 10)
        a = search("withdraw_bug", PROPERTIES[1], policy="goal_first")
        b = search("withdraw_bug", PROPERTIES[1], policy="goal_first")
        self.assertEqual(a.trace, b.trace)


if __name__ == "__main__":
    unittest.main()
