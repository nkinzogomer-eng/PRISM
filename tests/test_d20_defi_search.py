"""Adversarial checks for the restricted DeFi D2.0 planner.

These are MODEL checks, not independent EVM confirmations.
"""
import json
from pathlib import Path
import tempfile
import unittest

from prism.defi_search import (
    ACTION_SPACE, MAX_DEPTH, INITIAL, State, replay, search, transition, violated,
)
from scripts.d20_explore import run


class DeFiModelTests(unittest.TestCase):
    def test_donation_must_be_backed_by_balance(self):
        self.assertIsNone(transition(State(attacker_wallet=0, victim_wallet=400),
                                     ("donate", 1), protected=False))

    def test_zero_share_mint_is_rejected_by_guard(self):
        source = State()
        source = transition(source, ("deposit_attacker", 1), protected=False)
        source = transition(source, ("donate", 10), protected=False)
        self.assertEqual(source.share_supply, 1)
        bug = transition(source, ("deposit_victim", 1), protected=False)
        fixed = transition(source, ("deposit_victim", 1), protected=True)
        self.assertEqual(bug.victim_shares, 0)
        self.assertTrue(bug.zero_share_victim_deposit)
        self.assertIsNone(fixed)

    def test_redeem_is_not_a_free_mint(self):
        s = transition(State(), ("deposit_attacker", 10), protected=False)
        s = transition(s, ("redeem_attacker", 0), protected=False)
        self.assertEqual(s.attacker_wallet, INITIAL)
        self.assertEqual(s.vault_assets, 0)
        self.assertFalse(violated(s))

    def test_exact_conservation_under_all_local_actions(self):
        for action in ACTION_SPACE:
            next_state = transition(State(), action, protected=False)
            if next_state is not None:
                self.assertTrue(next_state.conservation())
                self.assertEqual(
                    next_state.vault_assets + next_state.attacker_wallet
                    + next_state.victim_wallet,
                    INITIAL * 2,
                )

    def test_same_cap_replay_on_both_variants(self):
        buggy = search(policy="goal_first", protected=False)
        self.assertTrue(buggy.found)
        self.assertEqual(len(buggy.plan), 4)
        s, at = replay(buggy.plan, protected=False)
        self.assertIsNone(at)
        self.assertTrue(violated(s))
        guarded, rejected_at = replay(buggy.plan, protected=True)
        self.assertIsNotNone(rejected_at)
        self.assertEqual(buggy.plan[rejected_at][0], "deposit_victim")
        self.assertFalse(violated(guarded))

    def test_breadth_first_also_finds_candidate(self):
        naive = search(policy="breadth_first", protected=False)
        guided = search(policy="goal_first", protected=False)
        self.assertTrue(naive.found)
        self.assertTrue(guided.found)
        self.assertEqual(len(naive.plan), len(guided.plan))
        self.assertTrue(violated(naive.terminal))
        self.assertTrue(violated(guided.terminal))

    def test_no_witness_on_guarded_vault_at_frozen_depth(self):
        for policy in ("breadth_first", "goal_first"):
            result = search(policy=policy, protected=True)
            self.assertFalse(result.found)
            self.assertFalse(result.budget_exhausted)

    def test_restricted_budget_is_unknown_not_proof_of_safety(self):
        result = search(policy="breadth_first", protected=False, state_budget=1)
        self.assertFalse(result.found)
        self.assertTrue(result.budget_exhausted)

    def test_unsupported_action_fails_closed(self):
        with self.assertRaises(ValueError):
            transition(State(), ("steal", 1), protected=False)

    def test_search_rejects_invalid_limits(self):
        with self.assertRaises(ValueError):
            search(depth=9)
        with self.assertRaises(ValueError):
            search(state_budget=0)

    def test_generator_writes_candidate_not_confirmed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "contract"
            (root / "src").mkdir(parents=True)
            (root / "src" / "VaultFixture.sol").write_text("local test fixture", encoding="utf-8")
            report = run(Path(d) / "reports", root)
            self.assertEqual(report["status"], "CANDIDATE_ONLY_AWAITING_EVM")
            code = (root / "test" / "GeneratedDiscovery.t.sol").read_text()
            self.assertIn("testGeneratedVulnerableTraceAndExactAccounting", code)
            self.assertIn("testSameGeneratedTraceBlockedByGuardedVariant", code)
            self.assertIn("model-EVM-attacker-wallet-mismatch", code)
            self.assertEqual(len(report["plan"]), 4)
            self.assertEqual(len(report["baseline_and_experiment"]), 4)


if __name__ == "__main__":
    unittest.main()
