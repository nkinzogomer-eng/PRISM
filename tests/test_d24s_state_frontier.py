import unittest

from prism.d24s_state_frontier import propose_state_frontier
from scripts.d24r_safe_native import ABI, _solidity


class StateFrontierTests(unittest.TestCase):
    def test_balanced_initialization_modes_and_zero_assets(self):
        result = propose_state_frontier(ABI)
        self.assertEqual(result["total_proposed"], 24)
        self.assertEqual(sum(not x["initialized_by_legitimate_owners"]
                             for x in result["candidates"]), 12)
        self.assertTrue(all(x["starting_attacker_assets"] == 0
                            for x in result["candidates"]))
        self.assertEqual(result["zero_days"], 0)
        self.assertEqual(result["status"], "POST_INSPECTION_EXPLORATORY_REPRODUCTION")

    def test_frozen_and_exploratory_native_functions_are_separate(self):
        from prism.d24r_zero_capital_probe import propose_treasury_trials
        code = _solidity(propose_treasury_trials(ABI)["candidates"],
                         propose_state_frontier(ABI)["candidates"])
        self.assertIn("test_frozen_bounded_safe_hypotheses", code)
        self.assertIn("test_exploratory_generated_state_frontier", code)
        self.assertIn("D24S_STATE_ASSET_WITNESS_23", code)
        self.assertIn("test_legitimate_owner_approvals_and_nonce_replay", code)


if __name__ == "__main__":
    unittest.main()
