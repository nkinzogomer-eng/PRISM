"""Adversarial bounds on the frozen hypothesis engine (no EVM claims)."""
import unittest

from prism.d24r_zero_capital_probe import propose_treasury_trials
from scripts.d24r_safe_native import ABI, _solidity


class D24RProbeTests(unittest.TestCase):
    def test_budget_and_label_free_grammar(self):
        result = propose_treasury_trials(ABI)
        self.assertEqual(result["status"], "FROZEN_HYPOTHESES_AWAIT_NATIVE_EVM")
        self.assertEqual(result["total_proposed"], 12)
        self.assertEqual(len(result["candidates"]), 12)
        self.assertEqual(result["zero_days"], 0)
        self.assertEqual({x["family"] for x in result["candidates"]}, {
            "unapproved_module_execution", "unsigned_direct_treasury_execution",
            "unauthorized_owner_or_threshold_change", "reinitialization_after_legitimate_setup"})
        self.assertTrue(all(x["attacker_start_assets"] == 0 and
                            x["owner_signatures_supplied"] == 0 for x in result["candidates"]))
        self.assertIn("signature_replay_without_fresh_authorization",
                      result["uncovered_frozen_families"])

    def test_unknown_interface_is_unknown_not_safe(self):
        data = propose_treasury_trials([])
        self.assertEqual(data["status"], "UNSUPPORTED_ABI_UNKNOWN")
        self.assertFalse(data["candidates"])

    def test_budget_and_input_rejection(self):
        for invalid in (0, -1, 65, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                propose_treasury_trials(ABI, max_trials=invalid)
        with self.assertRaises(ValueError):
            propose_treasury_trials(["malformed"])
        limited = propose_treasury_trials(ABI, max_trials=3)
        self.assertEqual(len(limited["candidates"]), 3)
        self.assertEqual(limited["omitted_for_budget"], 9)

    def test_native_source_separates_target_from_controls(self):
        source = _solidity(propose_treasury_trials(ABI)["candidates"])
        self.assertIn("import \"safe/contracts/Safe.sol\"", source)
        self.assertIn("SafeProxy proxy = new SafeProxy", source)
        self.assertIn("test_frozen_bounded_safe_hypotheses", source)
        self.assertIn("test_positive_auth_bypass_control_detected", source)
        self.assertIn("test_exploratory_preinitialization_risk_is_known_not_novel", source)
        self.assertEqual(source.count("uint8 result"), 13)  # 12 declarations + method return
        self.assertIn("D24R_AUTHORITY_WITNESS_11", source)


if __name__ == "__main__":
    unittest.main()
