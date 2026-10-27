import json
from pathlib import Path
import tempfile
import unittest

from prism.d24t_unseen_wallet_frontier import propose_wallet_frontier
from scripts.d24t_unseen_erc4337_native import ABI, _solidity, score


class UnseenSmartAccountTests(unittest.TestCase):
    def test_frozen_state_action_product_and_zero_start(self):
        plan = propose_wallet_frontier(ABI)
        self.assertEqual(plan["total_proposed"], 18)
        self.assertEqual(len(plan["candidates"]), 18)
        self.assertEqual(len([x for x in plan["candidates"]
                              if x["deployment_state"] == "official_initialized"]), 9)
        self.assertTrue(all(x["attacker_start_units"] == 0 for x in plan["candidates"]))
        self.assertIn("unauthorized_ownership_transfer", plan["unsupported_registered_families"])
        self.assertEqual(plan["zero_days"], 0)

    def test_unknown_abi_must_be_unknown_not_safe(self):
        result = propose_wallet_frontier([])
        self.assertEqual(result["status"], "UNSUPPORTED_ABI_UNKNOWN")
        self.assertFalse(result["candidates"])

    def test_budget_and_malformed_abi(self):
        for n in (-1, 0, 25, True):
            with self.subTest(n=n), self.assertRaises(ValueError):
                propose_wallet_frontier(ABI, max_trials=n)
        with self.assertRaises(ValueError):
            propose_wallet_frontier(["invalid"])
        self.assertEqual(propose_wallet_frontier(ABI, max_trials=4)["omitted_for_budget"], 14)

    def test_source_generation_requires_real_original_factory(self):
        src = _solidity(propose_wallet_frontier(ABI)["candidates"])
        self.assertIn("SimpleAccountFactory factory = new SimpleAccountFactory", src)
        self.assertIn("factory.createAccount(OWNER", src)
        self.assertIn("new ERC1967Proxy(address(factory.accountImplementation()), \"\")", src)
        self.assertIn("D24T_ASSET_WITNESS_17", src)
        self.assertIn("test_authorized_owner_control", src)

    def test_result_separates_official_from_unsafe_deployment(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            (out / "trial_plan.json").write_text(json.dumps(propose_wallet_frontier(ABI)))
            (out / "source_attestation.json").write_text(json.dumps({
                "original_sources_attested": True,
                "repositories": {"eth-infinitism/account-abstraction": {
                    "revision": "7af70c8993a6f42973f520ae0752386a5032abe7"}}}))
            control = ["Suite result: ok. 3 passed; 0 failed",
                       "D24T_ALL_GENERATED_EXTERNAL_TRIALS_EXECUTED",
                       "D24T_ORIGINAL_AUTHORIZED_OWNER_CONTROL_SUCCESS",
                       "D24T_AUTHORED_VULNERABLE_CONTROL_SUCCESS"] + [
                           f"D24T_TRIAL_EXECUTED_{i}" for i in range(18)]
            (out / "forge-output.txt").write_text("\n".join(control + [
                "D24T_ASSET_WITNESS_15", "D24T_AUTH_WITNESS_15"]))
            result = score(out)
            self.assertEqual(result["unsafe_proxy_asset_witness_indices"], [15])
            self.assertFalse(result["official_factory_asset_witness_indices"])
            self.assertFalse(result["known_misdeployment_is_zero_day"])
            self.assertFalse(result["zero_actual_expense_verified"])
            self.assertEqual(result["zero_days"], 0)
            self.assertTrue(result["every_candidate_native_execution_logged"])
            (out / "forge-output.txt").write_text("\n".join(control + [
                "D24T_ASSET_WITNESS_0"]))
            self.assertEqual(score(out)["status"],
                             "POTENTIAL_UNEXPECTED_OFFICIAL_FACTORY_OUTFLOW_REQUIRES_INDEPENDENT_TRIAGE")
            (out / "forge-output.txt").write_text("\n".join(control + [
                "D24T_ASSET_WITNESS_15", "D24T_ASSET_WITNESS_15"]))
            with self.assertRaises(ValueError):
                score(out)
            (out / "forge-output.txt").write_text("\n".join(control[:2]))
            with self.assertRaises(ValueError):
                score(out)
            (out / "forge-output.txt").write_text("\n".join(control[:-1]))
            with self.assertRaises(ValueError):
                score(out)


if __name__ == "__main__":
    unittest.main()
