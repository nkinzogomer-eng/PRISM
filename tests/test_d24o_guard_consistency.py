"""Adversarial calibration controls; no claim of blind real-world discovery."""
import unittest

from prism.d24o_guard_consistency import propose_peer_debit_guards


SOURCE = """
contract Accounts {
    function take(uint n) external {
        decreaseBalance(account, n);
        checkHealthy(account);
    }
    function move(uint n) external {
        transferBalance(from, to, n);
        checkHealthy(from);
    }
    function giftToReserves(uint n) external {
        uint orig = ledger.users[account].balance;
        uint remaining;
        if (n == 99999) { remaining = 0; }
        else { remaining = orig - n; }
        ledger.users[account].balance = encodeAmount(remaining);
        ledger.reserveBalance += n;
        logEvent(n);
    }
    function supply(uint n) external {
        increaseBalance(account, n);
    }
}
"""


class D24OPeerGuardTests(unittest.TestCase):
    def test_unguarded_direct_balance_decrease_is_a_hypothesis(self):
        result = propose_peer_debit_guards(SOURCE)
        self.assertEqual(result["inferred_peer_checks"]["checkHealthy"], ["move", "take"])
        self.assertEqual([c["function"] for c in result["candidates"]], ["giftToReserves"])
        self.assertEqual(result["verified_real_vulnerabilities"], 0)
        self.assertEqual(result["native_evm_witnesses"], 0)
        self.assertEqual(result["status"], "SOURCE_ONLY_HYPOTHESES_NOT_VERIFIED")

    def test_patch_like_guard_suppresses_anomaly_but_not_claims_safety(self):
        patched = SOURCE.replace("ledger.reserveBalance += n;", "ledger.reserveBalance += n;\n        checkHealthy(account);")
        result = propose_peer_debit_guards(patched)
        self.assertFalse(result["candidates"])
        self.assertEqual(result["status"], "SOURCE_ONLY_HYPOTHESES_NOT_VERIFIED")

    def test_check_before_debit_does_not_justify_later_state(self):
        misplaced = SOURCE.replace("ledger.users[account].balance = encodeAmount(remaining);",
                                   "checkHealthy(account);\n        ledger.users[account].balance = encodeAmount(remaining);")
        self.assertEqual(len(propose_peer_debit_guards(misplaced)["candidates"]), 1)

    def test_dead_or_conditional_guard_does_not_suppress_candidate(self):
        conditional = SOURCE.replace("ledger.reserveBalance += n;",
                                     "ledger.reserveBalance += n;\n        if (false) { checkHealthy(account); }")
        self.assertEqual(len(propose_peer_debit_guards(conditional)["candidates"]), 1)
        conditional = SOURCE.replace("ledger.reserveBalance += n;",
                                     "ledger.reserveBalance += n;\n        if (n > 0) { checkHealthy(account); }")
        self.assertEqual(len(propose_peer_debit_guards(conditional)["candidates"]), 1)
        conditional = SOURCE.replace("ledger.reserveBalance += n;",
                                     "ledger.reserveBalance += n;\n        if (false) checkHealthy(account);")
        self.assertEqual(len(propose_peer_debit_guards(conditional)["candidates"]), 1)

    def test_no_peers_abstains_and_no_bug_name_dependency(self):
        solo = SOURCE.replace("checkHealthy(account);", "logEvent(n);").replace(
            "checkHealthy(from);", "logEvent(n);")
        result = propose_peer_debit_guards(solo)
        self.assertFalse(result["candidates"])
        self.assertEqual(result["inferred_peer_checks"], {})
        renamed = SOURCE.replace("giftToReserves", "executeAllowedAccounting")
        result = propose_peer_debit_guards(renamed)
        self.assertEqual(result["candidates"][0]["function"], "executeAllowedAccounting")

    def test_false_balance_bumps_and_log_calls_are_not_debits(self):
        source = SOURCE.replace("ledger.users[account].balance = encodeAmount(remaining);",
                                "ledger.users[account].balance = encodeAmount(orig + n);")
        source = source.replace("uint remaining;", "uint remaining = orig + n;")
        source = source.replace("remaining = 0;", "remaining = orig + n;")
        source = source.replace("remaining = orig - n;", "remaining = orig + n;")
        result = propose_peer_debit_guards(source)
        self.assertEqual(result["candidates"], [])

    def test_budgets_and_bad_solidity_fail_closed(self):
        with self.assertRaises(ValueError):
            propose_peer_debit_guards(SOURCE, max_candidates=0)
        with self.assertRaises(ValueError):
            propose_peer_debit_guards(SOURCE, minimum_peers=1)
        with self.assertRaises(ValueError):
            propose_peer_debit_guards("not source code")


if __name__ == "__main__":
    unittest.main()
