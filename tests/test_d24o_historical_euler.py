"""Pin/claim-scope controls for D2.4O historical source inspection."""
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.d24o_historical_euler import HISTORICAL_COMMIT, run_trial


class D24OHistoricalTrialTests(unittest.TestCase):
    def test_reject_wrong_snapshot(self):
        with self.assertRaisesRegex(ValueError, "forty-digit"):
            run_trial(Path("."), commit="master")
        with self.assertRaisesRegex(ValueError, "preregistered"):
            run_trial(Path("."), commit="0"*40)

    def test_unexpected_upstream_refused(self):
        with patch("scripts.d24o_historical_euler._git") as git:
            git.side_effect = [HISTORICAL_COMMIT+"\n", "https://github.com/someone/other.git\n"]
            with self.assertRaisesRegex(ValueError, "unexpected historical"):
                run_trial(Path("."))

    def test_oracle_claims_remain_absent_even_on_historical_candidate(self):
        source = """
        contract A {
            function x(uint q) external { decreaseBalance(user,q); checkHealthy(user); }
            function y(uint q) external { transferBalance(user,other,q); checkHealthy(user); }
            function z(uint q) external {
                uint oldBalance = book.users[user].balance;
                uint next = oldBalance - q;
                book.users[user].balance = encodeAmount(next);
            }
        }
        """
        with patch("scripts.d24o_historical_euler._git") as git:
            git.side_effect = [
                HISTORICAL_COMMIT+"\n",
                "https://github.com/euler-legacy-xyz/euler-contracts.git\n",
                "b"*40+"\n",
                source,
            ]
            result = run_trial(Path("."))
        self.assertEqual([c["function"] for c in result[
            "source_first_candidate_engine"]["candidates"]], ["z"])
        self.assertEqual(result["historical_real_flaws_independently_verified"], 0)
        self.assertEqual(result["new_zero_days"], 0)
        self.assertFalse(result["financial_loss_reproduced"])
        self.assertEqual(result["verdict"], "RETROSPECTIVE_SOURCE_HYPOTHESIS_ONLY")


if __name__ == "__main__":
    unittest.main()
