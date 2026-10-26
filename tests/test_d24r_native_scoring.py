import json
from pathlib import Path
import tempfile
import unittest

from scripts.d24r_safe_native import score


class D24RNativeScoring(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        (self.folder / "source_attestation.json").write_text(json.dumps({
            "revision": "bf943f80fec5ac647159d26161446ac5d716a294",
            "original_source_attested": True}))
        (self.folder / "trial_plan.json").write_text(json.dumps({
            "candidates": [{"family": "frozen"} for _ in range(12)]}))
        (self.folder / "state_frontier_plan.json").write_text(json.dumps({
            "candidates": [{"initialized_by_legitimate_owners": i >= 12}
                           for i in range(24)]}))

    def _write_trace(self, *logs):
        (self.folder / "forge-output.txt").write_text(
            "Suite result: ok. 5 passed; 0 failed; 0 skipped\n" + "\n".join(logs))

    def _required(self):
        return ("D24R_FROZEN_TRIALS_EXECUTED",
                "D24R_AUTHORED_POSITIVE_CONTROL_WITNESS",
                "D24R_KNOWN_UNINITIALIZED_PROXY_CONFIGURATION_WITNESS",
                "D24S_GENERATED_STATE_FRONTIER_EXECUTED",
                "D24S_LEGITIMATE_AUTHORIZATION_SUCCEEDED_AND_REPLAY_REJECTED")

    def test_positive_control_is_not_target_zero_day(self):
        self._write_trace(*self._required())
        result = score(self.folder)
        self.assertEqual(result["frozen_treasury_witness_count"], 0)
        self.assertEqual(result["confirmed_zero_days"], 0)
        self.assertFalse(result["actual_zero_expense_proved"])
        self.assertEqual(result["exploratory_state_candidate_count"], 24)
        self.assertEqual(result["status"],
                         "NO_UNAUTHORIZED_TREASURY_WITNESS_IN_FROZEN_BOUNDED_TRIALS")

    def test_unexpected_witness_not_auto_promoted_to_zero_day(self):
        self._write_trace(*self._required(), "D24R_UNAUTHORIZED_WITNESS_6")
        result = score(self.folder)
        self.assertEqual(result["frozen_treasury_witness_indices"], [6])
        self.assertEqual(result["confirmed_zero_days"], 0)
        self.assertEqual(result["status"],
                         "POTENTIAL_NATIVE_WITNESS_REQUIRES_INDEPENDENT_REPLAY")

    def test_native_failure_and_duplicate_witness_rejected(self):
        self._write_trace("D24R_FROZEN_TRIALS_EXECUTED")
        with self.assertRaises(ValueError):
            score(self.folder)
        self._write_trace(*self._required(),
                          "D24R_UNAUTHORIZED_WITNESS_0", "D24R_UNAUTHORIZED_WITNESS_0")
        with self.assertRaises(ValueError):
            score(self.folder)

    def test_state_witness_is_marked_exploratory_not_novel(self):
        self._write_trace(*self._required(), "D24S_STATE_ASSET_WITNESS_11",
                          "D24S_STATE_AUTHORITY_WITNESS_11")
        result = score(self.folder)
        self.assertEqual(result["frozen_treasury_witness_count"], 0)
        self.assertEqual(result["exploratory_state_asset_witness_indices"], [11])
        self.assertFalse(result["exploratory_state_witnesses_are_novelty_claims"])


if __name__ == "__main__":
    unittest.main()
