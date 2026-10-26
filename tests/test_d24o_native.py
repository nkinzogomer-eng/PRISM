"""Fail-closed native-oracle result contract, no synthetic test called real."""
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts.d24o_euler_native import _native_once, restored_guard


class D24ONativeTests(unittest.TestCase):
    def test_restored_guard_only_changes_historical_donation_method(self):
        source = """contract E {
          function withdraw() public { checkLiquidity(account); logAssetStatus(assetCache); }
          function donateToReserves(uint n) external {
            ledger.balance = encodeAmount(rest);
            logAssetStatus(assetCache);
          }
        }"""
        patched = restored_guard(source)
        self.assertEqual(patched.count("checkLiquidity(account);"), 2)
        self.assertEqual(patched.count("function donateToReserves("), 1)
        self.assertTrue(patched.startswith(source.split("function donateToReserves(")[0]))

    def test_unexpected_source_or_existing_guard_fails(self):
        with self.assertRaisesRegex(ValueError, "not found"):
            restored_guard("contract E { function other() public {} }")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            restored_guard("function donateToReserves() { checkLiquidity(account); "
                           "logAssetStatus(assetCache); }")

    def test_exit_zero_without_specific_passing_test_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as d, patch(
                "scripts.d24o_euler_native.subprocess.run") as mock:
            mock.return_value = subprocess.CompletedProcess([], 0, "0 passing\n", "")
            with self.assertRaisesRegex(ValueError, "native EVM control failed"):
                _native_once(Path(d), "fixture.js", Path(d))
            mock.return_value = subprocess.CompletedProcess([], 1, "1 passing\n", "fail")
            with self.assertRaisesRegex(ValueError, "native EVM control failed"):
                _native_once(Path(d), "fixture.js", Path(d))
            mock.return_value = subprocess.CompletedProcess([], 0, "1 passing\n1 failing\n", "")
            with self.assertRaisesRegex(ValueError, "native EVM control failed"):
                _native_once(Path(d), "fixture.js", Path(d))


if __name__ == "__main__":
    unittest.main()
