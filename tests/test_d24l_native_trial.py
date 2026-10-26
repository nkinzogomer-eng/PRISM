"""Do not accept fabricated, partial or red independent EVM verdicts."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.d24l_typed_trial import TESTS, select_build_info, verify_native_evm


class NativeTrialControls(unittest.TestCase):
    def good(self):
        return {"test/D24LBankValue.t.sol:D24LBankValueTest":{
            "test_results":{name:{"status":"Success"} for name in TESTS}}}

    def test_all_three_controls_required(self):
        self.assertEqual(verify_native_evm(json.dumps(self.good()),0)["tests_passed"],3)
        bad=self.good()
        del bad[next(iter(bad))]["test_results"][next(iter(TESTS))]
        with self.assertRaisesRegex(ValueError,"incomplete"):
            verify_native_evm(json.dumps(bad),0)

    def test_exit_code_and_each_native_status_matter(self):
        with self.assertRaisesRegex(ValueError,"failed"):
            verify_native_evm(json.dumps(self.good()),1)
        bad=self.good()
        bad[next(iter(bad))]["test_results"][next(iter(TESTS))]["status"]="Failure"
        with self.assertRaisesRegex(ValueError,"failed"):
            verify_native_evm(json.dumps(bad),0)

    def test_build_info_must_contain_both_original_and_control_ast_files(self):
        with TemporaryDirectory() as folder:
            a=Path(folder)/"one.json"
            a.write_text(json.dumps({"output":{"sources":{
                "test/D24LBankValue.t.sol":{},"src/tokens/ERC4626.sol":{}}}}))
            self.assertIn("output", select_build_info(Path(folder)))
            b=Path(folder)/"two.json"
            b.write_text(a.read_text())
            with self.assertRaisesRegex(ValueError,"exactly one"):
                select_build_info(Path(folder))

    def test_invalid_json_is_not_a_native_success(self):
        with self.assertRaisesRegex(ValueError,"JSON"):
            verify_native_evm("nope",0)


if __name__=="__main__":
    unittest.main()
