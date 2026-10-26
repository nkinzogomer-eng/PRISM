import json
import unittest

from scripts.d24m_retrospective import NATIVE_TESTS, _verify_native


class IndependentBranchOracleControls(unittest.TestCase):
    def test_frozen_native_inventory_must_all_pass(self):
        good={"D24MBranchValueTest":{"test_results":{
            x:{"status":"Success"} for x in NATIVE_TESTS}}}
        self.assertEqual(_verify_native(json.dumps(good),0)["passed"],3)
        del good["D24MBranchValueTest"]["test_results"][next(iter(NATIVE_TESTS))]
        with self.assertRaisesRegex(ValueError,"all pass"):
            _verify_native(json.dumps(good),0)

    def test_red_or_broken_evm_output_not_accepted(self):
        good={"D24MBranchValueTest":{"test_results":{
            x:{"status":"Success"} for x in NATIVE_TESTS}}}
        with self.assertRaisesRegex(ValueError,"all pass"):
            _verify_native(json.dumps(good),1)
        with self.assertRaisesRegex(ValueError,"JSON"):
            _verify_native("broken",0)


if __name__=="__main__":
    unittest.main()
