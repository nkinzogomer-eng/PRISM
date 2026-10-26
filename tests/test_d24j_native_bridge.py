"""Adversarial guards for actual third-party EVM observation parsing."""
import json
import unittest

from scripts.d24j_native_evm import TESTS, _relative_imports, parse_foundry_lab


def forged(status="Success", *, missing=(), extra=False):
    rows={name:{"status":status,"reason":None} for name in TESTS if name not in missing}
    if extra:
        rows["test_ignored_extra()"]={"status":"Success"}
    return json.dumps({"D24J.t.sol:Suite":{"test_results":rows}})


class NativeEvidenceGuards(unittest.TestCase):
    def test_complete_bounded_inventory_success(self):
        out=parse_foundry_lab(forged(),0)
        self.assertEqual(out["passed"],3)
        self.assertEqual(out["total"],3)
        self.assertEqual(len(out["native_stdout_sha256"]),64)

    def test_missing_or_extra_observer_is_not_a_green_evaluation(self):
        with self.assertRaisesRegex(ValueError,"missing or unexpected"):
            parse_foundry_lab(forged(missing=(next(iter(TESTS)),)),0)
        with self.assertRaisesRegex(ValueError,"missing or unexpected"):
            parse_foundry_lab(forged(extra=True),0)

    def test_failure_or_compiler_error_must_be_visible(self):
        with self.assertRaisesRegex(ValueError,"failed"):
            parse_foundry_lab(forged("Failure"),1)
        with self.assertRaisesRegex(ValueError,"failed"):
            parse_foundry_lab(forged(),1)
        with self.assertRaisesRegex(ValueError,"JSON"):
            parse_foundry_lab("solc failed",1)

    def test_duplicate_test_name_fails_closed(self):
        base=json.loads(forged())
        base["OTHER"]={"test_results":json.loads(forged())["D24J.t.sol:Suite"]["test_results"]}
        with self.assertRaisesRegex(ValueError,"duplicate"):
            parse_foundry_lab(json.dumps(base),0)

    def test_dependency_closure_never_leaves_pinned_contract_dir(self):
        deps=_relative_imports("contracts/UniswapV2Pair.sol",
                              b"import './libraries/Math.sol';")
        self.assertEqual(deps,["contracts/libraries/Math.sol"])
        for code in (b"import '../../secrets.sol';",
                     b"import 'https://host.tld/m.sol';"):
            with self.assertRaisesRegex(ValueError,"import"):
                _relative_imports("contracts/UniswapV2Pair.sol",code)


if __name__=="__main__":
    unittest.main()
