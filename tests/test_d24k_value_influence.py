"""Adversarial evidence controls for isolated *known* ERC4626 behavior."""
import json
import unittest

from scripts.d24k_value_influence import TESTS,check_native_trial


def result(*, failed=(), missing=(), extra=False):
    rows={name:{"status":"Failure" if name in failed else "Success"}
          for name in TESTS if name not in missing}
    if extra: rows["test_unregistered()"]={"status":"Success"}
    return json.dumps({"test/D24JValueInfluence.t.sol:Test":{"test_results":rows}})


class EconomicWitnessGuards(unittest.TestCase):
    def test_all_five_controls_must_pass(self):
        record=check_native_trial(result(),0)
        self.assertEqual(record["passed"],5)
        self.assertEqual(len(record["stdout_sha256"]),64)

    def test_missing_or_extra_control_cannot_be_a_witness(self):
        with self.assertRaisesRegex(ValueError,"incomplete"):
            check_native_trial(result(missing=(next(iter(TESTS)),)),0)
        with self.assertRaisesRegex(ValueError,"incomplete"):
            check_native_trial(result(extra=True),0)

    def test_failed_semantics_or_forge_process_cannot_pass(self):
        with self.assertRaisesRegex(ValueError,"failed"):
            check_native_trial(result(failed=TESTS),1)
        with self.assertRaisesRegex(ValueError,"failed"):
            check_native_trial(result(),1)
        with self.assertRaisesRegex(ValueError,"JSON"):
            check_native_trial("compile error",1)

    def test_duplicate_native_test_ids_rejected(self):
        parsed=json.loads(result())
        parsed["OTHER"]={"test_results":dict(parsed["test/D24JValueInfluence.t.sol:Test"]["test_results"])}
        with self.assertRaisesRegex(ValueError,"duplicated"):
            check_native_trial(json.dumps(parsed),0)


if __name__=="__main__":
    unittest.main()
