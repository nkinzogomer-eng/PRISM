"""D2.4 external ABI smoke: missing roles => UNKNOWN, never safe."""
import json
from pathlib import Path
import tempfile
import unittest
from scripts.d24_origin_surface import TARGET_COMMIT, TARGET_CONTRACT, inspect


def fakeabi(*sigs):
    out=[]
    for sig in sigs:
        name, rest=sig.split("(")
        types=rest[:-1].split(",") if rest[:-1] else []
        out.append({"type":"function","name":name,
                    "inputs":[{"type":t,"name":""} for t in types]})
    return json.dumps(out).encode()


class D24OriginSmokeTests(unittest.TestCase):
    def test_real_token_only_does_not_fake_lender_or_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            raw=fakeabi("totalSupply()", "balanceOf(address)", "transfer(address,uint256)")
            report=inspect(Path(d),raw,b"contract OUSD {}",observed_commit=TARGET_COMMIT)
            self.assertEqual(report["public_function_count"],3)
            self.assertEqual(len(report["d23_template_decisions"]),3)
            self.assertTrue(all(x["decision"]=="UNKNOWN_INAPPLICABLE"
                                for x in report["d23_template_decisions"]))
            self.assertFalse(report["detection_executed"])
            self.assertIsNone(report["confirmed_prism_findings"])

    def test_revision_change_forbidden(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,"revision"):
                inspect(Path(d),fakeabi("totalSupply()"),b"source",observed_commit="0"*40)

    def test_unparseable_abi_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                inspect(Path(d),b"{",b"source",observed_commit=TARGET_COMMIT)

    def test_non_abi_input_cannot_become_property_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                inspect(Path(d),json.dumps({"evil":True}).encode(),
                        b"source",observed_commit=TARGET_COMMIT)

    def test_even_matching_asset_observations_do_not_create_lending_role(self):
        with tempfile.TemporaryDirectory() as d:
            raw=fakeabi("balanceOf(address)", "loanAsset()", "repay(uint256)",
                        "debt(address)", "locked(address)", "limit(address)",
                        "deposit(uint256)", "withdraw(uint256)", "borrow(uint256)")
            report=inspect(Path(d),raw,b"source",observed_commit=TARGET_COMMIT)
            self.assertTrue(all(x["decision"]=="UNKNOWN_INAPPLICABLE"
                                for x in report["d23_template_decisions"]))
            self.assertTrue(any("MISSING_ROLE:lender" in x["missing_requirements"]
                                for x in report["d23_template_decisions"]))


if __name__=="__main__":
    unittest.main()
