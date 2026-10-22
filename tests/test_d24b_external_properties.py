"""D2.4B fail-closed tests: ABI-gated properties and EVM outcome integrity.

Synthetic ABI is used ONLY to test validation. The actual experiment fetches
and compiles external OUSD source in GitHub Actions.
"""
import copy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from scripts.d24b_erc20_properties import select, generated_solidity, adapter_solidity, build
from scripts.d24b_external_evm import EXPECTED


def abis():
    specs={
        "totalSupply()":[],
        "balanceOf(address)":["address"],
        "transfer(address,uint256)":["address","uint256"],
        "approve(address,uint256)":["address","uint256"],
        "allowance(address,address)":["address","address"],
    }
    return [{"type":"function","name":name.split("(")[0],
             "inputs":[{"type":a,"name":f"x{i}"} for i,a in enumerate(kinds)],
             "outputs":[]} for name,kinds in specs.items()]


class D24BExternalPropertyTests(unittest.TestCase):
    def test_two_generic_properties_with_no_issue_labels(self):
        r=select(abis())
        self.assertEqual([x["id"] for x in r["candidates"]],
                         ["APPROVE_ALLOWANCE_OVERWRITE","TRANSFER_SUPPLY_PRESERVED"])
        self.assertFalse(r["unknown"])
        self.assertNotIn("known_bugs", json.dumps(r))
        self.assertNotIn("exploit_trace",json.dumps(r))

    def test_explicit_unknown_when_transfer_missing(self):
        names=[x for x in abis() if x["name"]!="transfer"]
        r=select(names)
        self.assertEqual(len(r["candidates"]),1)
        self.assertEqual(r["unknown"][0]["id"],"TRANSFER_SUPPLY_PRESERVED")

    def test_missing_allowance_keeps_only_transfer(self):
        names=[x for x in abis() if x["name"]!="allowance"]
        r=select(names)
        self.assertEqual(len(r["candidates"]),1)
        self.assertEqual(r["unknown"][0]["id"],"APPROVE_ALLOWANCE_OVERWRITE")

    def test_wrong_type_not_counted_as_valid_capability(self):
        x=abis()
        for item in x:
            if item["name"]=="transfer":
                item["inputs"][1]["type"]="bytes32"
        r=select(x)
        self.assertTrue(any(x["id"]=="TRANSFER_SUPPLY_PRESERVED" for x in r["unknown"]))

    def test_duplicate_abi_function_rejected(self):
        x=abis()
        x.append(copy.deepcopy(x[0]))
        with self.assertRaisesRegex(ValueError,"duplicate"):
            select(x)

    def test_bad_abi_rejected(self):
        for bad in (None,{},[],[{"type":"function","name":"f","inputs":[1]}]):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                select(bad)

    def test_function_order_has_no_effect_on_property_decision(self):
        x=abis()
        y=list(reversed(copy.deepcopy(x)))
        self.assertEqual(select(x),select(y))

    def test_generation_requires_explicit_unverified_properties(self):
        x=select(abis())
        x["candidates"][0]["decision"]="SAFE"
        with self.assertRaisesRegex(ValueError,"claimed verified"):
            generated_solidity(x)

    def test_duplicate_generated_property_rejected(self):
        x=select(abis())
        x["candidates"].append(copy.deepcopy(x["candidates"][0]))
        with self.assertRaisesRegex(ValueError,"repeated"):
            generated_solidity(x)

    def test_generated_solidity_scopes_supply_without_rebase(self):
        result=generated_solidity(select(abis()))
        self.assertIn("asset.totalSupply() == beforeSupply",result)
        self.assertIn("asset.allowance(address(0x30000), address(0x40000))",result)
        self.assertEqual(result.count("function testFuzz_PRISM"),2)
        self.assertNotIn("known_bugs",result)
        self.assertNotIn("canary",result)

    def test_derived_adapter_observes_real_underlying_token(self):
        s=adapter_solidity()
        self.assertIn("is CryticTester",s)
        self.assertIn("return address(ousd)",s)

    def test_builder_requires_actual_pinned_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            abi=root/"abi.json"
            abi.write_text(json.dumps(abis()))
            with self.assertRaisesRegex(FileNotFoundError,"pinned upstream CryticTester"):
                build(abi,root/"out",external_root=root)

    def test_builder_writes_hashes_and_marks_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            src=root/"test"/"recon"
            src.mkdir(parents=True)
            (src/"CryticTester.sol").write_text("contract CryticTester {}")
            abi=root/"abi.json"
            abi.write_text(json.dumps(abis()))
            report=build(abi,root/"out",external_root=root)
            self.assertEqual(report["candidate_count"],2)
            self.assertEqual(report["status"],"CANDIDATES_GENERATED_NOT_VERIFIED")
            self.assertIsNone(report["verified_vulnerabilities"])
            self.assertEqual(report["abi_sha256"],sha256(abi.read_bytes()).hexdigest())
            self.assertTrue((src/"D24BGeneratedAsset.t.sol").is_file())

    def test_judge_filename_rejected_by_builder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            abi=root/"judge-only-known-bugs.json"
            abi.write_text(json.dumps(abis()))
            with self.assertRaisesRegex(ValueError,"judge/label paths"):
                build(abi,root/"out",external_root=root)

    def test_expected_native_test_inventory_is_explicit(self):
        self.assertEqual(len(EXPECTED["source_generated"]),2)
        self.assertEqual(len(EXPECTED["native_stateful"]),1)


if __name__ == "__main__":
    unittest.main()
