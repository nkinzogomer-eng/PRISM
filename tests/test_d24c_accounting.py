"""Local fail-closed testing for D2.4C; not a substitute for real EVM tests."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

from scripts.d24c_accounting_properties import (
    adapter_solidity, build, generated_solidity, select,
)
from scripts.d24c_real_evm import INVENTORY


def abi():
    fns = {
        "balanceOf": ["address"],
        "totalSupply": [],
        "allowance": ["address", "address"],
        "approve": ["address", "uint256"],
        "transfer": ["address", "uint256"],
        "transferFrom": ["address", "address", "uint256"],
    }
    return [{"type": "function", "name": name,
             "inputs": [{"type": typ, "name": f"p{i}"}
                        for i, typ in enumerate(types)]}
            for name, types in fns.items()]


class AccountingProperties(unittest.TestCase):
    def test_two_multistep_candidates_not_findings(self):
        x = select(abi())
        self.assertEqual(len(x["candidates"]), 2)
        self.assertIsNone(x["verified_vulnerabilities"])
        self.assertFalse(x["blind_holdout"])
        self.assertTrue(all(c["decision"] == "CANDIDATE_UNVERIFIED"
                            for c in x["candidates"]))

    def test_missing_transfer_from_marks_only_spend_unknown(self):
        x = select([f for f in abi() if f["name"] != "transferFrom"])
        self.assertEqual([y["id"] for y in x["unknown"]],
                         ["ALLOWANCE_SPEND_CONSERVATION"])
        self.assertEqual(len(x["candidates"]), 1)

    def test_incompatible_transfer_from_marks_unknown(self):
        a = abi()
        next(f for f in a if f["name"] == "transferFrom")["inputs"][2]["type"] = "bytes32"
        self.assertEqual(len(select(a)["unknown"]), 1)

    def test_no_forged_safe_or_duplicate_candidate(self):
        p = select(abi())
        p["candidates"][0]["decision"] = "SAFE"
        with self.assertRaisesRegex(ValueError, "adjudicated"):
            generated_solidity(p)
        p = select(abi())
        p["candidates"].append(p["candidates"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            generated_solidity(p)

    def test_generated_multistep_checks_are_not_vacuous(self):
        sol = generated_solidity(select(abi()))
        self.assertEqual(sol.count("function testFuzz_SCM"), 2)
        self.assertEqual(sol.count("token.transferFrom("), 2)
        self.assertIn("D24C_FIRST_DEBIT", sol)
        self.assertIn("D24C_SECOND_DEBIT", sol)
        self.assertIn("D24C_RETURN_SUPPLY", sol)
        self.assertIn("D24C_BAD_SETUP", sol)
        self.assertNotIn("known_bugs", sol)

    def test_external_source_observed_through_adapter(self):
        self.assertIn("is CryticTester", adapter_solidity())
        self.assertIn("address(ousd)", adapter_solidity())

    def test_requires_external_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            abipath = root / "abi.json"
            abipath.write_text(json.dumps(abi()))
            with self.assertRaises(FileNotFoundError):
                build(abipath, root, root / "output")

    def test_checksums_are_source_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            harness = root / "test" / "recon" / "CryticTester.sol"
            harness.parent.mkdir(parents=True)
            harness.write_text("contract CryticTester {}")
            abipath = root / "abi.json"
            abipath.write_text(json.dumps(abi()))
            record = build(abipath, root, root / "out")
            self.assertEqual(record["abi_sha256"], sha256(abipath.read_bytes()).hexdigest())
            self.assertEqual(record["status"], "UNVERIFIED_CANDIDATES")

    def test_contamination_path_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "judge-known-bugs.json"
            path.write_text(json.dumps(abi()))
            with self.assertRaises(ValueError):
                build(path, root, root / "out")

    def test_mutation_witness_unique_and_non_vacuous(self):
        from scripts.d24c_mutation_controls import mutate, NEEDLE, MUTANT
        self.assertIn(MUTANT, mutate("begin " + NEEDLE + " end"))
        self.assertNotIn(NEEDLE, mutate("begin " + NEEDLE + " end"))
        with self.assertRaises(ValueError):
            mutate("no transferFrom allowance debit")
        with self.assertRaises(ValueError):
            mutate(NEEDLE + " " + NEEDLE)
        with self.assertRaises(ValueError):
            mutate(NEEDLE + " " + MUTANT)

    def test_expected_inventory_and_budget_contract(self):
        self.assertEqual({k: len(v) for k, v in INVENTORY.items()},
                         {"generated": 2, "matched_reference": 2,
                          "stateful_reference": 1})


if __name__ == "__main__":
    unittest.main()
