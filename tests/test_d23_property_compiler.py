"""Adversarial D2.3 ABI property compilation tests (no EVM fixture labels)."""
from __future__ import annotations

import copy
import unittest

from prism.defi_property_compiler import compile_properties, freeze_input, signatures, SPECIFICATIONS


def abi(*names: str) -> list[dict]:
    entries = []
    for name in names:
        fname, arguments = name.split("(")
        args=arguments[:-1].split(",") if arguments[:-1] else []
        entries.append({"type":"function","name":fname,
                        "inputs":[{"type":arg,"name":f"x{i}"} for i,arg in enumerate(args)],
                        "outputs":[],"stateMutability":"nonpayable"})
    return entries


def complete():
    return {
        "oracle": abi("owner()","price()","update(uint256)"),
        "lender": abi("borrow(uint256)","debt(address)","deposit(uint256)",
                      "limit(address)","locked(address)","withdraw(uint256)",
                      "loanAsset()","repay(uint256)"),
        "asset": abi("balanceOf(address)","transferFrom(address,address,uint256)")
    }


class D23CompilationTests(unittest.TestCase):
    def test_all_three_candidates_without_case_labels(self):
        record=compile_properties(complete())
        self.assertEqual([h["identifier"] for h in record["hypotheses"]],
                         ["ORACLE_AUTH","REPAY_CONSERVATION","WITHDRAW_SOLVENCY"])
        self.assertFalse(record["unknown"])
        for h in record["hypotheses"]:
            self.assertIn("CANDIDATE",h["decision"])
            self.assertTrue(h["observable_dependencies"])

    def test_relabeling_functions_unknown_not_safe(self):
        b=complete()
        b["oracle"][2]["name"]="modify"
        result=compile_properties(b)
        self.assertIn("ORACLE_AUTH", [x["identifier"] for x in result["unknown"]])
        self.assertNotIn("ORACLE_AUTH",[x["identifier"] for x in result["hypotheses"]])

    def test_overloads_require_exact_abi_types(self):
        b=complete()
        b["lender"][0]["inputs"]=[{"type":"bytes32","name":"hash"}]
        result=compile_properties(b)
        self.assertIn("WITHDRAW_SOLVENCY",[x["identifier"] for x in result["unknown"]])

    def test_missing_debt_disables_both_dependent_templates(self):
        b=complete()
        b["lender"]=[x for x in b["lender"] if x["name"] != "debt"]
        result=compile_properties(b)
        self.assertEqual([x["identifier"] for x in result["hypotheses"]], ["ORACLE_AUTH"])
        self.assertEqual(len(result["unknown"]),2)

    def test_missing_balance_observation_unknown_repayment_only(self):
        b=complete()
        b["asset"]=[x for x in b["asset"] if x["name"] != "balanceOf"]
        result=compile_properties(b)
        self.assertIn("REPAY_CONSERVATION",[x["identifier"] for x in result["unknown"]])
        self.assertEqual(len(result["hypotheses"]),2)

    def test_reordered_abi_and_extra_events_are_semantically_equivalent(self):
        b=complete()
        original=compile_properties(b)
        c=copy.deepcopy(b)
        for role in c:
            c[role].reverse()
            c[role].append({"type":"event","name":"Donation","inputs":[]})
        result=compile_properties(c)
        self.assertEqual(original,result)

    def test_reject_duplicate_signature_not_count_as_new_capability(self):
        b=complete()
        b["oracle"].append(dict(b["oracle"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            compile_properties(b)

    def test_malformed_input_or_missing_role_fails_closed(self):
        for bad in ({"oracle":[], "lender": [], "asset": []},
                    {"oracle":[], "lender":[]},
                    {"oracle":{}, "lender":[], "asset":[]},
                    {"oracle":[{"type":"function","name":"f","inputs":["x"]}],
                     "lender":[], "asset":[]}):
            with self.subTest(bad=bad):
                with self.assertRaises((ValueError,TypeError)):
                    compile_properties(bad)

    def test_no_vulnerability_safety_claims(self):
        record=freeze_input(complete())
        self.assertTrue(record["abi_bundle_sha256"])
        self.assertTrue(record["compiled_hypotheses_sha256"])
        self.assertNotIn("safe",str(record["hypotheses"]).lower())
        self.assertNotIn("vulnerable",str(record["hypotheses"]).lower())

    def test_property_templates_have_inspectable_dependencies(self):
        result=compile_properties(complete())
        for h in result["hypotheses"]:
            self.assertIn(h["identifier"],SPECIFICATIONS)
            self.assertTrue(h["independent_observation"])
            self.assertTrue(h["limitations"])
            self.assertTrue(all("." in x for x in h["observable_dependencies"]))

    def test_non_lender_interface_returns_unknown_not_negative_evidence(self):
        b=complete()
        b["lender"]=abi("deposit(uint256)")
        result=compile_properties(b)
        self.assertEqual(len(result["hypotheses"]),1)
        self.assertEqual(len(result["unknown"]),2)


if __name__=="__main__":
    unittest.main()
