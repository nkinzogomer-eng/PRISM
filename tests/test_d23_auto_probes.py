"""D2.3 generator must not inspect vulnerability labels or model witness traces."""
import copy
import unittest

from prism.defi_property_compiler import freeze_input
from scripts.d23_generate_probes import generate, _validate_variations
from scripts.d23_probe_score import evaluate_forge, DEVELOPMENT_TRUTH


def _abi(*signature):
    entries=[]
    for sig in signature:
        name,args=sig.split("(")
        xs=args[:-1].split(",") if args[:-1] else []
        entries.append({"name":name,"type":"function","inputs":[{"type":x} for x in xs]})
    return entries


def sample_compiled():
    return freeze_input({
        "oracle":_abi("owner()","price()","update(uint256)"),
        "lender":_abi("borrow(uint256)","debt(address)","deposit(uint256)",
                      "limit(address)","locked(address)","withdraw(uint256)",
                      "loanAsset()","repay(uint256)"),
        "asset":_abi("balanceOf(address)")
    })


def configurations():
    return {"schema":"prism-d23-local-deployments-v1","variations":[
        {"id":"c0","oracle_owner_only":True,"withdraw_debt_check":True,
         "repay_transfers_asset":True},
        {"id":"c1","oracle_owner_only":False,"withdraw_debt_check":True,
         "repay_transfers_asset":True},
        {"id":"c2","oracle_owner_only":True,"withdraw_debt_check":False,
         "repay_transfers_asset":True},
        {"id":"c3","oracle_owner_only":True,"withdraw_debt_check":True,
         "repay_transfers_asset":False},
    ]}


class D23AutoProbes(unittest.TestCase):
    def test_fully_unlabelled_generate_twelve_tests(self):
        solidity=generate(sample_compiled(),configurations())
        self.assertEqual(solidity.count("function testD23_"),12)
        for ident in ("c0","c1","c2","c3"):
            for prop in ("ORACLE_AUTH","WITHDRAW_SOLVENCY","REPAY_CONSERVATION"):
                self.assertIn(f"function testD23_{ident}_{prop}()",solidity)
        self.assertNotIn("oracle_bug",solidity)
        self.assertNotIn("withdraw_bug",solidity)
        self.assertNotIn("repay_bug",solidity)

    def test_abi_candidate_selection_controls_probes(self):
        selected=copy.deepcopy(sample_compiled())
        selected["hypotheses"]=[x for x in selected["hypotheses"]
                                if x["identifier"]=="ORACLE_AUTH"]
        sol=generate(selected,configurations())
        self.assertEqual(sol.count("function testD23_"),4)

    def test_no_override_of_unknown_or_unsupported_property(self):
        selected=copy.deepcopy(sample_compiled())
        selected["hypotheses"][0]["identifier"]="UNSUPPORTED"
        with self.assertRaises(ValueError):
            generate(selected,configurations())

    def test_reject_duplicate_or_malformed_variations(self):
        b=configurations()
        b["variations"][1]["id"]="c0"
        with self.assertRaisesRegex(ValueError,"duplicated"):
            _validate_variations(b)
        b=configurations()
        b["variations"][0]["repay_transfers_asset"]="false"
        with self.assertRaisesRegex(ValueError,"booleans"):
            _validate_variations(b)

    def test_extra_labels_forbidden_as_input(self):
        b=configurations()
        b["variations"][2]["vulnerability_label"]="withdraw_bug"
        with self.assertRaisesRegex(ValueError,"fixture metadata"):
            _validate_variations(b)

    def test_strict_evm_result_inventory(self):
        ids=["ORACLE_AUTH","REPAY_CONSERVATION","WITHDRAW_SOLVENCY"]
        result={f"testD23_{c}_{p}()":
                {"status":"Failure" if DEVELOPMENT_TRUTH[c]==p else "Success",
                 "reason":("D23_"+p+"_WITNESS") if DEVELOPMENT_TRUTH[c]==p else None}
                for c in DEVELOPMENT_TRUTH for p in ids}
        # Concrete reason mapping uses D23_REPAY_CONSERVATION_WITNESS.
        scored=evaluate_forge({"suite":{"test_results":result}},ids)
        self.assertEqual(scored["metrics"]["tp"],3)
        self.assertEqual(scored["metrics"]["tn"],9)
        self.assertEqual(scored["metrics"]["fp"],0)

    def test_wrong_reason_is_not_valid_evidence(self):
        ids=["ORACLE_AUTH"]
        result={f"testD23_{c}_ORACLE_AUTH()":
                {"status":"Failure" if c=="c1" else "Success",
                 "reason":"out-of-gas" if c=="c1" else None}
                for c in DEVELOPMENT_TRUTH}
        with self.assertRaisesRegex(ValueError,"wrong reason"):
            evaluate_forge({"suite":{"test_results":result}},ids)

    def test_missing_test_cannot_be_marked_safe(self):
        ids=["ORACLE_AUTH"]
        d={f"testD23_{c}_ORACLE_AUTH()":{"status":"Success"}
           for c in DEVELOPMENT_TRUTH if c!="c0"}
        with self.assertRaisesRegex(ValueError,"missing/extra"):
            evaluate_forge({"suite":{"test_results":d}},ids)


if __name__=="__main__":
    unittest.main()
