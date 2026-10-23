"""Adversarial D2.4C gates; unit fixtures are NOT DeFi discoveries."""
import copy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.d24c_economic_properties import choose, solidity, compile_candidates
from scripts.d24c_external_evm import INVENTORY,execute,run

def abi():
    sigs={
        "totalSupply":[],
        "balanceOf":["address"],
        "transfer":["address","uint256"],
        "rebaseOptOut":[],
        "rebaseOptIn":[],
        "changeSupply":["uint256"],
        "vaultAddress":[],
        "nonRebasingSupply":[],
        "allowance":["address","address"],
        "approve":["address","uint256"],
        "transferFrom":["address","address","uint256"],
    }
    return [{"type":"function","name":name,
             "inputs":[{"name":f"a{i}","type":kind} for i,kind in enumerate(types)],
             "outputs":[]} for name,types in sigs.items()]

class D24CEconomicChecks(unittest.TestCase):
    def test_expected_two_source_only_candidates(self):
        p=choose(abi())
        self.assertEqual(len(p["candidates"]),2)
        self.assertIsNone(p["historical_root_causes"])
        self.assertFalse(p["source_code_semantics_inferred"])
    def test_missing_rebase_is_unknown(self):
        p=choose([x for x in abi() if x["name"]!="rebaseOptOut"])
        self.assertEqual(len(p["unknown"]),1)
        self.assertEqual(p["unknown"][0]["id"],"NONREBASING_HOLDER_ISOLATION")
    def test_missing_transferfrom_is_unknown(self):
        p=choose([x for x in abi() if x["name"]!="transferFrom"])
        self.assertEqual(len(p["unknown"]),1)
        self.assertEqual(p["unknown"][0]["id"],"SPENDER_ALLOWANCE_DEBIT")
    def test_bad_function_type_is_not_capability(self):
        functions=abi()
        for f in functions:
            if f["name"]=="changeSupply":f["inputs"][0]["type"]="bytes32"
        self.assertEqual(len(choose(functions)["unknown"]),1)
    def test_invalid_abi_is_rejected(self):
        for case in (None,{},[],[{"type":"function","name":"bad","inputs":[1]}]):
            with self.subTest(case=case), self.assertRaises(ValueError):
                choose(case)
    def test_duplicate_function_is_rejected(self):
        v=abi();v.append(copy.deepcopy(v[-1]))
        with self.assertRaises(ValueError): choose(v)
    def test_order_does_not_change_decisions(self):
        self.assertEqual(choose(abi()),choose(list(reversed(abi()))))
    def test_generated_solidity_has_economic_actions(self):
        s=solidity(choose(abi()))
        for snippet in ("economic.changeSupply","economic.rebaseOptOut",
                        "economic.rebaseOptIn","economic.transferFrom",
                        "D24C_ALLOWANCE_NOT_DEBITED","D24C_REBASING_YIELD_DRIFT",
                        "economic.nonRebasingSupply"):
            self.assertIn(snippet,s)
        self.assertNotIn("known_bugs",s)
    def test_only_unverified_hypotheses_accepted(self):
        p=choose(abi());p["candidates"][0]["status"]="SAFE"
        with self.assertRaises(ValueError): solidity(p)
    def test_candidate_tampering_is_rejected(self):
        p=choose(abi());p["candidates"][1]=p["candidates"][0]
        with self.assertRaises(ValueError): solidity(p)
    def test_schema_is_checked(self):
        p=choose(abi());p["schema"]="wrong"
        with self.assertRaises(ValueError): solidity(p)
    def test_label_path_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a=root/"judge-known-bugs.json"
            a.write_text(json.dumps(abi()))
            with self.assertRaises(ValueError): compile_candidates(a,root,root/"out")
    def test_missing_observation_adapter_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a=root/"abi.json";a.write_text(json.dumps(abi()))
            with self.assertRaises(FileNotFoundError): compile_candidates(a,root,root/"out")
    def test_compiler_archives_hash_and_unverified(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);a=root/"abi.json";a.write_text(json.dumps(abi()))
            p=root/"test"/"recon";p.mkdir(parents=True)
            (p/"D24BAdapter.sol").write_text("// fixture only")
            report=compile_candidates(a,root,root/"out")
            self.assertIsNone(report["verified_vulnerabilities"])
            self.assertEqual(report["abi_sha256"],sha256(a.read_bytes()).hexdigest())
            self.assertTrue((p/"D24CGeneratedEconomic.t.sol").exists())
    def test_expected_test_inventory_is_explicit(self):
        self.assertEqual({len(x) for x in INVENTORY.values()},{2})
    def test_invalid_runner_method_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                execute(Path(d),Path(d),"unrecognized",0)
    def test_invalid_repeat_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                execute(Path(d),Path(d),"generated",99)
    def test_forge_error_is_never_vulnerability(self):
        with tempfile.TemporaryDirectory() as d:
            fake=subprocess.CompletedProcess([],1,"not json","compile failed")
            with patch("scripts.d24c_external_evm.subprocess.run",return_value=fake):
                with self.assertRaisesRegex(RuntimeError,"no JSON"):
                    execute(Path(d),Path(d),"generated",0)
    def test_false_property_failure_reason_rejected(self):
        tests={s:{"status":"Failure","reason":"timeout/network error"} for s in INVENTORY["reference"]}
        fake=subprocess.CompletedProcess([],1,json.dumps({"contracts":{"test_results":tests}}),"")
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.d24c_external_evm.subprocess.run",return_value=fake):
                with self.assertRaisesRegex(RuntimeError,"not an adjudicated flaw"):
                    execute(Path(d),Path(d),"reference",0)

    def test_stateful_generic_revert_remains_unadjudicated_only_when_explicitly_allowed(self):
        tests={
            "invariant_positiveSupply()":{
                "status":"Failure",
                "reason":"invariant_positiveSupply persisted failure revert"},
            "testFuzz_CoverageSequence(uint96,uint96)":{
                "status":"Failure",
                "reason":"D24C_STATEFUL_ALLOWANCE"},
        }
        fake=subprocess.CompletedProcess([],1,json.dumps({"contracts":{"test_results":tests}}),"")
        with tempfile.TemporaryDirectory() as d:
            with patch("scripts.d24c_external_evm.subprocess.run",return_value=fake):
                with self.assertRaises(RuntimeError):
                    execute(Path(d),Path(d),"stateful",0)
                accepted=execute(Path(d),Path(d),"stateful",0,
                    allow_unadjudicated_handler_reverts=True)
        evidence={v["test"]:v["interpretation"] for v in accepted["outcomes"]}
        self.assertEqual(evidence["invariant_positiveSupply()"],
                         "STATEFUL_HANDLER_REVERT_UNADJUDICATED")

if __name__=="__main__":
    unittest.main()
