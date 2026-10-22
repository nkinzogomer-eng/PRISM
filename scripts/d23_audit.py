"""Audit D2.3 source-ABI-derived hypotheses against independent EVM outcomes.

Selection is compiled BEFORE running vulnerability tests, and this evaluator
reads the ground truth ONLY AFTER both ABI compilation and the native runs.
The experiment measures coverage of candidate PROPERTY TEMPLATES, not the
ability to discover new vulnerabilities from ABI alone.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


PROPERTY_TO_MODEL = {
    "ORACLE_AUTH": "unauthorized_oracle_write",
    "WITHDRAW_SOLVENCY": "unsafe_collateral_withdrawal",
    "REPAY_CONSERVATION": "unfunded_debt_repayment",
}
PROPERTY_TO_NATIVE = {
    "ORACLE_AUTH": "invariant_OracleOwnerOnly()",
    "WITHDRAW_SOLVENCY": "invariant_CollateralSolvent()",
    "REPAY_CONSERVATION": "invariant_RepaymentFunded()",
}


def audit(compiled_file: Path, model_file: Path, eval_file: Path, output: Path) -> dict:
    compiled=json.loads(compiled_file.read_text(encoding="utf-8"))
    model=json.loads(model_file.read_text(encoding="utf-8"))
    evm=json.loads(eval_file.read_text(encoding="utf-8"))
    if compiled.get("schema")!="prism-d23-property-compiler-v1":
        raise ValueError("untrusted hypothesis schema")
    if model.get("phase")!="DeFi D2.2" or evm.get("phase")!="DeFi D2.2":
        raise ValueError("unmatched fixture experiment")
    if "PASS:" not in evm.get("status",""):
        raise ValueError("EVM confirmations are incomplete")
    compiled_ids={x["identifier"] for x in compiled.get("hypotheses",[])
                  if x.get("decision")=="CANDIDATE_REQUIRES_DYNAMIC_VERIFICATION"}
    if len(compiled_ids)!=len(compiled.get("hypotheses",[])):
        raise ValueError("unknown or duplicated candidate status")
    if not compiled_ids <= PROPERTY_TO_MODEL.keys():
        raise ValueError("unsupported generated property without verified runtime")
    if any(x.get("identifier") in compiled_ids for x in compiled.get("unknown", [])):
        raise ValueError("ambiguous property selection")
    matrix={(row["case"],row["property"]):row for row in evm["comparisons"]}
    if len(matrix)!=12 or len(evm["comparisons"])!=12:
        raise ValueError("missing or duplicated EVM controls")
    matched=[]
    for case in ("oracle_bug","withdraw_bug","repay_bug","safe"):
        for ident in sorted(compiled_ids):
            x=matrix.get((case,PROPERTY_TO_NATIVE[ident]))
            if x is None:
                raise ValueError("property not confirmed on all EVM variants")
            if bool(x["model_guided_found"]) != bool(x["model_bfs_found"]):
                raise ValueError("candidate model disagreement")
            if x["model_guided_found"] and not x["positive_truth"]:
                raise ValueError("unsupported model positive")
            matched.append({
                "case":case, "generic_property_id":ident,
                "positive_truth":bool(x["positive_truth"]),
                "model_found":bool(x["model_guided_found"]),
                "evm_stateful_found":bool(x["native_stateful_found"]),
            })
    # Do not smuggle the ground truth into the compile phase.
    record={
        "schema":"prism-d23-source-property-audit-v1",
        "selected_property_count":len(compiled_ids),
        "unknown_property_count":len(compiled.get("unknown",[])),
        "cells_evaluated":len(matched),
        "property_provenance": compiled.get("abi_bundle_sha256"),
        "model_ledger_sha256":sha256(model_file.read_bytes()).hexdigest(),
        "evm_ledger_sha256":sha256(eval_file.read_bytes()).hexdigest(),
        "observations":matched,
        "scientific_status":"BOUNDED_DEVELOPMENT_ONLY",
        "limitations":[
            "Template names and behavioral model were designed for these financial APIs",
            "ABI selection is not semantic inference, and cannot prove a security property",
            "EVM replay generator and native stateful invariants are pre-authored for these same properties",
            "This is an internal test split with known developer labels, NOT blinded benchmarks",
            "Native Foundry discovers all three injected bugs; no novel recall advantage",
        ],
    }
    for label, key in (("model","model_found"),("foundry","evm_stateful_found")):
        tp=sum(x["positive_truth"] and x[key] for x in matched)
        fp=sum(not x["positive_truth"] and x[key] for x in matched)
        fn=sum(x["positive_truth"] and not x[key] for x in matched)
        tn=sum(not x["positive_truth"] and not x[key] for x in matched)
        record[label]={"tp":tp,"fp":fp,"fn":fn,"tn":tn}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return record


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--properties",type=Path,required=True)
    parser.add_argument("--model",type=Path,required=True)
    parser.add_argument("--evm",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    a=parser.parse_args()
    record=audit(a.properties,a.model,a.evm,a.output)
    print("D23_COMPILER_SELECTED",record["selected_property_count"])
    print("D23_CELLS",record["cells_evaluated"])
    print("D23_MODEL",record["model"])
    print("D23_FOUNDRY",record["foundry"])
    print("D23_VERDICT",record["scientific_status"])

if __name__=="__main__":
    main()
