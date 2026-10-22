"""Assess D2.3 *applicability*, not discovered bugs, on pinned OUSD Solidity.

The external ABI is compiled from actual third-party source. Ground-truth
known-bug labels, benchmark properties and exploit traces are forbidden
inputs to this module. Missing semantic contract roles remain UNKNOWN.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from prism.defi_property_compiler import SPECIFICATIONS, signatures

TARGET_COMMIT = "299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4"
TARGET_REPO = "https://github.com/scfuzzbench/origin-dollar-scfuzzbench"
TARGET_CONTRACT = "contracts/contracts/token/OUSD.sol"


def inspect(root: Path, abi_json: bytes, source: bytes, *, observed_commit: str) -> dict:
    if observed_commit != TARGET_COMMIT:
        raise ValueError("external code revision differs from frozen target")
    data=json.loads(abi_json)
    asset_symbols=signatures(data)
    # This source is a token, NOT a lending market nor price oracle.
    # Reassigning it to other roles would create nonexistent observations.
    actual_roles={"asset":asset_symbols}
    decisions=[]
    for ident, spec in sorted(SPECIFICATIONS.items()):
        missing=[]
        for role,sig in spec["requires"]:
            if role not in actual_roles:
                missing.append(f"MISSING_ROLE:{role}")
            elif sig not in actual_roles[role]:
                missing.append(f"MISSING_FUNCTION:{role}.{sig}")
        decisions.append({
            "template":ident,
            "decision":"UNKNOWN_INAPPLICABLE" if missing else "CANDIDATE_REQUIRES_VERIFICATION",
            "missing_requirements": sorted(set(missing)),
        })
    return {
        "phase":"DeFi D2.4A",
        "status":"REAL_EXTERNAL_SOURCE_ABI_ANALYZED_NO_VULNERABILITIES_TESTED",
        "repo":TARGET_REPO,
        "commit":observed_commit,
        "contract":TARGET_CONTRACT,
        "source_sha256":sha256(source).hexdigest(),
        "abi_sha256":sha256(abi_json).hexdigest(),
        "public_function_count":len(asset_symbols),
        "visible_contract_role":"asset_only",
        "d23_template_decisions":decisions,
        "confirmed_prism_findings":None,
        "detection_executed":False,
        "comparative_fuzz_executed":False,
        "limits":[
            "Only direct OUSD ABI evaluated, not the complete protocol call graph",
            "Token ABI is not evidence of a lending contract or price oracle",
            "D2.3 templates are unrelated to OUSD rebasing and accounting known issues",
            "No known bug aliases or external ground-truth files supplied here",
            "Real vulnerabilities are not claimed found or absent",
            "Compilation and ABI inspection do not amount to a security audit",
        ],
    }


def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--root",type=Path,required=True)
    cli.add_argument("--abi",type=Path,required=True)
    cli.add_argument("--commit",required=True)
    cli.add_argument("--output",type=Path,required=True)
    args=cli.parse_args()
    root=args.root.resolve()
    if not (root/TARGET_CONTRACT).is_file():
        raise ValueError("pinned origin-dollar source not found")
    result=inspect(root,args.abi.read_bytes(),
                   (root/TARGET_CONTRACT).read_bytes(),
                   observed_commit=args.commit)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("D24_REAL_SOURCE_ABI",result["public_function_count"])
    print("D24_D23_PROPERTY_COMPATIBILITY",
          [(r["template"],r["decision"]) for r in result["d23_template_decisions"]])
    print("D24_CONFIRMATIONS",result["confirmed_prism_findings"])


if __name__=="__main__":
    main()
