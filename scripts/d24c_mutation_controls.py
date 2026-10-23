"""D2.4C explicitly injected sandbox-only mutation controls.

A mutation is NEVER an actual issue discovered in upstream OUSD.  The script
restores byte-for-byte the original external Solidity source after each run.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from scripts.d24c_external_evm import run

PATH=Path("contracts/contracts/token/OUSD.sol")
MUTATIONS={
    "allowance-not-decremented":(
        "allowances[_from][msg.sender] = userAllowance - _value;",
        "allowances[_from][msg.sender] = userAllowance;",
        "SpenderDebit"
    ),
    "yield-denominator-omits-excluded-supply":(
        "uint256 rebasingSupply = totalSupply - nonRebasingSupply;",
        "uint256 rebasingSupply = totalSupply;",
        "Isolation"
    )
}

def check_mutant(root:Path,abi:Path,proposals:Path,out:Path,name:str)->dict:
    if name not in MUTATIONS:
        raise ValueError("not a preregistered mutation")
    source=root/PATH
    original=source.read_bytes()
    old,new,target=MUTATIONS[name]
    content=original.decode("utf-8")
    if content.count(old)!=1 or content.count(new):
        raise ValueError("external source revision differs from preregistered mutation")
    subprocess.run(["git","-C",str(root),"diff","--exit-code","--",str(PATH)],
                   capture_output=True,check=True)
    mutated=content.replace(old,new).encode("utf-8")
    out.mkdir(parents=True,exist_ok=True)
    report={"mutation":name,
            "upstream_security_discovery":False,
            "scientific_interpretation":"INSTRUMENTATION_SENSITIVITY_ONLY",
            "sha256_before":sha256(original).hexdigest(),
            "sha256_mutated":sha256(mutated).hexdigest(),
            "status":"ERROR",
            "observed":None}
    try:
        source.write_bytes(mutated)
        evidence=run(root,abi,proposals,out/name)
        status={}
        for row in evidence["runs"]:
            kind=row["method"]
            observed={x["test"]:x["status"] for x in row["outcomes"]}
            expected={t:("Failure" if target in t else "Success") for t in observed}
            if observed!=expected:
                raise RuntimeError(f"mutation {name} unexpected statuses: {observed} expected {expected}")
            status[f"{kind}:repeat{row['repeat']}"]=observed
        report["observed"]=status
        report["status"]="EXPECTED_SYNTHETIC_MUTATION_DETECTED_BY_BOTH"
    finally:
        source.write_bytes(original)
        if source.read_bytes()!=original:
            raise RuntimeError("external source restoration failed")
        subprocess.run(["git","-C",str(root),"diff","--exit-code","--",str(PATH)],
                       capture_output=True,check=True)
        (out/(name+"-attestation.json")).write_text(
            json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report

def test_controls(root:Path,abi:Path,proposals:Path,out:Path)->dict:
    records=[]
    for name in sorted(MUTATIONS):
        outcome=check_mutant(root,abi,proposals,out,name)
        print("D24C_MUTATION",name,outcome["status"])
        records.append(outcome)
    result={"schema":"prism-d24c-local-mutation-controls-v1",
            "target_is_originally_pinned":True,
            "real_world_vulnerabilities_discovered":0,
            "superiority_claim":False,
            "mutant_controls":records}
    (out/"synthetic-controls.json").write_text(
        json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for key in ("root","abi","proposals","output"):
        parser.add_argument("--"+key,required=True,type=Path)
    a=parser.parse_args()
    test_controls(a.root,a.abi,a.proposals,a.output)
