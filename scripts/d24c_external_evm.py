"""D2.4C immutable-source economic multi-transaction EVM evaluation.

Same compiled external contract, same non-secret candidate properties and
same fuzz-run budget for generated and independently authored Foundry tests.
This does NOT compare independent flaw-discovery recall.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import subprocess
from time import perf_counter

TARGET="299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4"
INVENTORY={
    "generated":{"testFuzz_PRISMNonrebasingIsolation(uint96)",
                 "testFuzz_PRISMSpenderDebit(uint96)"},
    "reference":{"testFuzz_ReferenceRebaseIsolation(uint96)",
                 "testFuzz_ReferenceSpenderDebit(uint96)"},
    "stateful":{"invariant_positiveSupply()",
                "testFuzz_CoverageSequence(uint96,uint96)"}
}
CONTRACTS={"generated":"D24CGeneratedEconomicTest",
           "reference":"D24CIndependentReferenceTest",
           "stateful":"D24CStatefulReferenceTest"}
PREDICATE_FAILURES=(
    "D24C_REBASE_LEAK_TO_NONREBASING","D24C_SUPPLY_DELTA_MISMATCH",
    "D24C_TOGGLE_LOSS","D24C_ALLOWANCE_NOT_DEBITED",
    "D24C_REBASING_YIELD_DRIFT","D24C_REF_YIELD_ACCOUNTING_DRIFT",
    "D24C_REF_NONREBASE_DRIFT","D24C_REF_SUPPLY_DRIFT",
    "D24C_REF_OPTIN_DRIFT","D24C_REF_ALLOWANCE_DRIFT",
    "D24C_STATEFUL_REBASE_YIELD","D24C_STATEFUL_ALLOWANCE",
    "D24C_STATEFUL_OWNER_DRIFT","D24C_STATEFUL_SUPPLY",
    "D24C_STATEFUL_ZERO_SUPPLY"
)

def execute(root:Path,out:Path,method:str,repeat:int, *,
            allow_unadjudicated_handler_reverts:bool=False)->dict:
    if method not in CONTRACTS or repeat not in (0,1):
        raise ValueError("unrecognized evaluation")
    out.mkdir(parents=True,exist_ok=True)
    env={**os.environ,"FOUNDRY_FUZZ_RUNS":"256",
         "FOUNDRY_FUZZ_SEED":"0x"+format(repeat+1,"064x"),
         "FOUNDRY_INVARIANT_RUNS":"128",
         "FOUNDRY_INVARIANT_DEPTH":"48",
         "FOUNDRY_INVARIANT_FAIL_ON_REVERT":"true"}
    command=["forge","test","--match-contract",CONTRACTS[method],"--json"]
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    t=perf_counter()
    p=subprocess.run(command,cwd=root,env=env,text=True,capture_output=True,timeout=300)
    wall=perf_counter()-t
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stem=f"{method}-repeat{repeat}"
    (out/(stem+".stdout.json")).write_text(p.stdout)
    (out/(stem+".stderr.txt")).write_text(p.stderr)
    try:
        parsed=json.loads(p.stdout)
    except (ValueError,TypeError) as exc:
        raise RuntimeError("no JSON EVM result, probable compile/tool error") from exc
    tests={}
    if not isinstance(parsed,dict):
        raise RuntimeError("Foundry output is not an object")
    for group in parsed.values():
        if not isinstance(group,dict):
            continue
        for name,result in group.get("test_results",{}).items():
            if name in tests:
                raise RuntimeError("duplicate Foundry test identity")
            tests[name]=result
    if set(tests)!=INVENTORY[method]:
        raise RuntimeError("wrong test inventory: "+str(sorted(tests)))
    states=[]
    for name,row in sorted(tests.items()):
        status=row.get("status")
        reason=str(row.get("reason") or "")
        if status not in ("Success","Failure"):
            raise RuntimeError(f"invalid EVM status: {status}")
        unclassified_handler_revert=(
            method=="stateful" and allow_unadjudicated_handler_reverts
            and name=="invariant_positiveSupply()"
            and "persisted failure revert" in reason
        )
        if status=="Failure" and not any(code in reason for code in PREDICATE_FAILURES) and not unclassified_handler_revert:
            raise RuntimeError("EVM error or setup failure, not an adjudicated flaw: "+reason[:300])
        interpretation=(
            "STATEFUL_HANDLER_REVERT_UNADJUDICATED" if unclassified_handler_revert else
            "NO_COUNTEREXAMPLE_IN_BOUNDED_RUN" if status=="Success" else
            "CANDIDATE_COUNTEREXAMPLE_REQUIRES_ADJUDICATION"
        )
        states.append({"test":name,"status":status,
                       "interpretation":interpretation,
                       "reason":reason[:500]})
    if (p.returncode!=0) != any(x["status"]=="Failure" for x in states):
        raise RuntimeError("Foundry exit/outcome mismatch")
    return {"method":method,"repeat":repeat,"budget":{"fuzz_runs_per_test":256,
            "seed":env["FOUNDRY_FUZZ_SEED"],
            "invariant_runs":128 if method=="stateful" else None,
            "invariant_depth":48 if method=="stateful" else None},
            "outcomes":states,"wall_seconds":wall,
            "child_cpu_seconds":(after.ru_stime+after.ru_utime)
                              -(before.ru_stime+before.ru_utime),
            "max_child_rss_kib":after.ru_maxrss,
            "forge_exit_code":p.returncode,
            "stdout_sha256":sha256(p.stdout.encode()).hexdigest()}

def run(root:Path,abi:Path,proposals:Path,out:Path)->dict:
    p=json.loads(proposals.read_text())
    if p.get("status")!="CANDIDATES_NOT_VERIFIED":
        raise ValueError("no unverified hypotheses")
    if p.get("abi_sha256")!=sha256(abi.read_bytes()).hexdigest():
        raise ValueError("ABI provenance mismatch")
    if {x["id"] for x in p["candidates"]}!={"NONREBASING_HOLDER_ISOLATION",
                                          "SPENDER_ALLOWANCE_DEBIT"}:
        raise ValueError("candidate list changed")
    out.mkdir(parents=True,exist_ok=True)
    report={"schema":"prism-d24c-external-economics-v1",
            "target_revision":TARGET,
            "external_source_unmodified":True,
            "blind_holdout":False,
            "historical_root_causes_evaluated":None,
            "precision":None,"recall":None,"superiority_claim":False,
            "evaluation":"bounded multi-transaction property conformance",
            "limitations":["Templates manually designed, no root-cause discovery",
                           "Public OUSD dataset, not blind holdout",
                           "Matched Foundry settings do not prove identical fuzz inputs",
                           "Elapsed time excludes upstream acquisition and manual design",
                           "This independent reference is not a symbolic or full stateful-fuzzer baseline"],
            "status":"NOT_COMPLETE","runs":[]}
    try:
        for method in ("generated","reference"):
            for repeat in (0,1):
                result=execute(root,out,method,repeat)
                report["runs"].append(result)
                print("D24C_EVM",method,repeat,
                      [(x["test"],x["status"]) for x in result["outcomes"]],
                      "wall",round(result["wall_seconds"],6))
        report["status"]="MULTISTEP_RUNS_COMPLETE_UNADJUDICATED"
    finally:
        (out/"d24c-real-evaluation.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for x in ("root","abi","proposals","output"):
        parser.add_argument("--"+x,required=True,type=Path)
    args=parser.parse_args()
    print("D24C_STATUS",run(args.root,args.abi,args.proposals,args.output)["status"])
