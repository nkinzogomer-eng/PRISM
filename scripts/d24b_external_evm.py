"""D2.4B exact external EVM property checks vs independently written stateful Foundry baseline.

The script has NO access to known_bugs, canaries, or issue aliases. Failed
properties remain UNADJUDICATED until independently reproduced and linked to a
distinct root cause. A failed Foundry command due to compilation is an ERROR,
never a bug. Raw stdout/stderr and child CPU/resource peaks are archived.
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


EXPECTED = {
    "source_generated": {
        "testFuzz_PRISMTransferSupply(uint96)",
        "testFuzz_PRISMApproveOverwrite(uint96)",
    },
    "native_stateful": {
        "invariant_SupplyUnchangedForTransferAndApproval()",
    },
}
CONFIGS = {
    "source_generated": ("D24BGeneratedAssetTest", 256, 1),
    "native_stateful": ("D24BStatefulReferenceTest", 128, 48),
}
ALLOWED_REASONS = {
    "D24B_TRANSFER_SUPPLY_DRIFT",
    "D24B_APPROVE_MISMATCH",
    "D24B_BASELINE_SUPPLY_DRIFT",
    "D24B_BASELINE_APPROVE_MISMATCH",
}


def single(root: Path, out: Path, *, experiment: str, repeat: int) -> dict:
    if experiment not in CONFIGS or repeat not in (0,1):
        raise ValueError("invalid experiment")
    contract, runs, depth=CONFIGS[experiment]
    env={**os.environ,
         "FOUNDRY_FUZZ_RUNS":str(runs),
         "FOUNDRY_INVARIANT_RUNS":str(runs),
         "FOUNDRY_INVARIANT_DEPTH":str(depth),
         "FOUNDRY_INVARIANT_FAIL_ON_REVERT":"false"}
    argv=["forge","test","--match-contract",contract,"--json"]
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    started=perf_counter()
    proc=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=240)
    wall=perf_counter()-started
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stem=f"{experiment}-repeat{repeat}"
    (out/(stem+".stdout.json")).write_text(proc.stdout)
    (out/(stem+".stderr.txt")).write_text(proc.stderr)
    try:
        raw=json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{stem} produced no parseable JSON (compile/tool failure)") from exc
    by_name={}
    for group in raw.values():
        if not isinstance(group,dict):
            continue
        for name,row in group.get("test_results",{}).items():
            if name in by_name:
                raise RuntimeError("duplicate test identity")
            by_name[name]=row
    if set(by_name)!=EXPECTED[experiment]:
        raise RuntimeError(f"{stem} incorrect native test inventory {sorted(by_name)}")
    outcomes=[]
    for name,row in sorted(by_name.items()):
        status=row.get("status")
        reason=str(row.get("reason") or "")
        if status not in ("Success","Failure"):
            raise RuntimeError(f"unreadable test status {name}: {status}")
        # Any failure must contain a known property predicate. Panics, setup
        # failures or arbitrary reverts cannot be called property findings.
        if status=="Failure" and not any(code in reason for code in ALLOWED_REASONS):
            raise RuntimeError(f"foundry failure unrelated to financial property: {name}: {reason[:150]}")
        outcomes.append({"test":name,"status":status,
                         "reason":reason[:600],
                         "interpretation":"PROPERTY_COUNTEREXAMPLE_UNADJUDICATED" if status=="Failure" else
                                          "NO_COUNTEREXAMPLE_IN_FIXED_BUDGET"})
    # Nonzero status is valid only if at least one explicit property failed.
    if proc.returncode!=0 and not any(x["status"]=="Failure" for x in outcomes):
        raise RuntimeError("unexpected nonzero forge status")
    if proc.returncode==0 and any(x["status"]=="Failure" for x in outcomes):
        raise RuntimeError("forge success status inconsistent with failed property")
    return {"experiment":experiment, "repeat":repeat, "exit_code":proc.returncode,
            "wall_seconds":wall,
            "child_cpu_seconds":(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
            "max_child_rss_kib":after.ru_maxrss,
            "raw_sha256":sha256(proc.stdout.encode()).hexdigest(),
            "budget":{"runs":runs,"depth":depth},
            "outcomes":outcomes}


def run(root:Path, abi_path:Path, properties:Path, out:Path)->dict:
    out.mkdir(parents=True,exist_ok=True)
    candidate=json.loads(properties.read_text())
    if candidate.get("status")!="CANDIDATES_GENERATED_NOT_VERIFIED":
        raise ValueError("missing candidate generation")
    if candidate.get("abi_sha256")!=sha256(abi_path.read_bytes()).hexdigest():
        raise ValueError("compiled ABI provenance mismatch")
    if set(x["id"] for x in candidate["candidates"])!={
        "TRANSFER_SUPPLY_PRESERVED","APPROVE_ALLOWANCE_OVERWRITE"}:
        raise ValueError("required external testable properties unsupported")
    attestation={
        "schema":"prism-d24b-real-evm-evaluation-v1",
        "status":"NOT_COMPLETE",
        "source_repository":"scfuzzbench/origin-dollar-scfuzzbench",
        "revision":"299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4",
        "abi_sha256":candidate["abi_sha256"],
        "known_bugs_accessed_by_detector":False,
        "real_external_source":True,
        "holdout_blind":False,
        "historical_root_cause_findings":None,
        "precision_or_recall":None,
        "runs":[],
        "limitations":[
            "Two conventional generic ERC20 properties only; source-independent ABI triggers",
            "No historical external ground-truth issues evaluated or confirmed",
            "Public benchmark upstream is not a blind holdout",
            "Stateful baseline explores sequences while generated unit fuzz probes execute shorter single sequences",
            "Different objectives and execution budgets forbid timing or discovery-superiority claims",
            "No systematic comparison against Echidna/Medusa/Halmos",
            "Potential transfer rounding/rebase semantics require manual adjudication of a property counterexample",
            "Resource figures do not include human authoring, git/submodule network access or cold installation",
        ],
    }
    try:
        for name in ("source_generated","native_stateful"):
            for repeat in (0,1):
                result=single(root,out,experiment=name,repeat=repeat)
                attestation["runs"].append(result)
                print("D24B_EXTERNAL_EVM",name,"repeat",repeat,
                      "wall_seconds",round(result["wall_seconds"],5),
                      "statuses",[(x["test"],x["status"]) for x in result["outcomes"]])
        attestation["status"]="REAL_EVM_PROPERTY_RUNS_COMPLETE_UNADJUDICATED"
    finally:
        (out/"real-evm-evaluation.json").write_text(
            json.dumps(attestation,indent=2,sort_keys=True)+"\n")
    return attestation


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--abi",type=Path,required=True)
    p.add_argument("--properties",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    run(a.root.resolve(),a.abi.resolve(),a.properties.resolve(),a.output.resolve())
