"""Score automatically generated behavioral property probes against EVM labels.

The generator MUST run without ground-truth. This scorer is the ONLY step that
maps local opaque configuration ids to known injected-bug identities.

A changed ABI, missing test, wrong failure reason or unexpected false positive
is not silently converted into a true negative.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import subprocess
import time

from scripts.d23_generate_probes import PROPERTY_ORDER

# Truth used exclusively by the post-execution scorer, not the compiler.
DEVELOPMENT_TRUTH = {
    "c0": None, "c1": "ORACLE_AUTH",
    "c2": "WITHDRAW_SOLVENCY", "c3": "REPAY_CONSERVATION",
}
FAILURE_REASONS = {
    "ORACLE_AUTH": "D23_ORACLE_AUTH_WITNESS",
    "WITHDRAW_SOLVENCY": "D23_WITHDRAW_SOLVENCY_WITNESS",
    "REPAY_CONSERVATION": "D23_REPAY_CONSERVATION_WITNESS",
}


def _metrics(rows: list[dict]) -> dict:
    tp=sum(r["truth"] and r["found"] for r in rows)
    fp=sum(not r["truth"] and r["found"] for r in rows)
    fn=sum(r["truth"] and not r["found"] for r in rows)
    tn=sum(not r["truth"] and not r["found"] for r in rows)
    return {"tp":tp,"fp":fp,"fn":fn,"tn":tn,
            "precision":tp/(tp+fp) if tp+fp else None,
            "recall":tp/(tp+fn) if tp+fn else None}


def evaluate_forge(raw: dict, enabled: list[str]) -> dict:
    expected={f"testD23_{case}_{property_id}()"
              for case in DEVELOPMENT_TRUTH for property_id in enabled}
    native={}
    for group in raw.values():
        if not isinstance(group,dict):
            continue
        for name,item in group.get("test_results",{}).items():
            if name in native:
                raise ValueError(f"duplicate test output: {name}")
            native[name]=item
    if set(native)!=expected:
        raise ValueError(f"missing/extra probe tests, missing={expected-set(native)}, extra={set(native)-expected}")
    result=[]
    for case in DEVELOPMENT_TRUTH:
        for ident in sorted(enabled):
            name=f"testD23_{case}_{ident}()"
            value=native[name]
            status=value.get("status")
            if status not in ("Success","Failure"):
                raise ValueError("unknown EVM status")
            found=status=="Failure"
            reason=str(value.get("reason") or "")
            if found and FAILURE_REASONS[ident] not in reason:
                raise ValueError(f"failed for wrong reason: {name} reason={reason}")
            result.append({
                "case":case,"property":ident,"truth":DEVELOPMENT_TRUTH[case]==ident,
                "found":found,"reason":reason,"status":status,
            })
    return {"cases":result, "metrics":_metrics(result)}


def run(root: Path, out: Path, generated: Path) -> dict:
    if generated.get("status")!="GENERATED_NOT_EVM_VERIFIED":
        raise ValueError("probe generation missing")
    ids=generated.get("selected_properties")
    if (not isinstance(ids,list) or len(ids)!=len(set(ids))
        or any(x not in PROPERTY_ORDER for x in ids)
        or generated.get("variant_ids")!=list(DEVELOPMENT_TRUTH)):
        raise ValueError("changed or missing property/variant inventory")
    out.mkdir(parents=True,exist_ok=True)
    started=time.perf_counter()
    previous=resource.getrusage(resource.RUSAGE_CHILDREN)
    command=["forge","test","--match-contract","D23AutoPropertyTest","--json"]
    p=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=180)
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    elapsed=time.perf_counter()-started
    (out/"d23-generated-probes-forge.json").write_text(p.stdout,encoding="utf-8")
    (out/"d23-generated-probes-stderr.txt").write_text(p.stderr,encoding="utf-8")
    try:
        parsed=json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Foundry produced invalid JSON") from exc
    result=evaluate_forge(parsed,ids)
    meta={
        "status":"EVM_PROBES_EXECUTED",
        "process_exit":p.returncode,
        "forge_wall_seconds":elapsed,
        "forge_child_cpu_seconds":(after.ru_utime+after.ru_stime)-(previous.ru_utime+previous.ru_stime),
        "forge_max_rss_kib":after.ru_maxrss,
        "raw_sha256":sha256(p.stdout.encode()).hexdigest(),
        "compiled_property_ids":ids,
        "truth_used_only_after_exec":True,
        "finding_count":sum(x["found"] for x in result["cases"]),
        "observations":result["cases"],
        "metrics":result["metrics"],
        "limits":["Ordinary fixed domain-specific EVM probes, NOT stateful fuzz.",
                  "Local named configurations only; their boolean values expose defects.",
                  "12 known labelled development cells; no blind external vulnerabilities.",
                  "Manual ABI templates and test operations are not new security theory.",
                  "Raw EVM test time is not comparable to fully independent stateful search at equal coverage.",
                  "Installing tools and human property design excluded from process time."],
    }
    (out/"d23-generated-probes-score.json").write_text(
        json.dumps(meta,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("D23_BLACKBOX_EVM_METRICS",json.dumps(result["metrics"],sort_keys=True))
    print("D23_EVM_TIME",round(elapsed,4),"CPU",round(meta["forge_child_cpu_seconds"],4))
    if p.returncode==0 and any(x["found"] for x in result["cases"]):
        raise RuntimeError("Foundry exit code zero despite property violations")
    return meta


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--generation-ledger",type=Path,required=True)
    a=parser.parse_args()
    generated=json.loads(a.generation_ledger.read_text(encoding="utf-8"))
    run(a.root.resolve(),a.output.resolve(),generated)

if __name__=="__main__":
    main()
