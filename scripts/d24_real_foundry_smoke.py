"""Run an externally authored Foundry invariant harness strictly as a SMOKE test.

An intentional SCFuzzBench canary is not a security vulnerability. This
pilot is NOT a matching-budget competitive fuzzer campaign: it only ensures
the pinned third-party harness can execute locally. Exit code 1 alone is not
a finding and results are not scored against known-bug labels.
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


def smoke(target_root:Path,out:Path,*,timeout:int=180)->dict:
    target_root=target_root.resolve()
    out.mkdir(parents=True,exist_ok=True)
    cmd=["forge","test","--match-contract","CryticToFoundry",
         "--match-test","invariant_noop","--json"]
    # Limited canary smoke ONLY, not an official SCFuzzBench campaign.
    env={**os.environ,"FOUNDRY_INVARIANT_RUNS":"20",
         "FOUNDRY_INVARIANT_DEPTH":"32",
         "FOUNDRY_INVARIANT_FAIL_ON_REVERT":"false"}
    started=perf_counter()
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        proc=subprocess.run(cmd,cwd=target_root,env=env,
                            capture_output=True,text=True,timeout=timeout)
    except subprocess.TimeoutExpired as err:
        summary={"status":"TIMEOUT", "timeout_seconds":timeout,
                 "benchmark_quality":"SMOKE_ONLY_NO_COMPARATIVE_CLAIM",
                 "confirmed_findings":None}
        (out/"origin-native-smoke.json").write_text(json.dumps(summary,indent=2)+"\n")
        raise RuntimeError("external Foundry invariant smoke timed out") from err
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    (out/"origin-native-stdout.json").write_text(proc.stdout)
    (out/"origin-native-stderr.txt").write_text(proc.stderr)
    try:
        raw=json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("external Foundry harness failed to produce JSON") from exc
    results=[]
    for group in raw.values():
        if not isinstance(group,dict): continue
        for name,item in group.get("test_results",{}).items():
            results.append({
                "test_name":name,
                "status":item.get("status"),
                "reason":str(item.get("reason") or "")[:1000],
            })
    summary={
        "phase":"D2.4A",
        "status":"EXTERNAL_EVM_HARNESS_EXECUTED" if results else "NO_TEST_EXECUTED",
        "benchmark_quality":"SMOKE_ONLY_NO_COMPARATIVE_CLAIM",
        "native_foundry_exit_code":proc.returncode,
        "native_results":results,
        "wall_seconds":perf_counter()-started,
        "child_cpu_seconds":(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
        "raw_output_sha256":sha256(proc.stdout.encode()).hexdigest(),
        "property_budget":{"invariant_runs":20,"depth":32,"single_run":True},
        "confirmed_findings":None,
        "limitations":[
            "Upstream harness contains deliberately failing canary properties",
            "Do not interpret a failing or passing invariant as a real bug automatically",
            "No duplicate root-cause matching or independent exploit verification",
            "Too few independent runs and not equivalent to published SCFuzzBench budgets",
            "Not a PRISM generated property or discovered vulnerability",
        ]
    }
    (out/"origin-native-smoke.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    print("D24_EXTERNAL_FOUNDRY_SMOKE",summary["status"],
          "EXIT",proc.returncode,"RESULTS",results)
    if not results:
        raise RuntimeError("external Foundry harness did not execute a test")
    return summary


def main()->None:
    a=argparse.ArgumentParser()
    a.add_argument("--root",type=Path,required=True)
    a.add_argument("--output",type=Path,required=True)
    args=a.parse_args()
    smoke(args.root,args.output)


if __name__=="__main__":
    main()
