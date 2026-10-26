"""Matched synthetic-file reference comparison against pinned Slither 0.11.6.

Slither detections are tool findings, not independently verified exploits.
Unlike the PRISM typed generator, Slither performs its own compilation;
record that runtime distinction and do not claim an overall cost advantage.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from time import perf_counter


def classify_slither_json(root: object) -> dict:
    if type(root) is not dict or root.get("success") is not True:
        raise ValueError("Slither did not return a successful JSON analysis")
    detectors = root.get("results", {}).get("detectors")
    if type(detectors) is not list:
        raise ValueError("missing Slither detector results")
    checked=[]
    for detector in detectors:
        if detector.get("check")!="reentrancy-eth":
            raise ValueError("unexpected detector family in controlled baseline")
        text=detector.get("description", "")
        if type(text) is not str:
            raise ValueError("invalid Slither finding text")
        checked.append({"id":detector.get("id",""),
                        "unsafe_withdraw_named":"D24LUnsafeBank.withdraw(" in text,
                        "guarded_withdraw_named":"D24LGuardedBank.withdraw(" in text})
    return {"detector_total":len(checked),
            "unsafe_withdraw_detections":sum(x["unsafe_withdraw_named"] for x in checked),
            "fixed_withdraw_detections":sum(x["guarded_withdraw_named"] for x in checked),
            "unattributed_detections":sum(not (x["unsafe_withdraw_named"] or x["guarded_withdraw_named"])
                                         for x in checked)}


def run_baseline(source: Path, output: Path, compiler: Path) -> dict:
    if not source.is_file() or source.name!="D24LBankValue.t.sol":
        raise ValueError("only the exact labelled synthetic benchmark is authorized")
    if not compiler.is_file() or not compiler.name.startswith("solc-0.8.24"):
        raise ValueError("expected pinned solc 0.8.24 not installed")
    output.mkdir(parents=True,exist_ok=True)
    args=["slither",str(source.resolve()),"--detect","reentrancy-eth",
          "--solc",str(compiler),"--json",str((output/"slither-results.json").resolve())]
    started=perf_counter()
    proc=subprocess.run(args,capture_output=True,text=True,check=False,timeout=180)
    seconds=perf_counter()-started
    (output/"slither.stdout.txt").write_text(proc.stdout[-40_000:])
    (output/"slither.stderr.txt").write_text(proc.stderr[-40_000:])
    path=output/"slither-results.json"
    if not path.is_file():
        raise ValueError("baseline failed to output Slither JSON; must report UNAVAILABLE")
    parsed=classify_slither_json(json.loads(path.read_text()))
    data={"schema":"scm.prism.d24l.matched-known-synthetic-baseline.v1",
          "tool":"slither-analyzer", "requested_version":"0.11.6",
          "detector":"reentrancy-eth", "compiler":"0.8.24",
          "same_synthetic_source_sha256":sha256(source.read_bytes()).hexdigest(),
          "exit_code":proc.returncode,"measured_wall_seconds":seconds,
          "new_vulnerabilities_claimed":0,"zero_days_claimed":0,
          "run_finished_with_parseable_output":True,
          "cost_comparison_limitation":"Slither independently recompiles; PRISM AST stage used prior Foundry build",
          **parsed}
    (output/"baseline-evidence.json").write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    return data


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",type=Path,required=True)
    ap.add_argument("--compiler",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    answer=run_baseline(a.source,a.out,a.compiler)
    print("D24L_SLITHER_BASELINE",json.dumps({
        "findings":answer["detector_total"],
        "unsafe":answer["unsafe_withdraw_detections"],
        "guarded":answer["fixed_withdraw_detections"],
        "wall_seconds":round(answer["measured_wall_seconds"],4)},sort_keys=True))
