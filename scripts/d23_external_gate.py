"""D2.3 independent, revision-locked real-target benchmark *readiness* audit.

This script NEVER runs the PRISM detector. It validates that genuine
root-cause labels exist at a pinned external commit, counts distinct issues
separately from synthetic health-check canaries, and provides a sealed target
manifest for a future blind evaluation.

A READINESS result must NEVER be interpreted as vulnerabilities detected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


AUTHORITATIVE_SUITE_SHA="de70065957a32fc5dd5fba3e53bb60f8564c722c"
PINNED_TARGET="origin-dollar"
PINNED_TARGET_COMMIT="299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4"
PINNED_SOURCE="contracts/contracts/token/OUSD.sol"


def _json(path: Path) -> dict:
    o=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(o,dict):
        raise ValueError("expected JSON object")
    return o


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(catalog: Path, known_bugs: Path, target_source: Path) -> dict:
    targets=_json(catalog)
    labels=_json(known_bugs)
    if targets.get("schema_version")!=1 or labels.get("schema_version")!=1:
        raise ValueError("unknown external benchmark format")
    ts=[x for x in targets.get("targets",[]) if x.get("id")==PINNED_TARGET]
    ks=[x for x in labels.get("targets",[]) if x.get("target_id")==PINNED_TARGET]
    if len(ts)!=1 or len(ks)!=1:
        raise ValueError("external target was not uniquely present")
    target,ground_truth=ts[0],ks[0]
    if target.get("commit")!=PINNED_TARGET_COMMIT or ground_truth.get("target_commit")!=PINNED_TARGET_COMMIT:
        raise ValueError("catalog/labels target source revision drift")
    if target.get("repo")!="https://github.com/scfuzzbench/origin-dollar-scfuzzbench":
        raise ValueError("external repository has unexpectedly changed")
    if not target_source.is_file():
        raise ValueError("real target Solidity file missing")
    real_source=target_source.read_text(encoding="utf-8")
    if "contract OUSD" not in real_source or "totalSupply" not in real_source:
        raise ValueError("unexpected real Solidity target source")
    bugs=ground_truth.get("known_bugs")
    canaries=ground_truth.get("canaries")
    if not isinstance(bugs,list) or not isinstance(canaries,list):
        raise ValueError("external bugs and health canaries unavailable")
    bug_ids=[x.get("id") for x in bugs]
    canary_ids=[x.get("id") for x in canaries]
    if not bugs or any(not isinstance(v,str) or not v for v in bug_ids):
        raise ValueError("no validated root-cause anchors for requested target")
    if len(set(bug_ids))!=len(bug_ids) or len(set(canary_ids))!=len(canary_ids):
        raise ValueError("duplicate ground-truth identifiers")
    if set(bug_ids)&set(canary_ids):
        raise ValueError("health-check canary mistaken for real vulnerability")
    if any(not item.get("evidence") or not item.get("aliases") for item in bugs):
        raise ValueError("unsubstantiated external known bug")
    report={
        "schema":"prism-d23-independent-benchmark-gate-v1",
        "external_suite_repository":"scfuzzbench/scfuzzbench",
        "external_suite_commit":AUTHORITATIVE_SUITE_SHA,
        "target_id":PINNED_TARGET,
        "target_repository":target["repo"],
        "target_commit":PINNED_TARGET_COMMIT,
        "target_source_path":PINNED_SOURCE,
        "target_source_sha256":_digest(target_source),
        "catalog_sha256":_digest(catalog),
        "ground_truth_catalog_sha256":_digest(known_bugs),
        "documented_root_causes":len(bug_ids),
        "health_canaries_excluded":len(canary_ids),
        "labels_available_only_to_evaluator":True,
        "engine_target_inputs_not_yet_prepared":True,
        "property_support":"UNSUPPORTED: current PRISM ABI library is for oracle/lending/repay; OUSD rebasing and supply-credit semantics require new templates and modeled state.",
        "detection_metric":"NOT_EVALUATED",
        "status":"READY_FOR_BENCHMARK_DESIGN_NOT_A_DETECTION_RESULT",
        "reason_for_no_scoring":[
            "No PRISM analysis or security proof executed on real target",
            "Real rebasing/supply semantics unsupported by D2.3 checker",
            "Known bug labels are publicly available, so this alone is not a blind holdout",
            "SCFuzzBench calls unannotated failures unmapped; they are not automatic zero-days",
            "Historical true positives must be separately reproduced in a local EVM",
        ],
    }
    return report


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--catalog",type=Path,required=True)
    parser.add_argument("--known-bugs",type=Path,required=True)
    parser.add_argument("--target-source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    a=parser.parse_args()
    r=validate(a.catalog,a.known_bugs,a.target_source)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("D23_EXTERNAL_TARGET",r["target_id"],r["target_commit"])
    print("D23_EXTERNAL_DOCUMENTED_ROOT_CAUSES",r["documented_root_causes"])
    print("D23_HEALTH_CANARIES_EXCLUDED",r["health_canaries_excluded"])
    print("D23_EXTERNAL_STATUS",r["status"])
    print("D23_DETECTION_METRIC",r["detection_metric"])

if __name__=="__main__":
    main()
