"""D2.4I: pre-registered, strictly read-only, CPU-only source holdout.

Sources must already be downloaded as <id>.py from the pinned upstream
commits. This script neither fetches nor executes third-party program code.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter, process_time

try:
    import resource
except ImportError:  # Windows: no resource module; keep measurement UNKNOWN.
    resource = None

from prism.cyber_flow_model import model_source_flow
from prism.cyber_hypotheses import compile_python_hypotheses


def evaluate_holdout(manifest_file: Path, sources_root: Path, *,
                     max_candidates: int = 128, max_statements: int = 256,
                     max_paths: int = 16) -> dict:
    if not 1 <= max_candidates <= 512:
        raise ValueError("invalid candidate budget")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if manifest.get("schema") != "scm.prism.d24i.preregistered.source-holdout.v1":
        raise ValueError("unknown pre-registration schema")
    entries = manifest["entries"]
    ids = [e["id"] for e in entries]
    if len(ids) != len(set(ids)) or not ids or any(
        not x.isidentifier() or len(x) > 40 for x in ids
    ):
        raise ValueError("invalid source inventory")
    started = perf_counter()
    cpu_started = process_time()
    results = []
    for entry in entries:
        local = sources_root / (entry["id"] + ".py")
        data = local.read_bytes()
        if len(data) > 1_000_000:
            raise ValueError("a held-out source exceeds the bounded parser budget")
        text = data.decode("utf-8")
        file_started = perf_counter()
        file_cpu = process_time()
        hypotheses = compile_python_hypotheses(text)
        checks = []
        for h in hypotheses["candidates"][:max_candidates]:
            if h["family"] in ("secret_logging", "untrusted_execution"):
                verdict = model_source_flow(text, h, max_statements=max_statements,
                                            max_paths=max_paths)
                checks.append({
                    "id": h["identifier"],
                    "family": h["family"],
                    "status": verdict["status"],
                    "modeled_witnesses": verdict["modeled_witnesses"],
                    "reason": verdict.get("reason"),
                    "scope": "MODEL_ONLY_NOT_A_VULNERABILITY",
                })
            else:
                checks.append({"id":h["identifier"],"family":h["family"],
                               "status":"UNVERIFIED_NO_HOLDOUT_EXECUTOR",
                               "scope":"CANDIDATE_ONLY"})
        results.append({
            "id":entry["id"], "repository":entry["repository"],
            "commit":entry["commit"], "repository_path":entry["path"],
            "content_sha256":sha256(data).hexdigest(),
            "source_bytes":len(data),
            "candidate_count":len(hypotheses["candidates"]),
            "evaluated_candidates":len(checks),
            "candidate_overflow":max(0,len(hypotheses["candidates"])-len(checks)),
            "families":hypotheses["counts_by_family"],
            "checks":checks,
            "cpu_seconds":round(process_time()-file_cpu,6),
            "wall_seconds":round(perf_counter()-file_started,6),
        })
    return {
        "schema":"scm.prism.d24i.preregistered.holdout.results.v1",
        "manifest_sha256":sha256(manifest_file.read_bytes()).hexdigest(),
        "all_inputs_preselected":True,
        "sources_are_executed":False,
        "requires_gpu":False,
        "external_model_calls":0,
        "verified_novel_vulnerabilities":0,
        "known_ground_truth":False,
        "precision_recall_measured":False,
        "model_witnesses_are_real_vulnerabilities":False,
        "budgets":{"max_source_bytes":1000000,"max_candidates":max_candidates,
                   "max_statements_per_candidate":max_statements,
                   "max_paths_per_candidate":max_paths},
        "total_source_bytes":sum(x["source_bytes"] for x in results),
        "total_candidates":sum(x["candidate_count"] for x in results),
        "modeled_flow_witnesses":sum(len(c.get("modeled_witnesses",[]))
                                      for x in results for c in x["checks"]),
        "cpu_seconds":round(process_time()-cpu_started,6),
        "wall_seconds":round(perf_counter()-started,6),
        "max_process_rss_kib_linux":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                                     if resource is not None and sys.platform == "linux" else None,
        "results":results,
        "limitations":[
            "An upstream commit hash is provenance, not a ground-truth vulnerability label",
            "Four selected modules are a small convenience holdout, not a population sample",
            "Hypotheses and safe AST model checks are incomplete, and never evidence of zero-days",
            "No independent red-team exploit reproduction; no precision or recall claim",
            "CPU/memory are environment-specific absolute measurements, not comparative speedups",
        ],
    }


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--manifest",type=Path,required=True)
    parser.add_argument("--sources-root",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--max-candidates",type=int,default=128)
    args=parser.parse_args()
    report=evaluate_holdout(args.manifest,args.sources_root,
                            max_candidates=args.max_candidates)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("D24I_HOLDOUT",json.dumps({
        "files":len(report["results"]),"candidates":report["total_candidates"],
        "model_witnesses_not_vulnerabilities":report["modeled_flow_witnesses"],
        "novel_vulnerabilities":report["verified_novel_vulnerabilities"],
        "cpu_seconds":report["cpu_seconds"],"wall_seconds":report["wall_seconds"],
        "max_rss_kib":report["max_process_rss_kib_linux"],
    },sort_keys=True))
