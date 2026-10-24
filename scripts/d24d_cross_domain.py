"""Reproducible cross-domain engineering benchmarks, never real-world recall."""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from statistics import median

from prism.cyber_kernel import audit_effects, search, verify_trace
from prism.cyber_workloads import cases

MODES = ("full", "slice", "quotient")


def run(*, seeds: int = 8, depth: int = 5, budget: int = 20000) -> dict:
    if not 1 <= seeds <= 100:
        raise ValueError("seed-count outside protocol")
    rows = []
    for seed in range(seeds):
        for domain in cases((seed,)):
            integrity = audit_effects(domain, depth=3)
            results = {mode: search(domain, mode=mode, depth=depth,
                                    max_expanded=budget) for mode in MODES}
            original = results["full"]
            for mode, observed in results.items():
                if original.verdict == "UNKNOWN_BUDGET" or observed.verdict == "UNKNOWN_BUDGET":
                    raise RuntimeError("budget exhaustion: no scientific comparison")
                if observed.found != original.found:
                    raise AssertionError(f"lost/fabricated finite model reachability: {domain.name}:{domain.scenario}:{mode}")
                if observed.found and not verify_trace(domain, observed.plan):
                    raise AssertionError("nonreproducible trace")
                if not observed.found and observed.verdict != "NOT_FOUND_IN_FINITE_MODEL":
                    raise AssertionError("unexpected false-safe verdict")
            rows.append({
                "family": domain.name, "scenario": domain.scenario,
                "seed": seed, "positive_in_finite_model": original.found,
                "effect_audit": integrity,
                "results": {k: asdict(v) for k, v in results.items()},
            })
    by_family = defaultdict(list)
    for record in rows:
        by_family[record["family"]].append(record)
    summary = {}
    for family, group in sorted(by_family.items()):
        summary[family] = {
            "cases": len(group),
            "found_positive": sum(x["positive_in_finite_model"] for x in group),
            "negative_exhaustive": sum(not x["positive_in_finite_model"] for x in group),
            "median_attempted": {m: median(r["results"][m]["attempted"] for r in group) for m in MODES},
            "median_expanded": {m: median(r["results"][m]["expanded"] for r in group) for m in MODES},
            "median_seconds": {m: median(r["results"][m]["elapsed_seconds"] for r in group) for m in MODES},
            "verdict_agreement": True,
        }
    doc = {"schema": "prism-d24d-model-reachability-v1",
           "status": "COMPLETED_MODEL_ONLY",
           "target_count": len(rows), "seed_count": seeds,
           "budget": {"max_depth": depth, "max_expanded": budget},
           "algorithms": {
               "full": "conventional full BFS",
               "slice": "conventional backward static dependency slice + BFS",
               "quotient": "conventional slice + projection-state quotient BFS (SCM pilot)",
           },
           "supported_families": sorted(by_family),
           "superiority_claim": None,
           "historical_real_vulnerabilities_evaluated": None,
           "model_finite_reachability_not_real_cyber_security": True,
           "limitations": [
               "Two web threat families are researcher-authored finite-state fixtures",
               "DeFi D2.2 is a preexisting hand-authored finite-state model, not live OUSD",
               "All goals and action read/write signatures are researcher supplied",
               "Dynamic write audit does not prove reads or external effects are complete",
               "Search reduction combines conventional known algorithms",
               "No EVM/real-web-app exploit confirmation on these adapter runs",
               "Same action order per case; elapsed microtiming excludes authoring effort",
               "No independent security root-cause holdout",
           ], "by_family": summary, "runs": rows}
    evidence = [(r["family"], r["scenario"], r["seed"],
                 [(m, r["results"][m]["verdict"], r["results"][m]["expanded"],
                   r["results"][m]["attempted"]) for m in MODES]) for r in rows]
    doc["deterministic_evidence_sha256"] = sha256(
        json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    return doc


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--seeds", type=int, default=8)
    p.add_argument("--depth", type=int, default=5)
    p.add_argument("--budget", type=int, default=20000)
    x = p.parse_args()
    record = run(seeds=x.seeds, depth=x.depth, budget=x.budget)
    x.output.parent.mkdir(parents=True, exist_ok=True)
    x.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("D24D_MODEL_CASES", record["target_count"])
    for family, stats in record["by_family"].items():
        print("D24D_DOMAIN", family, json.dumps(stats, sort_keys=True))
    print("D24D_SHA256", record["deterministic_evidence_sha256"])


if __name__ == "__main__":
    main()
