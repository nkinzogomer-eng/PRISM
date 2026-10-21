#!/usr/bin/env python3
"""Label-blind Phase 4.4A candidate discovery, with a locked development corpus.

This program MUST NOT read expected-results or any ground-truth metadata.
A security claim remains UNVERIFIED until an independent replay proves it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
import time

if __package__ in ("", None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prism.goal_discovery import DiscoveryGoal, analyze
from scripts.measure_phase43b import source_inventory


def discover(source_dir: Path, output: Path, goal: DiscoveryGoal) -> dict:
    start = time.perf_counter()
    source_bytes = source_inventory(source_dir)
    entries = {}
    all_candidates = []
    error_count = 0
    for test_id, data in sorted(source_bytes.items()):
        begin = time.perf_counter()
        try:
            source = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            entries[test_id] = {
                "filename": test_id + ".py", "goal": goal.property_id,
                "candidate_count": 0, "unknown_count": 0, "verified_count": 0,
                "unresolved": ["invalid_encoding"], "findings": [],
                "explored_sinks": 0,
            }
        else:
            result = analyze(source, test_id + ".py", goal).as_record()
            entries[test_id] = result
        entries[test_id]["analysis_seconds"] = time.perf_counter() - begin
        if entries[test_id]["analysis_seconds"] > goal.max_seconds_per_case:
            entries[test_id]["unresolved"].append("deadline_exceeded")
        if entries[test_id]["unresolved"]:
            error_count += 1
        for finding in entries[test_id]["findings"]:
            all_candidates.append({"test_id": test_id, **finding})
    report = {
        "schema_version": 1,
        "phase": "4.4A",
        "scope": "CWE-22 candidate-generating AST flow; no verified vulnerabilities",
        "developer_dataset": "OWASP Python v0.1 pinned initial corpus; labels deliberately hidden",
        "source_commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
        "source_count": len(source_bytes),
        "source_bytes_sha256": (
            "fe0ec67dcc328feb33d592b790563add38c721af4b89abcf839e56bc9e3b9b9d"),
        "execution_environment": platform.platform(),
        "goal": {
            "property_id": goal.property_id,
            "target_recall": goal.target_recall,
            "max_false_positive_rate": goal.max_false_positive_rate,
            "max_seconds_per_case": goal.max_seconds_per_case,
            "require_independent_confirmation": goal.require_independent_confirmation,
        },
        "total_seconds": time.perf_counter() - start,
        "case_count": len(entries),
        "candidate_cases": sum(bool(e["candidate_count"]) for e in entries.values()),
        "unknown_cases": sum(bool(e["unknown_count"] or e["unresolved"])
                             for e in entries.values()),
        "verified_vulnerabilities": 0,
        "claim": "none; outputs are candidate hypotheses only",
        "cases": entries,
        "candidate_ledger": all_candidates,
        "limitations": [
            "No concrete replay against live application",
            "No use of ground truth in discovery; labels evaluated later",
            "Only bounded intraprocedural AST flow and some local functions",
            "Dynamic reflection/imports/aliases, closures, complex guards and "
            "framework lifecycle are not fully modeled",
            "Unobserved sinks can cause false negatives despite zero alerts",
            "Runtime and file memory metrics do not imply semantic correctness",
            "Benchmark includes contested labels; independent adjudication required",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-recall", type=float, default=0.80)
    parser.add_argument("--max-fpr", type=float, default=0.10)
    args = parser.parse_args()
    g = DiscoveryGoal(target_recall=args.target_recall,
                      max_false_positive_rate=args.max_fpr)
    report = discover(args.source_dir, args.output, g)
    print("discovered candidates", report["candidate_cases"],
          "unknown", report["unknown_cases"],
          "verified vulnerabilities", report["verified_vulnerabilities"],
          "total", round(report["total_seconds"], 3))
    if report["case_count"] != 1230:
        raise SystemExit("incomplete corpus")


if __name__ == "__main__":
    main()
