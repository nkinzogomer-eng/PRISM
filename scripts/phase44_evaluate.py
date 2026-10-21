#!/usr/bin/env python3
"""Post-hoc development scoring; never used to guide Phase 4.4 discovery.

OWASP labels may be disputed, and candidate agreement is NOT a proof of a
vulnerability. The scientific target (verified 8/10) is NOT awarded from
labels or mere AST candidates.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

if __package__ in ("", None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.score_phase4 import read_labels, calculate


def evaluate(discovery: dict, label_file: Path) -> dict:
    if discovery.get("verified_vulnerabilities") != 0:
        raise ValueError("candidate-only discovery must never assert verification")
    if discovery.get("source_count") != 1230:
        raise ValueError("unexpected discovery corpus")
    labels = read_labels(label_file)
    if set(discovery.get("cases", {})) != set(labels):
        raise ValueError("incomplete discovery case IDs")
    if any(row.get("verified_count") != 0 for row in discovery["cases"].values()):
        raise ValueError("fabricated or unexpected verified findings")
    predictions = {}
    result = {}
    for name, (category, expected) in labels.items():
        entry = discovery["cases"][name]
        if entry.get("unresolved") or entry.get("unknown_count", 0):
            predictions[name] = ("skipped", None)
            status = "unknown"
        else:
            found = entry.get("candidate_count", 0) > 0
            predictions[name] = ("ok", found)
            status = "candidate" if found else "no_candidate"
        result[name] = {
            "category": category,
            "status": status,
            "label": expected,
            "candidate_count": entry.get("candidate_count", 0),
            "unknown_count": entry.get("unknown_count", 0),
            "verified_vulnerability": False,
        }
    scores = calculate(labels, predictions)
    metric = scores["results"].get("pathtraver")
    if metric is None:
        raise ValueError("path traversal category missing")
    first_ten = {f"BenchmarkTest{i:05d}": result[f"BenchmarkTest{i:05d}"]
                 for i in range(1, 11)}
    return {
        "schema_version": 1,
        "phase": "4.4A goal-oriented candidate evaluation",
        "developer_dataset": "OWASP Python v0.1 (not independent holdout)",
        "scope": "CWE-22; pathtraver expected-results category",
        "pathtraver": metric,
        "first_ten_case_audit": first_ten,
        "candidates_all_categories": discovery["candidate_cases"],
        "unknown_all_categories": discovery["unknown_cases"],
        "verified_vulnerabilities": 0,
        "goal_of_8_verified_of_10": "NOT MET: no independent replay evidence",
        "quality_warning": [
            "Precision/recall compare against benchmark labels, NOT independently adjudicated flaws",
            "OWASP Python v0.1 has contested case labels, including a published challenge",
            "Files lacking evidence of a candidate are not certified safe",
            "Unknowns and unmodeled flows are not counted as negative predictions",
            "Positive raw scanner/AST outputs are hypotheses, not confirmed vulnerabilities",
            "The 1..10 audit is in-sample and was partially manually inspected",
            "Benchmark corpus and methods have been examined; NOT untouched holdout",
        ],
        "raw_score": scores,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.discovery.read_text(encoding="utf-8"))
    report = evaluate(data, args.labels)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    m = report["pathtraver"]
    print("CWE-22 benchmark labels (development only):")
    print("cases", m["cases"], "evaluated", m["evaluated"],
          "unknown", m["unknown_positive"] + m["unknown_negative"])
    print("TP", m["tp"], "FP", m["fp"], "TN", m["tn"], "FN", m["fn"])
    print("precision", m["precision"], "recall", m["recall"],
          "coverage", m["coverage"])
    print("NO confirmed vulnerabilities: candidate-only, no independent replay")
    print("1-10 audit", json.dumps(report["first_ten_case_audit"], sort_keys=True))


if __name__ == "__main__":
    main()
