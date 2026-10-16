#!/usr/bin/env python3
"""Normalize CodeQL SARIF alerts to OWASP Benchmark case-level predictions.

This is a deliberately coarse compatibility metric for continuity with the
Bandit/Semgrep pilot. It does not establish that an alert matches the intended
CWE. Preserve SARIF and use finding/CWE adjudication for competitive claims.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

CASE_RE = re.compile(r"(BenchmarkTest\d{5})\.py$")


def load_labels(path: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if row[0].strip().lower() in {"test name", "test_id"}:
                continue
            if len(row) < 3 or row[2].strip().lower() not in {"true", "false"}:
                raise ValueError(f"invalid label row: {row!r}")
            case_id = row[0].strip()
            if case_id in labels:
                raise ValueError(f"duplicate label ID: {case_id}")
            labels[case_id] = row[1].strip()
    if len(labels) != 1230:
        raise ValueError(f"expected 1230 labels, found {len(labels)}")
    return labels


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", required=True, type=Path)
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()

    labels = load_labels(args.labels)
    sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
    flagged: set[str] = set()
    unmapped = 0
    alert_count = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            alert_count += 1
            locations = result.get("locations", [])
            mapped = False
            for location in locations:
                physical = location.get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri", "")
                normalized = uri.replace("\\", "/")
                match = CASE_RE.search(normalized)
                if match and match.group(1) in labels:
                    flagged.add(match.group(1))
                    mapped = True
            if not mapped:
                unmapped += 1

    args.predictions.parent.mkdir(parents=True, exist_ok=True)
    with args.predictions.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["test_id", "category", "detected", "status"])
        for case_id, category in sorted(labels.items()):
            writer.writerow([case_id, category, str(case_id in flagged).lower(), "ok"])

    summary = {
        "schema_version": 1,
        "alerts": alert_count,
        "unique_cases_flagged": len(flagged),
        "unmapped_alerts": unmapped,
        "cases": len(labels),
        "mapping": "any CodeQL SARIF alert in a BenchmarkTest module flags that case; coarse pilot metric only",
        "sarif": str(args.sarif),
        "predictions": str(args.predictions),
    }
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
