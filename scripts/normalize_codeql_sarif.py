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
try:
    from .phase4_evidence import case_from_uri
except ImportError:
    from phase4_evidence import case_from_uri

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
    parser.add_argument('--verified-full-scan', action='store_true',
                        help='Caller verified successful full, non-diff analysis; SARIF alone cannot prove coverage')
    args = parser.parse_args()

    labels = load_labels(args.labels)
    sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
    if not sarif.get('runs'):
        raise ValueError('SARIF has no runs; cannot score a successful analysis')
    extracted = set()
    for run in sarif['runs']:
        if 'results' not in run:
            raise ValueError('SARIF missing results')
        for invocation in run.get('invocations', []):
            if invocation.get('executionSuccessful') is False:
                raise ValueError('SARIF reports failed invocation')
            if any(n.get('level') == 'error' for n in invocation.get('toolExecutionNotifications', [])):
                raise ValueError('SARIF reports execution errors')
            for notification in invocation.get('toolExecutionNotifications', []):
                if notification.get('descriptor', {}).get('id') == 'py/diagnostics/successfully-extracted-files':
                    for loc in notification.get('locations', []):
                        uri = loc.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                        case = case_from_uri(uri)
                        if case in labels:
                            extracted.add(case)
    if args.verified_full_scan and extracted != set(labels):
        raise ValueError('full scan requires extraction diagnostics for every labeled module')
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
                case = case_from_uri(uri)
                if case in labels:
                    flagged.add(case)
                    mapped = True
            if not mapped:
                unmapped += 1

    args.predictions.parent.mkdir(parents=True, exist_ok=True)
    with args.predictions.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["test_id", "category", "detected", "status"])
        for case_id, category in sorted(labels.items()):
            known = case_id in flagged or args.verified_full_scan
            writer.writerow([case_id, category, str(case_id in flagged).lower() if known else '', 'ok' if known else 'unsupported'])

    summary = {
        "schema_version": 1,
        "full_scan_verified_by_caller": args.verified_full_scan,
        "extracted_labeled_modules": len(extracted),
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
