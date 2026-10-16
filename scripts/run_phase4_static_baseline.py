#!/usr/bin/env python3
"""Run pinned static analyzers against OWASP Benchmark Python test-case modules.

The controller never receives labels. This runner maps findings to source test IDs
from paths only, preserves raw tool JSON, and emits one normalized CSV per tool.
It is a baseline runner, not a PRISM adapter.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path


TEST_ID_RE = re.compile(r"(BenchmarkTest\d{5})\.py$")


def load_labels(path: Path) -> dict[str, str]:
    labels = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if row[0].strip().lower() in {"test name", "test_id"}:
                continue
            if len(row) < 3 or row[2].strip().lower() not in {"true", "false"}:
                raise ValueError(f"invalid expected-results row: {row!r}")
            test_id = row[0].strip()
            if test_id in labels:
                raise ValueError(f"duplicate label ID: {test_id}")
            labels[test_id] = row[1].strip()
    if len(labels) != 1230:
        raise ValueError(f"expected 1230 pinned benchmark labels, found {len(labels)}")
    return labels


def run_tool(name: str, command: list[str], raw_path: Path, source_root: Path) -> dict:
    started = time.perf_counter()
    with raw_path.open("w", encoding="utf-8") as output:
        proc = subprocess.run(command, cwd=source_root.parent, stdout=output,
                              stderr=subprocess.PIPE, text=True, check=False)
    elapsed = time.perf_counter() - started
    result = {
        "name": name, "command": command, "return_code": proc.returncode,
        "wall_seconds": elapsed, "stderr": proc.stderr[-12000:],
        "raw_output": str(raw_path),
    }
    try:
        data = json.loads(raw_path.read_text(encoding="utf-8"))
        if name == "bandit":
            findings = data.get("results", [])
            files = [item.get("filename", "") for item in findings]
        else:
            findings = data.get("results", [])
            files = [item.get("path", "") for item in findings]
        case_ids = set()
        non_case_findings = 0
        for file_name in files:
            match = TEST_ID_RE.search(file_name.replace("\\", "/"))
            if match and match.group(1) in labels_placeholder:
                case_ids.add(match.group(1))
            else:
                non_case_findings += 1
        result.update({
            "output_valid_json": True,
            "finding_count": len(findings),
            "distinct_case_files_flagged": len(case_ids),
            "non_case_findings": non_case_findings,
            "flagged_case_ids": sorted(case_ids),
        })
    except (OSError, json.JSONDecodeError, AttributeError, TypeError) as exc:
        result.update({"output_valid_json": False, "parse_error": str(exc),
                       "finding_count": None, "flagged_case_ids": []})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", required=True, type=Path)
    parser.add_argument("--source-dir", required=True, type=Path,
                        help="pinned benchmark testcode directory")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    global labels_placeholder
    labels_placeholder = load_labels(args.labels)
    source_root = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    source_files = sorted(source_root.glob("BenchmarkTest*.py"))
    if len(source_files) != 1230:
        raise SystemExit(f"expected 1230 test modules, found {len(source_files)}")

    commands = {
        "bandit": [sys.executable, "-m", "bandit", "-r", str(source_root),
                   "-f", "json", "-q"],
        "semgrep": ["semgrep", "scan", "--config", "p/python", "--metrics=off",
                    "--no-git-ignore", "--json", str(source_root)],
    }
    results = []
    for name, command in commands.items():
        raw_path = output_dir / f"{name}-raw.json"
        result = run_tool(name, command, raw_path, source_root)
        result["source_files"] = len(source_files)
        results.append(result)
        if not result["output_valid_json"]:
            print(f"{name}: scanner output invalid; inspect {raw_path}", file=sys.stderr)
            continue
        flagged = set(result["flagged_case_ids"])
        normalized = output_dir / f"{name}-predictions.csv"
        with normalized.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["test_id", "category", "detected", "status"])
            for test_id, category in sorted(labels_placeholder.items()):
                writer.writerow([test_id, category, str(test_id in flagged).lower(), "ok"])
        score_path = output_dir / f"{name}-score.json"
        score_cmd = [sys.executable, str(Path(__file__).with_name("score_phase4.py")),
                     "--labels", str(args.labels.resolve()),
                     "--predictions", str(normalized), "--output", str(score_path)]
        score_proc = subprocess.run(score_cmd, capture_output=True, text=True, check=False)
        result["scoring_return_code"] = score_proc.returncode
        result["score_path"] = str(score_path)
        if score_proc.returncode != 0:
            result["scoring_stderr"] = score_proc.stderr[-4000:]

    report = {
        "schema_version": 1,
        "benchmark_commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
        "label_count": len(labels_placeholder),
        "source_file_count": len(source_files),
        "method": "binary case-level classification: at least one finding in the case's test module",
        "limitations": [
            "This is a first static-analysis baseline, not an end-to-end DAST evaluation.",
            "A finding anywhere in a test module is counted as a positive case prediction; findings are not yet adjudicated for category/CWE relevance.",
            "Benchmark labels are imperfect and v0.1 is preliminary.",
            "Tool configuration and version are part of the result; Semgrep's registry ruleset must be pinned separately before any final held-out comparison.",
            "No PRISM orchestration or optimization is evaluated by this runner.",
        ],
        "tools": results,
    }
    report_path = output_dir / "summary.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(report_path), "tools": [
        {k: v for k, v in r.items() if k in {"name", "return_code", "wall_seconds",
          "output_valid_json", "finding_count", "distinct_case_files_flagged",
          "non_case_findings", "scoring_return_code"}} for r in results]}, indent=2))
    return 0 if all(r.get("output_valid_json") and r.get("scoring_return_code") == 0
                    for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
