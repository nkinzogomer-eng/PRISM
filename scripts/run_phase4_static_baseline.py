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


def run_tool(name: str, command: list[str], raw_path: Path, source_root: Path, labels: dict[str, str]) -> dict:
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
            if match and match.group(1) in labels:
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
    parser.add_argument("--semgrep-config", action="append", default=None,
                        help="Semgrep registry alias or local immutable rules directory; repeat for multiple configs")
    args = parser.parse_args()
    labels = load_labels(args.labels)
    source_root = args.source_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    source_files = sorted(source_root.glob("BenchmarkTest*.py"))
    if len(source_files) != 1230:
        raise SystemExit(f"expected 1230 test modules, found {len(source_files)}")

    semgrep_configs = args.semgrep_config or ["p/python"]
    semgrep_config_args = []
    for config in semgrep_configs:
        resolved = config if config.startswith("p/") else str(Path(config).resolve())
        semgrep_config_args.extend(["--config", resolved])
    commands = {
        "bandit": [sys.executable, "-m", "bandit", "-r", str(source_root),
                   "-f", "json", "-q"],
        "semgrep": ["semgrep", "scan", *semgrep_config_args, "--metrics=off",
                    "--no-git-ignore", "--json", str(source_root)],
    }
    results = []
    for name, command in commands.items():
        raw_path = output_dir / f"{name}-raw.json"
        result = run_tool(name, command, raw_path, source_root, labels)
        result["source_files"] = len(source_files)
        results.append(result)
        if not result["output_valid_json"]:
            print(f"{name}: scanner output invalid; inspect {raw_path}; return_code={result['return_code']}; stderr={result['stderr']}", file=sys.stderr)
            continue
        flagged = set(result["flagged_case_ids"])
        normalized = output_dir / f"{name}-predictions.csv"
        with normalized.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["test_id", "category", "detected", "status"])
            for test_id, category in sorted(labels.items()):
                writer.writerow([test_id, category, str(test_id in flagged).lower(), "ok"])
        score_path = output_dir / f"{name}-score.json"
        score_cmd = [sys.executable, str(Path(__file__).with_name("score_phase4.py")),
                     "--labels", str(args.labels.resolve()),
                     "--predictions", str(normalized), "--output", str(score_path)]
        score_proc = subprocess.run(score_cmd, capture_output=True, text=True, check=False)
        result["scoring_return_code"] = score_proc.returncode
        result["score_path"] = str(score_path)
        if score_proc.returncode == 0:
            score_data = json.loads(score_path.read_text(encoding="utf-8"))
            overall = score_data["results"]["ALL"]
            result["metrics"] = {key: overall[key] for key in ("cases", "evaluated", "coverage", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "recall_lower_bound", "false_positive_rate_upper_bound")}
        if score_proc.returncode != 0:
            result["scoring_stderr"] = score_proc.stderr[-4000:]

    combined = None
    valid_tools = [r for r in results if r.get("output_valid_json") and r.get("scoring_return_code") == 0]
    if len(valid_tools) == 2:
        union_ids = sorted(set(valid_tools[0]["flagged_case_ids"]) | set(valid_tools[1]["flagged_case_ids"]))
        normalized = output_dir / "all-tools-predictions.csv"
        with normalized.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["test_id", "category", "detected", "status"])
            for test_id, category in sorted(labels.items()):
                writer.writerow([test_id, category, str(test_id in set(union_ids)).lower(), "ok"])
        score_path = output_dir / "all-tools-score.json"
        score_cmd = [sys.executable, str(Path(__file__).with_name("score_phase4.py")),
                     "--labels", str(args.labels.resolve()),
                     "--predictions", str(normalized), "--output", str(score_path)]
        score_proc = subprocess.run(score_cmd, capture_output=True, text=True, check=False)
        if score_proc.returncode == 0:
            score_data = json.loads(score_path.read_text(encoding="utf-8"))
            overall = score_data["results"]["ALL"]
            combined = {
                "policy": "fixed OR: flag a case if either analyzer reports at least one finding",
                "flagged_cases": len(union_ids),
                "wall_seconds_sum_of_tool_runs": sum(r["wall_seconds"] for r in valid_tools),
                "scoring_return_code": score_proc.returncode,
                "score_path": str(score_path),
                "metrics": {key: overall[key] for key in ("cases", "evaluated", "coverage", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "recall_lower_bound", "false_positive_rate_upper_bound")},
            }
        else:
            combined = {"scoring_return_code": score_proc.returncode, "scoring_stderr": score_proc.stderr[-4000:]}

    combined_and = None
    if len(valid_tools) == 2:
        intersection_ids = sorted(set(valid_tools[0]["flagged_case_ids"]) & set(valid_tools[1]["flagged_case_ids"]))
        normalized_and = output_dir / "all-tools-and-predictions.csv"
        with normalized_and.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["test_id", "category", "detected", "status"])
            for test_id, category in sorted(labels.items()):
                writer.writerow([test_id, category, str(test_id in set(intersection_ids)).lower(), "ok"])
        score_path_and = output_dir / "all-tools-and-score.json"
        score_cmd_and = [sys.executable, str(Path(__file__).with_name("score_phase4.py")),
                         "--labels", str(args.labels.resolve()),
                         "--predictions", str(normalized_and), "--output", str(score_path_and)]
        score_proc_and = subprocess.run(score_cmd_and, capture_output=True, text=True, check=False)
        if score_proc_and.returncode == 0:
            score_data_and = json.loads(score_path_and.read_text(encoding="utf-8"))
            overall_and = score_data_and["results"]["ALL"]
            combined_and = {
                "policy": "fixed AND: flag a case only if both analyzers report at least one finding",
                "flagged_cases": len(intersection_ids),
                "wall_seconds_sum_of_tool_runs": sum(r["wall_seconds"] for r in valid_tools),
                "scoring_return_code": score_proc_and.returncode,
                "score_path": str(score_path_and),
                "metrics": {key: overall_and[key] for key in ("cases", "evaluated", "coverage", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "recall_lower_bound", "false_positive_rate_upper_bound")},
            }
        else:
            combined_and = {"scoring_return_code": score_proc_and.returncode, "scoring_stderr": score_proc_and.stderr[-4000:]}

    sequential_policy = None
    if len(valid_tools) == 2:
        bandit_result = next((r for r in valid_tools if r["name"] == "bandit"), None)
        if bandit_result is not None:
            bandit_ids = set(bandit_result["flagged_case_ids"])
            remaining_files = []
            for source_file in source_files:
                match = TEST_ID_RE.search(source_file.name)
                if match and match.group(1) not in bandit_ids:
                    remaining_files.append(source_file)
            sequential_raw = output_dir / "semgrep-sequential-raw.json"
            sequential_command = [
                "semgrep", "scan", *semgrep_config_args, "--metrics=off",
                "--no-git-ignore", "--json", *[str(path) for path in remaining_files],
            ]
            sequential_result = run_tool(
                "semgrep-sequential", sequential_command, sequential_raw, source_root, labels
            )
            sequential_result["source_files"] = len(remaining_files)
            sequential_result["policy_note"] = "Semgrep runs only on cases not flagged by Bandit; labels are not used for selection"
            if sequential_result.get("output_valid_json"):
                semgrep_remaining_ids = set(sequential_result["flagged_case_ids"])
                combined_ids = bandit_ids | semgrep_remaining_ids
                normalized_seq = output_dir / "bandit-first-sequential-predictions.csv"
                with normalized_seq.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(["test_id", "category", "detected", "status"])
                    for test_id, category in sorted(labels.items()):
                        writer.writerow([test_id, category, str(test_id in combined_ids).lower(), "ok"])
                score_path_seq = output_dir / "bandit-first-sequential-score.json"
                score_cmd_seq = [sys.executable, str(Path(__file__).with_name("score_phase4.py")),
                                 "--labels", str(args.labels.resolve()),
                                 "--predictions", str(normalized_seq), "--output", str(score_path_seq)]
                score_proc_seq = subprocess.run(score_cmd_seq, capture_output=True, text=True, check=False)
                sequential_policy = {
                    "policy": "run Bandit on all cases, then run Semgrep only on cases Bandit did not flag",
                    "cases_sent_to_semgrep": len(remaining_files),
                    "cases_flagged": len(combined_ids),
                    "wall_seconds_sum_of_policy_tool_runs": bandit_result["wall_seconds"] + sequential_result["wall_seconds"],
                    "semgrep_return_code": sequential_result.get("return_code"),
                    "semgrep_output_valid_json": sequential_result.get("output_valid_json"),
                    "semgrep_findings": sequential_result.get("finding_count"),
                    "semgrep_wall_seconds": sequential_result.get("wall_seconds"),
                    "scoring_return_code": score_proc_seq.returncode,
                    "score_path": str(score_path_seq),
                }
                if score_proc_seq.returncode == 0:
                    score_data_seq = json.loads(score_path_seq.read_text(encoding="utf-8"))
                    overall_seq = score_data_seq["results"]["ALL"]
                    sequential_policy["metrics"] = {key: overall_seq[key] for key in ("cases", "evaluated", "coverage", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "recall_lower_bound", "false_positive_rate_upper_bound")}
                else:
                    sequential_policy["scoring_stderr"] = score_proc_seq.stderr[-4000:]
            else:
                sequential_policy = {
                    "policy": "run Bandit on all cases, then run Semgrep only on cases Bandit did not flag",
                    "semgrep_return_code": sequential_result.get("return_code"),
                    "semgrep_output_valid_json": False,
                    "stderr": sequential_result.get("stderr"),
                }

    report = {
        "schema_version": 1,
        "benchmark_commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
        "label_count": len(labels),
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
        "combined_all_tools_baseline": combined,
        "combined_and_tools_baseline": combined_and,
        "bandit_first_sequential_policy": sequential_policy,
    }
    report_path = output_dir / "summary.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(report_path), "tools": [
        {k: v for k, v in r.items() if k in {"name", "return_code", "wall_seconds",
          "output_valid_json", "finding_count", "distinct_case_files_flagged",
          "non_case_findings", "scoring_return_code", "metrics"}} for r in results],
        "combined_all_tools_baseline": combined, "combined_and_tools_baseline": combined_and, "bandit_first_sequential_policy": sequential_policy}, indent=2))
    return 0 if all(r.get("output_valid_json") and r.get("scoring_return_code") == 0
                    for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
