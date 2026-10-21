#!/usr/bin/env python3
"""Phase 4.3A: real-process, development-only binary-OR cost experiment.

All scanners see unchanged source bytes. The second scanner may skip a case
only after the first scanner flags that *same* case. This preserves a binary
OR objective when the scanners are module-local; it does not preserve all
Semgrep alerts. Paired full scans detect violations of that assumption.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    from prism.cost_policy import CostEstimate, checked_or, choose_plan, second_stage_inventory
    from scripts.phase4_evidence import validate_scan
    from scripts.score_phase4 import read_labels, calculate
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from prism.cost_policy import CostEstimate, checked_or, choose_plan, second_stage_inventory
    from scripts.phase4_evidence import validate_scan
    from scripts.score_phase4 import read_labels, calculate

CASE_RE = re.compile(r"^BenchmarkTest\d{5}\.py$")
PINNED_MANIFEST_SHA256 = "13585e460c4c59d50b622e3add0255bc7da7ca5278de0ea028ca5e7d58b32ca5"


def file_id(value: str) -> str | None:
    name = Path(value.replace("\\", "/")).name
    return name[:-3] if CASE_RE.fullmatch(name) else None


def inventory_and_hash(source_dir: Path) -> tuple[dict[str, Path], str]:
    files = {p.stem: p for p in sorted(source_dir.glob("BenchmarkTest*.py"))}
    digest = hashlib.sha256()
    for case, path in sorted(files.items()):
        digest.update(path.name.encode() + b"\x00" + path.read_bytes())
    return files, digest.hexdigest()


def execute(name: str, command: list[str], expected: set[str], path: Path,
            timeout: int = 300) -> dict:
    """Capture a new process with strict, tool-specific inventory verification."""
    start = time.perf_counter()
    cpu0 = os.times()
    try:
        with path.open("w", encoding="utf-8") as output:
            proc = subprocess.run(command, stdout=output, stderr=subprocess.PIPE,
                                  text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{name}: timed out; output is not a negative result") from exc
    wall = time.perf_counter() - start
    cpu1 = os.times()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"{name}: unreadable JSON; stderr unavailable in score") from exc
    problems = validate_scan(name, proc.returncode, data)
    raw_scanned = (data.get("metrics", {}).keys() if name == "bandit"
                   else data.get("paths", {}).get("scanned", []))
    scanned = {case for item in raw_scanned if (case := file_id(item)) is not None}
    if scanned != expected:
        problems.append(f"inventory mismatch: missing={len(expected-scanned)}, extra={len(scanned-expected)}")
    findings = data.get("results", [])
    positives = set()
    evidence = {}
    if isinstance(findings, list):
        for item in findings:
            case = file_id(item.get("filename", "") if name == "bandit"
                           else item.get("path", ""))
            if case is None or case not in expected:
                problems.append("finding outside expected inventory")
                continue
            positives.add(case)
            rule = item.get("test_id", "") if name == "bandit" else item.get("check_id", "")
            line = item.get("line_number", 0) if name == "bandit" else item.get("start", {}).get("line", 0)
            evidence.setdefault(case, set()).add((str(rule), int(line)))
    if problems:
        raise RuntimeError(f"{name}: incomplete/invalid scan: {sorted(set(problems))}; stderr={proc.stderr[-800:]}")
    return {
        "wall_seconds": wall,
        "cpu_child_seconds": max(0, cpu1.children_user + cpu1.children_system
                                - cpu0.children_user - cpu0.children_system),
        "return_code": proc.returncode,
        "scanned": scanned,
        "positive": positives,
        "evidence": evidence,
        "finding_count": len(findings),
        "raw_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "stderr_tail": proc.stderr[-500:],
        "command": [str(v) for v in command],
    }


def staged(files: dict[str, Path], selection: set[str], dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for case in sorted(selection):
        shutil.copyfile(files[case], dst / (case + ".py"))


def one_arm(policy: str, files: dict[str, Path], labels: dict,
            configs: list[str], output: Path, repeat: int, mode: str) -> dict:
    total = time.perf_counter()
    universe = set(files)
    stage_cost = 0.0
    verification_cost = 0.0
    with tempfile.TemporaryDirectory(prefix="prism-phase43-") as tmp:
        workspace = Path(tmp)
        start = time.perf_counter()
        first_dir = workspace / "bandit"
        staged(files, universe, first_dir)
        stage_cost += time.perf_counter() - start

        bandit = execute("bandit", [sys.executable, "-m", "bandit", "-r",
                         str(first_dir), "-f", "json", "-q"], universe,
                         output / f"{repeat}-{policy}-bandit.json")

        second_set = (universe if mode == "full"
                      else second_stage_inventory(universe, bandit["positive"]))
        start = time.perf_counter()
        second_dir = workspace / "semgrep"
        staged(files, second_set, second_dir)
        stage_cost += time.perf_counter() - start

        if second_set:
            semgrep_cmd = ["semgrep", "scan", "--metrics=off", "--no-git-ignore",
                           "--json"]
            for config in configs:
                semgrep_cmd.extend(["--config", config])
            semgrep_cmd.append(str(second_dir))
            semgrep = execute("semgrep", semgrep_cmd, second_set,
                              output / f"{repeat}-{policy}-semgrep.json")
        else:
            semgrep = {
                "wall_seconds": 0.0, "cpu_child_seconds": 0.0,
                "scanned": set(), "positive": set(), "evidence": {},
                "finding_count": 0, "raw_sha256": None,
                "return_code": None, "command": [],
            }

        start = time.perf_counter()
        union = checked_or(universe, bandit["positive"], semgrep["positive"],
                           semgrep["scanned"], sequential=mode == "sequential")
        scores = calculate(labels, {key: ("ok", key in union) for key in labels})
        verification_cost = time.perf_counter() - start

    elapsed = time.perf_counter() - total  # includes cleanup; excludes report serialization
    return {
        "policy": policy, "effective_mode": mode, "repeat": repeat,
        "total_seconds": elapsed, "staging_seconds": stage_cost,
        "verification_and_scoring_seconds": verification_cost,
        "bandit_seconds": bandit["wall_seconds"],
        "semgrep_seconds": semgrep["wall_seconds"],
        "child_cpu_seconds": bandit["cpu_child_seconds"] + semgrep["cpu_child_seconds"],
        "first_scanned": len(bandit["scanned"]), "second_scanned": len(semgrep["scanned"]),
        "first_positive": len(bandit["positive"]), "second_positive": len(semgrep["positive"]),
        "first_findings": bandit["finding_count"], "second_findings": semgrep["finding_count"],
        "positive_case_ids": sorted(union),
        "second_scanned_ids": sorted(semgrep["scanned"]),
        "second_evidence": {k: sorted(list(v)) for k, v in semgrep["evidence"].items()},
        "tool_commands": {"bandit": bandit["command"], "semgrep": semgrep["command"]},
        "raw_sha256": {"bandit": bandit["raw_sha256"], "semgrep": semgrep["raw_sha256"]},
        "score_coarse_in_sample": scores["results"]["ALL"],
    }


def verify_pair(full: dict, candidate: dict) -> dict:
    """Ensure binary-OR decisions *and* examined Semgrep per-case alerts match."""
    full_positive = set(full["positive_case_ids"])
    candidate_positive = set(candidate["positive_case_ids"])
    candidate_scanned = set(candidate["second_scanned_ids"])
    f_evidence = full["second_evidence"]
    c_evidence = candidate["second_evidence"]
    mismatches = sorted(case for case in candidate_scanned
                        if f_evidence.get(case, []) != c_evidence.get(case, []))
    return {
        "decision_equal": full_positive == candidate_positive,
        "missing_positive_cases": sorted(full_positive - candidate_positive),
        "extra_positive_cases": sorted(candidate_positive - full_positive),
        "second_stage_findings_equal_on_scanned_cases": not mismatches,
        "second_stage_mismatch_cases": mismatches,
        "semgrep_findings_intentionally_not_retained_in_first_positive_cases":
            full["second_findings"] - sum(
                len(full["second_evidence"].get(case, [])) for case in candidate_scanned),
    }


def measure(source_dir: Path, labels_path: Path, configs: list[str],
            output: Path, repeats: int, estimate: CostEstimate) -> dict:
    if not 1 <= repeats <= 10:
        raise ValueError("repeats must be in 1..10")
    if not configs:
        raise ValueError("at least one pinned, local Semgrep config required")
    for config in configs:
        if not Path(config).is_dir():
            raise ValueError(f"Semgrep configuration directory not found: {config}")
    files, manifest = inventory_and_hash(source_dir)
    if manifest != PINNED_MANIFEST_SHA256 or len(files) != 1230:
        raise ValueError(f"pinned source manifest mismatch ({manifest}; {len(files)} modules)")
    labels = read_labels(labels_path)
    if set(labels) != set(files):
        raise ValueError("labels/source inventory mismatch")
    output.mkdir(parents=True, exist_ok=True)
    plan_start = time.perf_counter()
    plan = choose_plan(estimate)
    planning_seconds = time.perf_counter() - plan_start
    results = {
        "phase": "4.3A", "decision": "binary per-module OR only",
        "dataset": "OWASP Benchmark Python v0.1, development only",
        "source_manifest_sha256": manifest,
        "calibration": {"source": "Phase 4 development baseline; no holdout",
                        "first_seconds": estimate.first_seconds,
                        "second_seconds": estimate.second_seconds,
                        "first_positive_fraction": estimate.first_positive_fraction},
        "plan": plan, "planner_wall_seconds": planning_seconds,
        "limits": ["No semantic/CWE claim", "Not all individual Semgrep alerts retained",
                   "No held-out data", "Module-local assumption checked against full scan",
                   "Peak memory and installation/network cost not measured",
                   "Three scanner arms do not establish PRISM novelty"],
        "runs": [], "checks": [],
    }
    policies = ["full", "fixed_sequential", "prism"]
    try:
        for repeat in range(repeats):
            arms = {}
            for policy in policies[repeat % 3:] + policies[:repeat % 3]:
                mode = ("full" if policy == "full" else "sequential" if policy == "fixed_sequential"
                        else plan["mode"])
                arm = one_arm(policy, files, labels, configs, output, repeat, mode)
                results["runs"].append(arm)
                arms[policy] = arm
            for policy in ("fixed_sequential", "prism"):
                check = verify_pair(arms["full"], arms[policy])
                check.update({"repeat": repeat, "policy": policy})
                results["checks"].append(check)
                if not check["decision_equal"] or not check["second_stage_findings_equal_on_scanned_cases"]:
                    raise RuntimeError(f"paired preservation gate failed for {policy}, repeat {repeat}: {check}")
        results["validation"] = "PASS: development-only binary decisions and observed second-stage identities"
    except Exception as exc:
        results["validation"] = "FAIL: missing/invalid scanner coverage or paired disagreement"
        results["failure"] = str(exc)
        raise
    finally:
        (output / "measurement.json").write_text(
            json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return results


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-dir", type=Path, required=True)
    p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--semgrep-config", action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--repeats", type=int, default=2)
    p.add_argument("--first-seconds", type=float, default=5.41)
    p.add_argument("--second-seconds", type=float, default=21.0)
    p.add_argument("--first-positive-fraction", type=float, default=352 / 1230)
    args = p.parse_args()
    result = measure(args.source_dir, args.labels,
                     [str(Path(x).resolve()) for x in args.semgrep_config],
                     args.output, args.repeats,
                     CostEstimate(args.first_seconds, args.second_seconds,
                                  args.first_positive_fraction))
    for row in result["runs"]:
        print(f"repeat={row['repeat']} policy={row['policy']} mode={row['effective_mode']} "
              f"wall={row['total_seconds']:.3f}s second_scanned={row['second_scanned']} "
              f"positive_cases={len(row['positive_case_ids'])}")
    print("preservation:", result["validation"], "planner:", result["plan"]["mode"])


if __name__ == "__main__":
    main()
