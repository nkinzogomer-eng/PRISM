#!/usr/bin/env python3
"""Phase 4.3B: real-process, full-finding incremental scans (development only).

Run full Bandit + Semgrep on a pinned source snapshot, modify deterministic
copies, then compare fresh whole-corpus scans to: (1) ordinary SHA-256 cache
and (2) a cost-aware chooser over that cache. No original sources are edited.

A passing comparison is empirical for the pinned scanner/rules and these
snapshots; NOT a proof of cross-module independence or absence of bugs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prism.incremental import (
    changed_files, content_hash, finding_fingerprint, merge_findings, plan_update,
)
from scripts.measure_phase43 import file_id
from scripts.phase4_evidence import validate_scan

PINNED_DEV_SHA = "fe0ec67dcc328feb33d592b790563add38c721af4b89abcf839e56bc9e3b9b9d"
TOOL_VERSIONS = {"bandit": "1.8.6", "semgrep": "1.181.0"}
FILE_COUNT = 1230


def source_inventory(source_dir: Path) -> dict[str, bytes]:
    paths = sorted(source_dir.glob("BenchmarkTest*.py"))
    sources = {p.stem: p.read_bytes() for p in paths}
    if len(paths) != FILE_COUNT or len(sources) != FILE_COUNT:
        raise ValueError("development benchmark inventory not equal to pinned 1230 modules")
    h = hashlib.sha256()
    for name, data in sorted(sources.items()):
        h.update((name + ".py").encode() + b"\0" + data)
    if h.hexdigest() != PINNED_DEV_SHA:
        raise ValueError("source-byte provenance changed; refusing to reinterpret prior benchmark")
    return sources


def config_digest(tool: str, rules: list[Path]) -> str:
    """Include tool version, pinned command flags and content of all active rules."""
    h = hashlib.sha256()
    h.update((tool + "|" + TOOL_VERSIONS[tool] + "|"
              + "module-inventory-v1;no-git-ignore;metrics-off;security-rules").encode())
    if tool == "semgrep":
        for i, root in enumerate(rules):
            if not root.is_dir():
                raise ValueError(f"missing pinned Semgrep rules: {root}")
            paths = sorted(p for p in root.rglob("*") if p.is_file())
            if not paths:
                raise ValueError("empty Semgrep rules")
            for path in paths:
                h.update(str(i).encode() + b":" +
                         str(path.relative_to(root)).encode() + b"\0" +
                         hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def make_snapshot(source_dir: Path, targets: set[str], scenario: str) -> dict[str, bytes]:
    result = source_inventory(source_dir)
    if not targets <= result.keys():
        raise ValueError("unknown mutation target")
    for i, name in enumerate(sorted(targets)):
        # These are artificial benchmark edits, never written to the real repo.
        # Every eighth edit deliberately introduces an analyzer-recognizable
        # call; the others are comments (still byte-level changes).
        suffix = (b'\neval("1 + 1")\n' if i % 8 == 0
                  else ("\n# scm-benchmark-update-" + scenario + "-" + name + "\n").encode())
        result[name] = result[name] + suffix
    return result


def normalized_finding(tool: str, obj: dict) -> tuple[str, tuple]:
    if tool == "bandit":
        case = file_id(str(obj.get("filename", "")))
        if case is None:
            raise ValueError("Bandit finding outside benchmark")
        value = (
            "bandit", str(obj.get("test_id", "")),
            int(obj.get("line_number", 0)), int(obj.get("col_offset") or 0),
            str(obj.get("issue_text", "")), str(obj.get("issue_severity", "")),
            str(obj.get("issue_confidence", "")),
        )
        return case, value
    case = file_id(str(obj.get("path", "")))
    if case is None:
        raise ValueError("Semgrep finding outside benchmark")
    start, end, extra = obj.get("start") or {}, obj.get("end") or {}, obj.get("extra") or {}
    value = (
        "semgrep", str(obj.get("check_id", "")),
        int(start.get("line", 0)), int(start.get("col", 0)),
        int(end.get("line", 0)), int(end.get("col", 0)),
        str(extra.get("message", "")), str(extra.get("severity", "")),
    )
    return case, value


def decode_scan(tool: str, raw: dict, return_code: int,
                expected: set[str]) -> dict[str, tuple[tuple, ...]]:
    problems = validate_scan(tool, return_code, raw)
    paths = (raw.get("metrics", {}).keys() if tool == "bandit"
             else (raw.get("paths") or {}).get("scanned", []))
    actually_scanned = {case for p in paths if (case := file_id(str(p)))}
    if actually_scanned != expected:
        problems.append(f"scanner inventory mismatch expected={len(expected)} actual={len(actually_scanned)}")
    findings = raw.get("results", [])
    if not isinstance(findings, list):
        problems.append("invalid findings")
    if problems:
        raise ValueError(f"{tool} incomplete or failed: {problems}")
    rows: dict[str, list[tuple]] = {name: [] for name in expected}
    for finding in findings:
        case, key = normalized_finding(tool, finding)
        if case not in expected:
            raise ValueError(f"{tool} emitted result for unscanned module {case}")
        rows[case].append(key)
    return {name: tuple(sorted(values)) for name, values in rows.items()}


def run_scanner(tool: str, selected: set[str], sources: dict[str, bytes],
                rules: list[Path], output: Path, scan_id: str) -> tuple[dict, dict]:
    if not selected:
        return {name: () for name in selected}, {
            "tool": tool, "scanned": 0, "findings": 0,
            "wall_seconds": 0., "child_cpu_seconds": 0.,
            "raw_sha256": None, "skipped_process": True,
        }
    if not selected <= sources.keys():
        raise ValueError("invalid scan selection")
    stage_start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="scm43b-") as temp:
        stage = Path(temp) / "testcode"
        stage.mkdir()
        for name in sorted(selected):
            (stage / (name + ".py")).write_bytes(sources[name])
        stage_seconds = time.perf_counter() - stage_start
        if tool == "bandit":
            command = [sys.executable, "-m", "bandit", "-r", str(stage), "-f", "json", "-q"]
        else:
            command = ["semgrep", "scan", "--metrics=off", "--no-git-ignore", "--json"]
            for config in rules:
                command += ["--config", str(config)]
            command.append(str(stage))
        cpu_before = os.times()
        clock = time.perf_counter()
        try:
            proc = subprocess.run(command, capture_output=True, text=True,
                                  check=False, timeout=180)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{tool} timeout; scanned files remain unknown") from exc
        scanner_seconds = time.perf_counter() - clock
        cpu_after = os.times()
        raw_path = output / (scan_id + "-" + tool + ".json")
        raw_path.write_text(proc.stdout, encoding="utf-8")
        try:
            raw = json.loads(proc.stdout)
        except ValueError as exc:
            raise RuntimeError(f"{tool} invalid scanner JSON; stderr={proc.stderr[-500:]}") from exc
        valid_start = time.perf_counter()
        ledger = decode_scan(tool, raw, proc.returncode, selected)
        validation_seconds = time.perf_counter() - valid_start
        info = {
            "tool": tool, "scanned": len(selected),
            "findings": sum(map(len, ledger.values())),
            "stage_seconds": stage_seconds, "scanner_seconds": scanner_seconds,
            "validation_seconds": validation_seconds,
            "child_cpu_seconds": max(0, cpu_after.children_user + cpu_after.children_system
                                    - cpu_before.children_user - cpu_before.children_system),
            "raw_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
            "return_code": proc.returncode,
            "rules": [str(p) for p in rules] if tool == "semgrep" else [],
            "stderr_tail": proc.stderr[-400:],
        }
    info["wall_seconds"] = time.perf_counter() - stage_start
    return ledger, info


def profile_snapshot(sources: dict[str, bytes]) -> dict[str, str]:
    return {name: content_hash(data) for name, data in sources.items()}


def execute_arm(policy: str, source_dir: Path, targets: set[str], scenario: str,
                cached: dict[str, dict], rules: list[Path], output: Path,
                repeat: int) -> tuple[dict, dict[str, dict]]:
    started = time.perf_counter()
    snapshot = make_snapshot(source_dir, targets, scenario)
    digests = profile_snapshot(snapshot)
    reports = {}
    ledgers = {}
    for tool in ("bandit", "semgrep"):
        old = cached[tool]
        contract = config_digest(tool, rules)
        plan = plan_update(policy, old["hashes"], digests,
                           old["contract"], contract, old["full_wall_seconds"],
                           estimated_setup_seconds=1.0)
        new_rows, run_info = run_scanner(
            tool, set(plan.execute), snapshot, rules, output,
            f"{scenario}-{repeat}-{policy}",
        )
        ledger = merge_findings(
            digests, old["hashes"], old["contract"], contract,
            old["ledger"], new_rows, set(plan.execute),
        )
        if set(ledger) != set(snapshot):
            raise RuntimeError("missing ledger inventory")
        ledgers[tool] = ledger
        reports[tool] = {
            "plan": {"mode": plan.strategy, "reason": plan.reason,
                     "executed": len(plan.execute),
                     "predicted_gain": plan.predicted_gain},
            "run": run_info, "fingerprint": finding_fingerprint(ledger),
            "total_finding_count": sum(map(len, ledger.values())),
            "cache_reused": len(snapshot) - len(plan.execute),
        }
    return {
        "policy": policy, "scenario": scenario, "repeat": repeat,
        "changed": len(targets), "modules": len(snapshot),
        "wall_seconds_including_read_hash_plan_merge_cleanup":
            time.perf_counter() - started,
        "child_cpu_seconds": sum(x["run"].get("child_cpu_seconds", 0)
                                 for x in reports.values()),
        "tools": reports,
    }, ledgers


def diff_finding_counts(a: dict[str, tuple[tuple, ...]],
                        b: dict[str, tuple[tuple, ...]]) -> dict:
    missing = extra = 0
    affected = 0
    for name in a:
        ca, cb = Counter(a[name]), Counter(b.get(name, ()))
        lost = sum((ca-cb).values())
        added = sum((cb-ca).values())
        missing += lost
        extra += added
        if lost or added:
            affected += 1
    return {"missing": missing, "extra": extra, "affected_modules": affected}


def measure(source_dir: Path, rules: list[Path], output: Path,
            repeats: int = 2) -> dict:
    if not 1 <= repeats <= 5:
        raise ValueError("repeats must be between 1 and 5")
    output.mkdir(parents=True, exist_ok=True)
    base = source_inventory(source_dir)
    base_hashes = profile_snapshot(base)
    versions = {}
    for tool, cmd in [
        ("bandit", [sys.executable, "-m", "bandit", "--version"]),
        ("semgrep", ["semgrep", "--version"]),
    ]:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if p.returncode:
            raise ValueError(f"{tool} version probe failed")
        value = p.stdout + "\n" + p.stderr
        if TOOL_VERSIONS[tool] not in value:
            raise ValueError(f"wrong {tool} version: {value[:120]}")
        versions[tool] = value.strip()
    report = {
        "schema_version": 1, "experiment": "4.3B full-finding incremental",
        "development_only": True,
        "source_commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
        "source_sha256": PINNED_DEV_SHA,
        "tool_versions": versions, "platform": platform.platform(),
        "limitations": [
            "Empirical module-local independence, not a formal static-analysis proof",
            "Cache keys omit arbitrary external execution environment dependencies",
            "Strong hash-cache comparator is not SCM-specific",
            "Pinned synthetic development data and synthetic edits, no held-out test",
            "No correctness claim beyond exact normalized scanner finding equality",
            "Memory, energy, financial cost and setup/network are not timed",
            "Repeated timing on shared CI hardware; no reliable p95 inference",
            "Results include scanner setup and per-run planner/hash/copy; initial cache build is separate",
        ],
        "cold_cache_build": {}, "runs": [], "checks": [], "status": "STARTED",
    }
    try:
        cache = {}
        for tool in ("bandit", "semgrep"):
            start = time.perf_counter()
            contract = config_digest(tool, rules)
            ledger, info = run_scanner(tool, set(base), base, rules, output, "cold-base")
            wall = time.perf_counter() - start
            cache[tool] = {
                "contract": contract, "hashes": base_hashes,
                "ledger": ledger, "full_wall_seconds": wall,
            }
            report["cold_cache_build"][tool] = {
                "wall_seconds": wall, "scan": info,
                "contract_sha256": contract,
                "fingerprint": finding_fingerprint(ledger),
            }
        names = sorted(base)
        scenarios = [
            ("one", 1), ("tenth", 123), ("all", 1230),
        ]
        for index, (scenario, amount) in enumerate(scenarios):
            target_ids = set(random.Random(4300 + index).sample(names, amount))
            for repeat in range(repeats):
                arms = {}
                for policy in (["full", "hash_cache", "prism"][repeat % 3:]
                               + ["full", "hash_cache", "prism"][:repeat % 3]):
                    row, ledger = execute_arm(policy, source_dir, target_ids,
                                              scenario, cache, rules, output, repeat)
                    report["runs"].append(row)
                    arms[policy] = ledger
                for policy in ("hash_cache", "prism"):
                    tool_diff = {tool: diff_finding_counts(arms["full"][tool],
                                                         arms[policy][tool])
                                 for tool in ("bandit", "semgrep")}
                    check = {"scenario": scenario, "repeat": repeat,
                             "policy": policy, "diff": tool_diff,
                             "exact_equal": all(not any(v.values())
                                                for v in tool_diff.values())}
                    report["checks"].append(check)
                    if not check["exact_equal"]:
                        raise RuntimeError(f"finding preservation failed: {check}")
        report["status"] = "PASS: scanner findings exactly preserved in development snapshots"
    except Exception as exc:
        report["status"] = "FAIL: scanner or exact-finding integrity gate"
        report["failure"] = str(exc)
        raise
    finally:
        (output / "measurement.json").write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--semgrep-config", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    args = parser.parse_args()
    data = measure(args.source_dir, [p.resolve() for p in args.semgrep_config],
                   args.output, args.repeats)
    print(data["status"])
    for row in data["runs"]:
        print(row["scenario"], row["repeat"], row["policy"],
              f"wall={row['wall_seconds_including_read_hash_plan_merge_cleanup']:.3f}",
              "scanned", {k: v["plan"]["executed"] for k, v in row["tools"].items()},
              "findings", {k: v["total_finding_count"] for k, v in row["tools"].items()})


if __name__ == "__main__":
    main()
