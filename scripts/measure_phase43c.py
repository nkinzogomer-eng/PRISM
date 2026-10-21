#!/usr/bin/env python3
"""Phase 4.3C: fresh Bandit 1.8.6 B307 scanner experiment.

Compare full, an exact-byte cache, conventional AST+directive cache, a conventional suffix diff, and
a narrow sufficient-change certificate with actual normalized alert equality.

Do not interpret B307 alert retention as broad cybersecurity capability.
The special benchmark edits are constructed and predeclared, not naturally
sampled software development. A cheap suffix test can also be used by an
ordinary incremental system; this is NOT inherently novel SCM computation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time

if __package__ in ("", None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prism.property_certificate import select_reanalysis, merge_or_fail, suffix_certificate
from prism.incremental import finding_fingerprint
from scripts.measure_phase43b import (
    source_inventory, normalized_finding, decode_scan, diff_finding_counts,
)

MODES = ("full", "hash", "ast_reference", "diff_reference", "scm_suffix")


def mutate(previous: dict[str, bytes], scenario: str) -> tuple[dict[str, bytes], dict]:
    """Deterministic edits, no labels or old alert inventory in selection."""
    names = sorted(previous)
    random.Random(43030 + {"inert_all": 0, "mixed": 1, "adversarial": 2,
                           "line_shift": 3}[scenario]).shuffle(names)
    result = dict(previous)
    actions = Counter()
    targets = (names if scenario != "line_shift" else names[:123])
    for i, name in enumerate(targets):
        raw = previous[name]
        suffix = (b"# SCM43C-INERT-" + str(i % 99999).encode() + b"\n")
        if scenario == "inert_all":
            edit = raw + suffix
            action = "inert_suffix"
        elif scenario == "mixed":
            if i % 10 == 0:
                edit = raw + b'\neval("1 + 1")\n'
                action = "new_eval_call"
            else:
                edit = raw + suffix
                action = "inert_suffix"
        elif scenario == "adversarial":
            if i % 10 == 0:
                edit = raw + b'\neval("1 + 1") # nosec B307\n'
                action = "scanner_suppression"
            elif i % 10 == 1:
                edit = raw + b'\neval("1 + 1")\n'
                action = "new_eval_call"
            else:
                edit = raw + suffix
                action = "inert_suffix"
        elif scenario == "line_shift":
            edit = b"\n" + raw
            action = "line_shift"
        else:
            raise ValueError(scenario)
        result[name] = edit
        actions[action] += 1
    return result, {"scenario": scenario, "edited": len(targets),
                    "actions": dict(actions),
                    "edit_seed": 43030 + {"inert_all": 0, "mixed": 1,
                                          "adversarial": 2, "line_shift": 3}[scenario]}


def run_scanner(snapshot: dict[str, bytes], selected: set[str],
                output: Path, ident: str) -> tuple[dict[str, tuple[tuple, ...]], dict]:
    if not selected:
        return {}, {"selected": 0, "wall_seconds": 0.0, "scanner_seconds": 0.0,
                    "findings": 0, "raw_sha256": None}
    total = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="scm43c-") as temp:
        staged = Path(temp) / "testcode"
        staged.mkdir()
        for name in sorted(selected):
            (staged / (name + ".py")).write_bytes(snapshot[name])
        stage_sec = time.perf_counter() - total
        command = [sys.executable, "-m", "bandit", "-r", str(staged),
                   "-t", "B307", "-f", "json", "-q"]
        clock = time.perf_counter()
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, timeout=120)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Bandit B307 timeout; results are unknown") from exc
        scan_sec = time.perf_counter() - clock
        raw_file = output / f"{ident}.json"
        raw_file.write_text(proc.stdout, encoding="utf-8")
        try:
            report = json.loads(proc.stdout)
        except ValueError as exc:
            raise RuntimeError("B307 did not return valid JSON") from exc
        ledger = decode_scan("bandit", report, proc.returncode, selected)
        # Fail if the scanner selection does not in fact restrict to B307.
        if any(item[1] != "B307" for values in ledger.values() for item in values):
            raise RuntimeError("unrequested Bandit rule in B307 result")
        info = {
            "selected": len(selected), "stage_seconds": stage_sec,
            "scanner_seconds": scan_sec, "findings": sum(map(len, ledger.values())),
            "raw_sha256": hashlib.sha256(proc.stdout.encode()).hexdigest(),
            "return_code": proc.returncode,
        }
    info["wall_seconds"] = time.perf_counter() - total
    return ledger, info


def measure(source_dir: Path, output: Path, repeats: int = 2) -> dict:
    if repeats < 1 or repeats > 4:
        raise ValueError("repeats must be in 1..4")
    output.mkdir(parents=True, exist_ok=True)
    original = source_inventory(source_dir)
    # A successful full run establishes the external parser precondition,
    # relative to the pinned Bandit implementation and this input corpus.
    check = subprocess.run([sys.executable, "-m", "bandit", "--version"],
                           capture_output=True, text=True, timeout=30)
    if check.returncode or "1.8.6" not in check.stdout + check.stderr:
        raise ValueError("requires frozen Bandit 1.8.6")

    report = {
        "phase": "4.3C", "scope": "Bandit 1.8.6 rule B307 only",
        "status": "INCOMPLETE", "source_manifest": "pinned by 4.3B loader",
        "scenarios": [], "cold_cache": {},
        "runs": [], "checks": [],
        "limits": [
            "A restricted inert-tail source edit, not general dependency reasoning",
            "A simple conventional suffix-diff comparator can duplicate the SCM certificate",
            "Bandit B307 only, no claim of full Bandit or Semgrep finding preservation",
            "Old source parser and scanner preconditions verified experimentally",
            "Empirical scanner equivalence on synthetic changes; no formal verification of all scanner behaviors",
            "No held-out software or realistic edit distribution",
            "Read/scan/verification and cleanup counted per run; install/network and final serialization excluded",
            "Only two repeats on shared runners; no stable CI/p95/memory or money estimate",
            "All alert matches are scanner results, not verified vulnerabilities",
        ],
    }
    try:
        prior, info = run_scanner(original, set(original), output, "cold-b307")
        report["cold_cache"] = {
            "wall_seconds": info["wall_seconds"],
            "findings": sum(map(len, prior.values())),
            "fingerprint": finding_fingerprint(prior),
        }
        for scenario in ("inert_all", "mixed", "adversarial", "line_shift"):
            after, meta = mutate(original, scenario)
            report["scenarios"].append(meta)
            for repeat in range(repeats):
                grouped = {}
                ordered = list(MODES[repeat % len(MODES):] + MODES[:repeat % len(MODES)])
                for mode in ordered:
                    elapsed = time.perf_counter()
                    snapshot = source_inventory(source_dir)
                    candidate, _ = mutate(snapshot, scenario)
                    selection_start = time.perf_counter()
                    selection, reasons = select_reanalysis(mode, snapshot, candidate)
                    selection_seconds = time.perf_counter() - selection_start
                    fresh, scan = run_scanner(
                        candidate, selection, output, f"{scenario}-{repeat}-{mode}")
                    merged = merge_or_fail(set(candidate), selection, prior, fresh)
                    fingerprint = finding_fingerprint(merged)
                    wall = time.perf_counter() - elapsed
                    row = {
                        "scenario": scenario, "repeat": repeat, "policy": mode,
                        "total_seconds": wall,
                        "selection_seconds": selection_seconds,
                        "scanned": len(selection), "cache_reused": len(candidate)-len(selection),
                        "selection_reasons": reasons, "scan": scan,
                        "finding_count": sum(map(len, merged.values())),
                        "finding_fingerprint": fingerprint,
                    }
                    report["runs"].append(row)
                    grouped[mode] = merged
                for mode in MODES[1:]:
                    diff = diff_finding_counts(grouped["full"], grouped[mode])
                    check = {"scenario": scenario, "repeat": repeat,
                             "policy": mode, "diff": diff,
                             "identical": not any(diff.values())}
                    report["checks"].append(check)
                    if not check["identical"]:
                        raise RuntimeError("B307 findings differ from full scan: " + str(check))
        report["status"] = "PASS: development B307 alerts matched at all normalized identities"
    except Exception as exc:
        report["failure"] = str(exc)
        report["status"] = "FAIL: incomplete benchmark or scanner finding divergence"
        raise
    finally:
        (output / "measurement.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=2)
    args = parser.parse_args()
    report = measure(args.source_dir, args.output, args.repeats)
    print(report["status"])
    for x in report["runs"]:
        print(x["scenario"], x["repeat"], x["policy"],
              "selected", x["scanned"],
              "findings", x["finding_count"],
              "total", round(x["total_seconds"], 3),
              "proof", round(x["selection_seconds"], 3))
    print("comparisons", len(report["checks"]), "all_equal",
          all(c["identical"] for c in report["checks"]))


if __name__ == "__main__":
    main()
