"""Run three real external EVM protocols; compare ONLY compatible budgets.

Failures are never silently counted as vulnerabilities. Property
counterexamples require adjudication on the pinned external source.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import subprocess
from time import perf_counter

INVENTORY = {
    "generated": {"testFuzz_SCMMultistepAllowance(uint96,uint96)",
                  "testFuzz_SCMRoundTrip(uint96)"},
    "matched_reference": {"testFuzz_ReferenceAllowance(uint96,uint96)",
                          "testFuzz_ReferenceRoundTrip(uint96)"},
    "stateful_reference": {"invariant_SupplyConsistentAcrossActions()"},
}
CONTRACT = {"generated": "D24CGeneratedAccountingTest",
            "matched_reference": "D24CIndependentReferenceTest",
            "stateful_reference": "D24CStatefulReferenceTest"}
PROPERTY_FAILURE_PREFIXES = (
    "D24C_", "D24C_REF_", "D24C_STATEFUL_"
)


def execute(root: Path, out: Path, mode: str, repeat: int) -> dict:
    if mode not in INVENTORY or repeat not in (0, 1):
        raise ValueError("unrecognized EVM experiment")
    env = dict(os.environ)
    env.update(FOUNDRY_FUZZ_RUNS="128", FOUNDRY_INVARIANT_RUNS="128",
               FOUNDRY_INVARIANT_DEPTH="48",
               FOUNDRY_INVARIANT_FAIL_ON_REVERT="true")
    args = ["forge", "test", "--match-contract", CONTRACT[mode], "--json"]
    start = perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    proc = subprocess.run(args, cwd=root, env=env, capture_output=True,
                          text=True, timeout=300, check=False)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall = perf_counter() - start
    stem = f"{mode}-{repeat}"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{stem}.stdout.json").write_text(proc.stdout)
    (out / f"{stem}.stderr.txt").write_text(proc.stderr)
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{stem}: no parseable forge JSON; exit={proc.returncode}; stderr={proc.stderr[-4000:]!r}; stdout={proc.stdout[:500]!r}") from exc
    received = {}
    for entry in raw.values():
        if isinstance(entry, dict):
            for key, result in entry.get("test_results", {}).items():
                if key in received:
                    raise RuntimeError("duplicate result name")
                received[key] = result
    if set(received) != INVENTORY[mode]:
        raise RuntimeError(f"{stem}: missing/extra tests: {list(received)}")
    outcomes = []
    for name, result in sorted(received.items()):
        status = result.get("status")
        reason = str(result.get("reason") or "")
        if status not in ("Success", "Failure"):
            raise RuntimeError(f"{stem}: invalid test status")
        if status == "Failure" and not any(x in reason for x in PROPERTY_FAILURE_PREFIXES):
            raise RuntimeError(f"{stem}: unrelated failure, not vulnerability: {reason[:180]}")
        outcomes.append({"name": name, "status": status, "reason": reason[:400],
                         "classification": "PROPERTY_COUNTEREXAMPLE_NEEDS_ADJUDICATION"
                         if status == "Failure" else "NO_COUNTEREXAMPLE_WITHIN_BUDGET"})
    if proc.returncode != 0 and not any(x["status"] == "Failure" for x in outcomes):
        raise RuntimeError(f"{stem}: failed forge process without property counterexample")
    if proc.returncode == 0 and any(x["status"] == "Failure" for x in outcomes):
        raise RuntimeError(f"{stem}: inconsistent exit status")
    return {"mode": mode, "repeat": repeat, "wall_seconds": wall,
            "child_cpu_seconds": ((after.ru_utime + after.ru_stime) -
                                  (before.ru_utime + before.ru_stime)),
            "child_max_rss_kib": after.ru_maxrss,
            "budget": {"fuzz_runs_per_test": 128, "invariant_runs": 128,
                       "invariant_depth": 48},
            "stdout_sha256": sha256(proc.stdout.encode()).hexdigest(),
            "outcomes": outcomes}


def evaluate(root: Path, abi: Path, proposals: Path, out: Path) -> dict:
    candidate = json.loads(proposals.read_text())
    if candidate.get("status") != "UNVERIFIED_CANDIDATES":
        raise ValueError("no frozen candidates")
    if candidate["abi_sha256"] != sha256(abi.read_bytes()).hexdigest():
        raise ValueError("wrong real ABI")
    if {x["id"] for x in candidate["candidates"]} != {
        "ALLOWANCE_SPEND_CONSERVATION", "TRANSFER_ROUNDTRIP_SUPPLY"}:
        raise ValueError("required generic external properties unavailable")
    report = {"schema": "prism-d24c-external-real-evm-v1",
              "status": "INCOMPLETE", "upstream":
              "scfuzzbench/origin-dollar-scfuzzbench",
              "upstream_sha": "299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4",
              "blind_holdout": False, "historical_bugs_tested": None,
              "true_positives": None, "false_positives": None,
              "false_negatives": None, "comparative_superiority": None,
              "runs": [], "limitations": [
                  "ABI-derived manually authored ERC20 templates, not financial semantic mining",
                  "No labeled historical security root cause was tested",
                  "Matching 128 runs is not proof of equal full CPU budget or identical input distribution",
                  "Stateful 128x48 trace budget is not matched to 128 single-test fuzz cases",
                  "Successful tests do not imply security and failures require independent adjudication",
                  "External source public, no sealed blind holdout",
              ]}
    try:
        for mode in INVENTORY:
            for repeat in (0, 1):
                run = execute(root, out, mode, repeat)
                report["runs"].append(run)
                print("D24C_RESULT", mode, repeat, round(run["wall_seconds"], 4),
                      [(v["name"], v["status"]) for v in run["outcomes"]])
        report["status"] = "REAL_EVM_MULTI_TX_COMPLETED_UNADJUDICATED"
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / "evaluation.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--abi", type=Path, required=True)
    p.add_argument("--proposals", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    x = p.parse_args()
    print("D24C_FINAL", evaluate(x.root, x.abi, x.proposals, x.out)["status"])
