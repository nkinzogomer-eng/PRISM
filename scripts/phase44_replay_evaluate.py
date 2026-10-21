#!/usr/bin/env python3
"""After-only benchmark label comparison of a controlled CWE22 runtime probe.

Missing observations are NEVER negative verdicts. Labels may be contested;
do not market replay-to-synthetic-sentinel as an exploitable critical flaw.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in ("", None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.score_phase4 import read_labels


def evaluate(replay: dict, labels_path: Path) -> dict:
    labels = read_labels(labels_path)
    if replay.get("tested") != len(replay.get("cases", {})):
        raise ValueError("partial replay ledger")
    tp = label_disagreement = unknown = not_observed = 0
    outside_target_scope = 0
    outside_scope_observed = 0
    categories = set()
    per_case = {}
    for case, result in replay["cases"].items():
        if case not in labels:
            raise ValueError("unlabelled test case")
        category, truth = labels[case]
        categories.add(category)
        proof = result["status"] == "verified_sandbox_path_escape"
        if proof and not result["verified_outside_root"]:
            raise ValueError("unjustified verification")
        if proof:
            evidence = result.get("operations") or []
            allowed = {"builtin_open", "codecs_open", "pathlib_open",
                       "pathlib_exists", "os_path_exists", "synthetic_sentinel_changed"}
            if not any(
                item.get("operation") in allowed
                and item.get("completed") is True
                and item.get("outside_allowed") is True
                and item.get("inside_temporary_sandbox") is True
                and str(item.get("path", "")).startswith("<TEMP>/SCM44_WITNESS_")
                for item in evidence
            ):
                raise ValueError("insufficient controlled filesystem evidence for claimed proof")
        if category != "pathtraver":
            outside_target_scope += 1
            if proof:
                outside_scope_observed += 1
        elif proof:
            if truth:
                tp += 1
            else:
                label_disagreement += 1
        elif result["status"] == "unknown":
            unknown += 1
        else:
            not_observed += 1
        per_case[case] = {
            "reference_label": truth, "runtime_status": result["status"],
            "observed_escape": proof,
            "adjudication": ("replayed" if proof else "unresolved"),
        }
    total_true = sum(
        bool(label[1]) for name, label in labels.items() if label[0] == "pathtraver")
    return {
        "phase": "4.4B",
        "scope": "CWE-22 controlled sentinel path escape, not full security proof",
        "evaluated_replay_count": len(replay["cases"]),
        "selection_mode": replay.get("selection_mode", "legacy_route_hint"),
        "selection_uses_benchmark_category_hint": replay.get(
            "selection_uses_benchmark_category_hint", True),
        "selected_outside_CWE22_category": outside_target_scope,
        "sandbox_escapes_outside_CWE22_category": outside_scope_observed,
        "pathtraver_expected_positive_count": total_true,
        "matched_positive_replay_count": tp,
        "replayed_but_labelled_negative": label_disagreement,
        "runtime_unknown": unknown,
        "single_probe_no_escape_observed": not_observed,
        "developer_label_positive_capture_lower_bound":
            tp / total_true if total_true else None,
        "benchmark_label_is_not_ground_truth": True,
        "independent_holdout_consumed": False,
        "goal_8_of_10_real_critical_vulnerabilities": "NOT VALIDATED",
        "comparison_caveat": (
            "A local path-escape witness is stronger than a static alert but "
            "does not prove a real-world critical vulnerability or normal "
            "user accessibility. Missing a witness on one payload is UNKNOWN, "
            "never certified safe."),
        "per_case": per_case,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = evaluate(json.loads(args.replay.read_text(encoding="utf-8")),
                       args.labels)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True)+"\n",
                           encoding="utf-8")
    print("CONTROLLED REPLAY LABEL AGREEMENT (development, disputed reference):")
    print({k: summary[k] for k in (
        "evaluated_replay_count", "selection_mode",
        "selected_outside_CWE22_category",
        "sandbox_escapes_outside_CWE22_category",
        "pathtraver_expected_positive_count",
        "matched_positive_replay_count", "replayed_but_labelled_negative",
        "runtime_unknown", "single_probe_no_escape_observed",
        "developer_label_positive_capture_lower_bound")})
    print("NO statement of critical real-world vulnerability count")


if __name__ == "__main__":
    main()
