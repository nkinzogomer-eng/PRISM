"""Reproducible synthetic comparison of PRISM observation policies.

Correctness and operation-cost results are deterministic for fixed seeds.
Wall-clock measurements are diagnostic and will vary by runner/hardware.
This is a finite synthetic benchmark, not evidence of real-world cyber efficacy.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict
from statistics import mean
from time import perf_counter

# Allow direct execution as `python scripts/run_comparison.py` from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prism.adaptive import Selection, run_adaptive
from prism.evaluation import evaluate_order_policy
from prism.generators import Generated, misspecified, parity, sparse_binary
from prism.optimal import solve_expected
from prism.policies import decision_disagreement, fixed_cost, random_order


def greedy_selector(problem, state, remaining):
    started = perf_counter()
    if not remaining:
        return None
    compatible = state.compatible

    def score(obs_id):
        groups = {}
        for hid in compatible:
            h = problem.hypotheses[hid]
            groups.setdefault(h.observations[obs_id], set()).add(h.decision)
        decision_separation = sum(len(decisions) for decisions in groups.values())
        cost = problem.observations[obs_id].cost
        return (decision_separation / max(cost, 1e-12), decision_separation, -cost, obs_id)

    chosen = max(remaining, key=score)
    planning_seconds = perf_counter() - started
    return Selection(chosen, planning_seconds)


def truth(generated: Generated) -> str:
    return generated.world_table[generated.hidden_id]["decision"]


def order_record(generated, policy_name, order_fn, run_id):
    started = perf_counter()
    metrics = evaluate_order_policy(
        generated,
        order_fn,
        policy=policy_name,
        run_id=run_id,
    )
    elapsed = perf_counter() - started
    return {
        "policy": policy_name,
        "status": metrics.status,
        "correct": metrics.correct_decision,
        "wrong_certificate": metrics.incorrect_non_abstention,
        "abstained": metrics.abstained,
        "execution_cost": metrics.costs.execution,
        "planning_seconds": metrics.costs.planning,
        "verification_seconds": metrics.costs.verification,
        "elapsed_seconds": elapsed,
    }


def adaptive_record(generated, run_id):
    started = perf_counter()
    outcome = run_adaptive(generated, greedy_selector)
    elapsed = perf_counter() - started
    certified = outcome.result.status == "CERTIFIED_DECISION"
    correct = outcome.result.decision == truth(generated) if certified else None
    return {
        "policy": "adaptive_greedy",
        "status": outcome.result.status,
        "correct": correct,
        "wrong_certificate": certified and correct is False,
        "abstained": outcome.result.status == "ABSTAIN",
        "execution_cost": outcome.result.state.cost.execution,
        "planning_seconds": outcome.result.state.cost.planning,
        "verification_seconds": None,
        "elapsed_seconds": elapsed,
    }


def summarize(records):
    count = len(records)
    def rate(predicate):
        return sum(bool(predicate(r)) for r in records) / count
    def avg(key):
        values = [r[key] for r in records if r[key] is not None]
        return mean(values) if values else None
    return {
        "runs": count,
        "certified_rate": rate(lambda r: r["status"] == "CERTIFIED_DECISION"),
        "correct_certified_rate": rate(lambda r: r["correct"] is True),
        "incorrect_certificate_rate": rate(lambda r: r["wrong_certificate"]),
        "abstention_rate": rate(lambda r: r["abstained"]),
        "mean_execution_cost_units": avg("execution_cost"),
        "mean_planning_seconds": avg("planning_seconds"),
        "mean_verification_seconds": avg("verification_seconds"),
        "mean_elapsed_seconds": avg("elapsed_seconds"),
    }


def build_report(runs: int):
    records = defaultdict(list)
    exact = defaultdict(list)
    families = []

    for seed in range(runs):
        families.append(("sparse_binary", f"seed-{seed}", sparse_binary(seed=seed, n=4, support=2)))
        families.append(("misspecified", f"seed-{seed}", misspecified(seed=seed, n=3, support=2)))
    families.append(("parity_control", "fixed-parity-n4", parity(n=4)))

    for family, run_id, generated in families:
        policies = [
            ("fixed_cost", fixed_cost),
            ("random_order", lambda view, seed=int(run_id.split("-")[-1]) if run_id.startswith("seed-") else 0: random_order(view, seed=seed)),
            ("decision_disagreement_order", decision_disagreement),
        ]
        for name, policy_fn in policies:
            records[(family, name)].append(order_record(generated, name, policy_fn, f"{family}:{run_id}"))
        records[(family, "adaptive_greedy")].append(adaptive_record(generated, f"{family}:{run_id}"))

        # Exact solver cost is comparable only under the declared-class model.
        # Misspecified worlds are intentionally excluded from this reference.
        if family != "misspecified":
            started = perf_counter()
            optimum = solve_expected(generated.declared)
            exact[family].append({
                "expected_execution_cost_units": optimum.expected_cost,
                "solver_runtime_seconds": perf_counter() - started,
            })

    summary = {}
    for (family, policy), rows in sorted(records.items()):
        summary.setdefault(family, {})[policy] = summarize(rows)
    exact_summary = {
        family: {
            "runs": len(rows),
            "mean_expected_execution_cost_units": mean(r["expected_execution_cost_units"] for r in rows),
            "mean_solver_runtime_seconds": mean(r["solver_runtime_seconds"] for r in rows),
            "note": "Exact cost is model-relative expected execution cost; solver runtime is measured separately."
        }
        for family, rows in exact.items()
    }
    return {
        "title": "PRISM finite synthetic policy comparison",
        "seed_policy": f"integer seeds 0..{runs - 1}; parity control has fixed hidden world",
        "runs_per_seeded_family": runs,
        "families": summary,
        "exact_reference": exact_summary,
        "interpretation_limits": [
            "Synthetic finite deterministic instances only; no external-world or real vulnerability claims.",
            "A declared-class certificate can be wrong when the true world is omitted; this is scored separately.",
            "Execution cost is the generator's abstract operation-cost unit, not wall-clock seconds.",
            "Planning, verification, and elapsed seconds are hardware/runner dependent.",
            "The exact solver is an expected execution-cost reference under the declared model; its planning/runtime is reported separately."
        ]
    }


def markdown(report):
    lines = [
        "# PRISM finite synthetic policy comparison",
        "",
        f"- Seed policy: {report['seed_policy']}",
        f"- Runs per seeded family: {report['runs_per_seeded_family']}",
        "- Synthetic finite deterministic tasks only; not evidence of real-world cyber efficacy.",
        "",
        "| Family | Policy | Runs | Certified | Correct certified | Wrong certificate | Abstention | Mean execution cost (units) | Mean planning (s) | Mean elapsed (s) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for family, policies in report["families"].items():
        for policy, s in policies.items():
            fmt = lambda x: "n/a" if x is None else f"{x:.6f}"
            lines.append(
                f"| {family} | {policy} | {s['runs']} | {s['certified_rate']:.3f} | "
                f"{s['correct_certified_rate']:.3f} | {s['incorrect_certificate_rate']:.3f} | "
                f"{s['abstention_rate']:.3f} | {fmt(s['mean_execution_cost_units'])} | "
                f"{fmt(s['mean_planning_seconds'])} | {fmt(s['mean_elapsed_seconds'])} |"
            )
    lines += ["", "## Exact reference (declared model only)", "",
              "| Family | Runs | Mean expected execution cost (units) | Mean solver runtime (s) |",
              "|---|---:|---:|---:|"]
    for family, s in report["exact_reference"].items():
        lines.append(
            f"| {family} | {s['runs']} | {s['mean_expected_execution_cost_units']:.6f} | "
            f"{s['mean_solver_runtime_seconds']:.6f} |"
        )
    lines += ["", "## Interpretation limits", ""]
    lines.extend(f"- {item}" for item in report["interpretation_limits"])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=20, help="number of fixed seeds per seeded family")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of Markdown")
    args = parser.parse_args()
    if args.runs < 1 or args.runs > 200:
        parser.error("--runs must be between 1 and 200")
    report = build_report(args.runs)
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else markdown(report))


if __name__ == "__main__":
    main()
