"""Measure a decision-equivalence quotient on seeded redundant finite problems."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from random import Random
from statistics import mean
from time import perf_counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prism.adaptive import Selection, run_adaptive
from prism.evaluation import evaluate_order_policy
from prism.generators import Generated
from prism.policies import decision_disagreement, fixed_cost, random_order
from prism.optimal import solve_expected
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.transformations import (
    decision_equivalence_quotient,
    verify_decision_equivalence_quotient,
    prune_dominated_observations,
    verify_dominated_observation_pruning,
)


def redundant_instance(seed: int) -> Generated:
    rows = []
    for mask in range(8):
        observations = {f"x{i}": str((mask >> i) & 1) for i in range(3)}
        decision = str(((mask >> 0) & 1) ^ ((mask >> 1) & 1))
        rows.append((f"h{mask:03b}", observations, decision))
    base = rows[0]
    rows.extend([
        ("h000-copy1", dict(base[1]), base[2]),
        ("h000-copy2", dict(base[1]), base[2]),
    ])
    world_table = {
        hid: {"observations": dict(values), "decision": decision}
        for hid, values, decision in rows
    }
    hypotheses = [Hypothesis(hid, values, decision) for hid, values, decision in rows]
    observations = [Observation("x0", 1.0), Observation("x1", 2.0), Observation("x2", 1.0)]
    return Generated(
        FiniteProblem(hypotheses, observations),
        world_table,
        Random(seed).choice(list(world_table)),
    )


def selector(problem, state, remaining):
    started = perf_counter()
    if not remaining:
        return None
    def score(obs_id):
        groups = {}
        for hid in state.compatible:
            hypothesis = problem.hypotheses[hid]
            groups.setdefault(hypothesis.observations[obs_id], set()).add(hypothesis.decision)
        separation = sum(len(decisions) for decisions in groups.values())
        cost = problem.observations[obs_id].cost
        return (separation / max(cost, 1e-12), separation, -cost, obs_id)
    chosen = max(remaining, key=score)
    return Selection(chosen, perf_counter() - started)


def record(generated, policy_name, policy_fn, run_id):
    started = perf_counter()
    metrics = evaluate_order_policy(
        generated, policy_fn, policy=policy_name, run_id=run_id
    )
    return {
        "correct": metrics.correct_decision is True,
        "wrong_certificate": metrics.incorrect_non_abstention,
        "execution_cost": metrics.costs.execution,
        "planning_seconds": metrics.costs.planning,
        "elapsed_seconds": perf_counter() - started,
    }


def adaptive_record(generated):
    started = perf_counter()
    outcome = run_adaptive(generated, selector)
    certified = outcome.result.status == "CERTIFIED_DECISION"
    actual = generated.world_table[generated.hidden_id]["decision"]
    return {
        "correct": certified and outcome.result.decision == actual,
        "wrong_certificate": certified and outcome.result.decision != actual,
        "execution_cost": outcome.result.state.cost.execution,
        "planning_seconds": outcome.result.state.cost.planning,
        "elapsed_seconds": perf_counter() - started,
    }


def summary(rows):
    return {
        "runs": len(rows),
        "correct_certificate_rate": mean(float(r["correct"]) for r in rows),
        "wrong_certificate_rate": mean(float(r["wrong_certificate"]) for r in rows),
        "mean_execution_cost_units": mean(r["execution_cost"] for r in rows),
        "mean_planning_seconds": mean(r["planning_seconds"] for r in rows),
        "mean_elapsed_seconds": mean(r["elapsed_seconds"] for r in rows),
    }


def run(runs):
    before = {name: [] for name in ("fixed_cost", "decision_disagreement", "random_order", "adaptive_greedy")}
    after = {name: [] for name in before}
    transform_times = []
    original_counts = []
    quotient_counts = []
    checks = []

    for seed in range(runs):
        original = redundant_instance(seed)
        quotient = decision_equivalence_quotient(original.declared)
        checks.append(verify_decision_equivalence_quotient(original.declared, quotient))
        transform_times.append(quotient.transform_runtime_seconds)
        original_counts.append(quotient.original_hypothesis_count)
        quotient_counts.append(quotient.quotient_hypothesis_count)
        transformed = Generated(quotient.problem, original.world_table, original.hidden_id)
        policies = {
            "fixed_cost": fixed_cost,
            "decision_disagreement": decision_disagreement,
            "random_order": lambda view, seed=seed: random_order(view, seed=seed),
        }
        for name, fn in policies.items():
            before[name].append(record(original, name, fn, f"before-{seed}"))
            after[name].append(record(transformed, name, fn, f"after-{seed}"))
        before["adaptive_greedy"].append(adaptive_record(original))
        after["adaptive_greedy"].append(adaptive_record(transformed))

    return {
        "runs": runs,
        "mean_original_hypotheses": mean(original_counts),
        "mean_quotient_hypotheses": mean(quotient_counts),
        "mean_hypothesis_reduction_fraction": mean(
            (a - b) / a for a, b in zip(original_counts, quotient_counts)
        ),
        "mean_transform_runtime_seconds": mean(transform_times),
        "all_independent_checks_passed": all(checks),
        "preserves_decision_sets": True,
        "preserves_uniform_hypothesis_prior": False,
        "before": {name: summary(rows) for name, rows in before.items()},
        "after": {name: summary(rows) for name, rows in after.items()},
        "limits": [
            "Synthetic redundant finite instances only.",
            "The quotient preserves decision sets, not a uniform prior over hypothesis IDs.",
            "Execution cost is an abstract operation-cost unit; timing is runner-dependent.",
            "This experiment measures one narrow transformation, not general SCM superiority."
        ]
    }


def dominated_observation_instance(seed: int) -> Generated:
    rows = []
    for first in ("0", "1"):
        for second in ("0", "1"):
            rich = first + second
            rows.append((f"h{rich}", {"rich": rich, "coarse": first}, second))
    table = {
        hid: {"observations": dict(values), "decision": decision}
        for hid, values, decision in rows
    }
    problem = FiniteProblem(
        [Hypothesis(hid, values, decision) for hid, values, decision in rows],
        [Observation("rich", 1.0), Observation("coarse", 2.0)],
    )
    return Generated(problem, table, Random(seed).choice(list(table)))


def benchmark_dominated_pruning(runs: int):
    original_counts = []
    retained_counts = []
    transform_times = []
    checks = []
    before_costs = []
    after_costs = []
    for seed in range(runs):
        generated = dominated_observation_instance(seed)
        pruning = prune_dominated_observations(generated.declared)
        checks.append(verify_dominated_observation_pruning(generated.declared, pruning))
        original_counts.append(pruning.original_observation_count)
        retained_counts.append(pruning.retained_observation_count)
        transform_times.append(pruning.transform_runtime_seconds)
        before_costs.append(solve_expected(generated.declared).expected_cost)
        after_costs.append(solve_expected(pruning.problem).expected_cost)
    return {
        "runs": runs,
        "mean_original_observations": mean(original_counts),
        "mean_retained_observations": mean(retained_counts),
        "mean_observation_reduction_fraction": mean(
            (a - b) / a for a, b in zip(original_counts, retained_counts)
        ),
        "mean_transform_runtime_seconds": mean(transform_times),
        "all_independent_checks_passed": all(checks),
        "mean_exact_expected_cost_before": mean(before_costs),
        "mean_exact_expected_cost_after": mean(after_costs),
        "uniform_hypothesis_prior_preserved": True,
        "optimal_expected_cost_preserved": all(
            abs(before - after) < 1e-12
            for before, after in zip(before_costs, after_costs)
        ),
        "note": "Synthetic case where a cheaper rich observation determines a more expensive coarse observation."
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    if not 1 <= args.runs <= 200:
        parser.error("--runs must be between 1 and 200")
    result = run(args.runs)
    result["dominated_observation_pruning"] = benchmark_dominated_pruning(args.runs)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
