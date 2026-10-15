"""Shared finite benchmark execution across order-based policies."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from .evaluation import PolicySummary, RunMetrics, evaluate_order_policy, summarize_policy
from .generators import Generated


OrderPolicy = Callable[[Generated], list[str]]


def run_policy_suite(
    instances: Sequence[tuple[str, Generated]],
    policies: Mapping[str, OrderPolicy],
) -> dict[str, PolicySummary]:
    """Run every order policy on the same completed benchmark instances.

    Policy callbacks receive only the sanitized public view assembled by
    `evaluate_order_policy`. The original generated instance is used by the
    oracle and by the evaluator after the policy has returned its order.
    """
    if not instances:
        raise ValueError("at least one benchmark instance is required")
    if not policies:
        raise ValueError("at least one policy is required")
    run_ids = [run_id for run_id, _ in instances]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("benchmark run ids must be unique")

    summaries: dict[str, PolicySummary] = {}
    for policy_name, policy_function in policies.items():
        records: list[RunMetrics] = []
        for run_id, generated in instances:
            records.append(evaluate_order_policy(
                generated,
                policy_function,
                policy=policy_name,
                run_id=run_id,
            ))
        summaries[policy_name] = summarize_policy(records)
    return summaries
