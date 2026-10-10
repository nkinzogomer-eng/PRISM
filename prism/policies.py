"""Transparent policies for finite PRISM comparisons.

Each policy returns an observation order. The runner then executes that order
against the oracle, so no policy can read the hidden answer.
"""

from __future__ import annotations

from random import Random

from .generators import Generated


def fixed_cost(g: Generated) -> list[str]:
    obs = g.declared.observations
    return sorted(obs, key=lambda x: (obs[x].cost, x))


def random_order(g: Generated, seed: int = 0) -> list[str]:
    order = sorted(g.declared.observations)
    Random(seed).shuffle(order)
    return order


def decision_disagreement(g: Generated) -> list[str]:
    """Greedy ordering: at each step prefer the observation whose outcome groups
    keep the most distinct decisions, computed from declared information only.
    Ordering heuristic only; certification is done by the runner, never here."""
    problem = g.declared
    compatible = set(problem.hypotheses)
    remaining = set(problem.observations)
    order: list[str] = []
    while remaining and len({problem.hypotheses[h].decision for h in compatible}) > 1:
        def score(o):
            groups: dict[str, set[str]] = {}
            for h in compatible:
                groups.setdefault(problem.hypotheses[h].observations[o], set()).add(
                    problem.hypotheses[h].decision)
            return (sum(len(v) for v in groups.values()), -problem.observations[o].cost, o)
        best = max(remaining, key=score)
        order.append(best)
        remaining.discard(best)
        # Ordering approximation: follow the largest surviving group.
        groups: dict[str, set[str]] = {}
        for h in compatible:
            groups.setdefault(problem.hypotheses[h].observations[best], set()).add(h)
        compatible = max(groups.values(), key=len)
    order.extend(sorted(remaining))
    return order
