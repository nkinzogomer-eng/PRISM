"""Exact expected-cost solver for finite deterministic PRISM instances.

This is a reference oracle for small instances, not a scalable planner.
The hidden hypothesis is represented by the current compatible set, so the
recursion is memoized over belief states and used-observation sets.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from math import inf

from .reference import FiniteProblem


@dataclass(frozen=True)
class Policy:
    observation_id: str | None
    branches: tuple[tuple[str, "Policy"], ...] = ()


@dataclass(frozen=True)
class OptimalResult:
    expected_cost: float
    policy: Policy | None


def solve_expected(problem: FiniteProblem) -> OptimalResult:
    ids = tuple(sorted(problem.hypotheses))
    observation_ids = tuple(sorted(problem.observations))

    @lru_cache(maxsize=None)
    def value(compatible: tuple[str, ...], used: tuple[str, ...]) -> tuple[float, Policy | None]:
        state = problem.initial_state()
        compatible_set = frozenset(compatible)
        state = state.__class__(evidence={}, compatible=compatible_set, cost=state.cost)
        if len(problem.decision_set(state)) <= 1:
            return 0.0, None

        available = [o for o in observation_ids if o not in used]
        if not available:
            return inf, None

        best_cost = inf
        best_policy = None
        for obs_id in available:
            obs = problem.observations[obs_id]
            values = sorted({problem.hypotheses[h].observations[obs_id] for h in compatible})
            expected = obs.cost
            branches = []
            for outcome in values:
                branch_ids = tuple(sorted(
                    h for h in compatible
                    if problem.hypotheses[h].observations[obs_id] == outcome
                ))
                branch_cost, branch_policy = value(branch_ids, tuple(sorted((*used, obs_id))))
                if branch_cost == inf:
                    expected = inf
                    break
                probability = len(branch_ids) / len(compatible)
                expected += probability * branch_cost
                branches.append((outcome, branch_policy or Policy(None)))
            if expected < best_cost:
                best_cost = expected
                best_policy = Policy(obs_id, tuple(branches))
        return best_cost, best_policy

    cost, policy = value(ids, ())
    return OptimalResult(cost, policy)
