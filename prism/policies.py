"""Transparent policies for finite PRISM comparisons."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random

from .reference import FiniteProblem, Result, State, certified_stop


@dataclass(frozen=True)
class Run:
    result: Result
    operations: tuple[str, ...]


def _run(problem: FiniteProblem, hidden_id: str, order: list[str]) -> Run:
    state = problem.initial_state()
    operations = []
    for obs_id in order:
        stop = certified_stop(problem, state)
        if stop is not None:
            return Run(stop, tuple(operations))
        obs = problem.observations[obs_id]
        value = problem.hypotheses[hidden_id].observations[obs_id]
        state = problem.apply(state, obs_id, value)
        operations.append(obs_id)
    stop = certified_stop(problem, state)
    if stop is not None:
        return Run(stop, tuple(operations))
    return Run(Result("ABSTAIN", None, None, state, "observations_exhausted"), tuple(operations))


def fixed_cost(problem: FiniteProblem, hidden_id: str) -> Run:
    return _run(problem, hidden_id, sorted(problem.observations, key=lambda x: (problem.observations[x].cost, x)))


def random_order(problem: FiniteProblem, hidden_id: str, seed: int = 0) -> Run:
    order = list(problem.observations)
    Random(seed).shuffle(order)
    return _run(problem, hidden_id, order)


def decision_disagreement(problem: FiniteProblem, hidden_id: str) -> Run:
    """Greedy policy maximizing the number of distinct possible decisions."""
    state = problem.initial_state()
    operations = []
    while True:
        stop = certified_stop(problem, state)
        if stop is not None:
            return Run(stop, tuple(operations))
        available = [x for x in problem.observations if x not in state.evidence]
        if not available:
            return Run(Result("ABSTAIN", None, None, state, "observations_exhausted"), tuple(operations))
        def score(obs_id):
            obs = problem.observations[obs_id]
            groups = {}
            for h in state.compatible:
                value = problem.hypotheses[h].observations[obs_id]
                groups.setdefault(value, set()).add(problem.hypotheses[h].decision)
            return (sum(len(v) for v in groups.values()), -obs.cost, obs_id)
        obs_id = max(available, key=score)
        value = problem.hypotheses[hidden_id].observations[obs_id]
        state = problem.apply(state, obs_id, value)
        operations.append(obs_id)
