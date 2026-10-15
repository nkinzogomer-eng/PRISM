"""Evaluate a policy against the oracle without leaking the hidden world.

Contract:
  - the policy sees only the declared problem and the answers it requests;
  - if an answer contradicts every declared hypothesis, PRISM abstains with
    `declared_class_contradicted` instead of certifying anything;
  - the cost of every executed operation is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from .generators import Generated
from .oracle import HiddenWorldOracle
from .reference import FiniteProblem, Result, State, certified_stop


@dataclass(frozen=True)
class Outcome:
    result: Result
    operations: tuple[str, ...]
    execution_cost: float
    verification_time_seconds: float = 0.0


def run_order(generated: Generated, order: list[str]) -> Outcome:
    problem: FiniteProblem = generated.declared
    oracle = HiddenWorldOracle(generated)
    state: State = problem.initial_state()
    executed: list[str] = []
    verification_time_seconds = 0.0

    def checked_stop() -> Result | None:
        nonlocal verification_time_seconds
        started = perf_counter()
        result = certified_stop(problem, state)
        verification_time_seconds += perf_counter() - started
        return result

    for obs_id in order:
        stop = checked_stop()
        if stop is not None:
            return Outcome(
                stop, tuple(executed), state.cost.execution,
                verification_time_seconds,
            )
        answer = oracle.observe(obs_id)
        executed.append(obs_id)
        survivors = [
            h for h in state.compatible
            if problem.hypotheses[h].observations[obs_id] == answer
        ]
        state = State(
            evidence={**state.evidence, obs_id: answer},
            compatible=frozenset(survivors),
            cost=state.cost.add(execution=problem.observations[obs_id].cost),
        )
        if not survivors:
            return Outcome(
                Result("ABSTAIN", None, None, state, "declared_class_contradicted"),
                tuple(executed), state.cost.execution, verification_time_seconds,
            )
    stop = checked_stop()
    if stop is not None:
        return Outcome(
            stop, tuple(executed), state.cost.execution,
            verification_time_seconds,
        )
    return Outcome(
        Result("ABSTAIN", None, None, state, "observations_exhausted"),
        tuple(executed), state.cost.execution, verification_time_seconds,
    )
