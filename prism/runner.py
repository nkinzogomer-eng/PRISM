"""Evaluate a policy against the oracle without leaking the hidden world.

Contract:
  - the policy sees only the declared problem and the answers it requests;
  - if an answer contradicts every declared hypothesis, PRISM abstains with
    `declared_class_contradicted` instead of certifying anything;
  - the cost of every executed operation is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass

from .generators import Generated
from .oracle import HiddenWorldOracle
from .reference import FiniteProblem, Result, State, certified_stop


@dataclass(frozen=True)
class Outcome:
    result: Result
    operations: tuple[str, ...]
    execution_cost: float


def run_order(generated: Generated, order: list[str]) -> Outcome:
    problem: FiniteProblem = generated.declared
    oracle = HiddenWorldOracle(generated)
    state: State = problem.initial_state()
    executed: list[str] = []
    for obs_id in order:
        stop = certified_stop(problem, state)
        if stop is not None:
            return Outcome(stop, tuple(executed), state.cost.execution)
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
                tuple(executed), state.cost.execution,
            )
    stop = certified_stop(problem, state)
    if stop is not None:
        return Outcome(stop, tuple(executed), state.cost.execution)
    return Outcome(
        Result("ABSTAIN", None, None, state, "observations_exhausted"),
        tuple(executed), state.cost.execution,
    )
