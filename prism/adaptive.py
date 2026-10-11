"""Adaptive finite reference runner for PRISM.

Unlike the legacy order-based runner, this loop asks the selector for exactly
one next operation after each real observation. The selector receives only the
declared problem, the current evidence state, and remaining operation IDs.

Planning cost is explicit per selection. This module is intentionally separate
from the legacy runner so existing experiments remain reproducible.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Callable

from .generators import Generated
from .oracle import HiddenWorldOracle
from .reference import FiniteProblem, Result, State, certified_stop


@dataclass(frozen=True)
class Selection:
    """One adaptive choice and the measured cost of making that choice."""

    observation_id: str
    planning_cost: float


Selector = Callable[[FiniteProblem, State, frozenset[str]], Selection | None]


@dataclass(frozen=True)
class AdaptiveOutcome:
    result: Result
    operations: tuple[str, ...]


def run_adaptive(generated: Generated, selector: Selector) -> AdaptiveOutcome:
    """Run a state-dependent selector without exposing the hidden world.

    The selector is called after every observation. It must report nonnegative,
    finite planning cost for each choice. Returning None means the selector
    cannot justify another operation, so the runner abstains rather than
    silently certifying or pretending the remaining operations are free.
    """
    problem: FiniteProblem = generated.declared
    oracle = HiddenWorldOracle(generated)
    state = problem.initial_state()
    executed: list[str] = []
    remaining = frozenset(problem.observations)

    while True:
        stop = certified_stop(problem, state)
        if stop is not None:
            return AdaptiveOutcome(stop, tuple(executed))

        selection = selector(problem, state, remaining)
        if selection is None:
            return AdaptiveOutcome(
                Result("ABSTAIN", None, None, state, "no_operation_selected"),
                tuple(executed),
            )

        if not isfinite(selection.planning_cost) or selection.planning_cost < 0:
            return AdaptiveOutcome(
                Result("INVALID_INSTANCE", None, None, state, "invalid_planning_cost"),
                tuple(executed),
            )
        if selection.observation_id not in remaining:
            return AdaptiveOutcome(
                Result("INVALID_INSTANCE", None, None, state, "operation_not_available"),
                tuple(executed),
            )

        state = State(
            evidence=state.evidence,
            compatible=state.compatible,
            cost=state.cost.add(planning=selection.planning_cost),
        )
        answer = oracle.observe(selection.observation_id)
        state = problem.apply(state, selection.observation_id, answer)
        executed.append(selection.observation_id)
        remaining = remaining - {selection.observation_id}

        if not state.compatible:
            return AdaptiveOutcome(
                Result(
                    "ABSTAIN", None, None, state,
                    "declared_class_contradicted",
                ),
                tuple(executed),
            )
        if not remaining:
            stop = certified_stop(problem, state)
            if stop is not None:
                return AdaptiveOutcome(stop, tuple(executed))
            return AdaptiveOutcome(
                Result("ABSTAIN", None, None, state, "observations_exhausted"),
                tuple(executed),
            )
