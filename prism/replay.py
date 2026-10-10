"""Deterministic replay of finite PRISM observation traces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .reference import FiniteProblem, State


@dataclass(frozen=True)
class Step:
    observation_id: str
    value: str


@dataclass(frozen=True)
class Trace:
    steps: tuple[Step, ...]

    @classmethod
    def from_pairs(cls, pairs: Sequence[tuple[str, str]]) -> "Trace":
        return cls(tuple(Step(obs, value) for obs, value in pairs))


def replay(problem: FiniteProblem, trace: Trace) -> State:
    """Replay a trace exactly; invalid traces fail instead of being repaired."""
    state = problem.initial_state()
    for step in trace.steps:
        state = problem.apply(state, step.observation_id, step.value)
    return state
