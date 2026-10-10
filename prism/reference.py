"""Small, dependency-free reference semantics for PRISM.

This is intentionally not optimized. Its job is to make the contract executable
and auditable on finite deterministic hypothesis spaces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Mapping, Sequence


@dataclass(frozen=True)
class Hypothesis:
    id: str
    observations: Mapping[str, str]
    decision: str


@dataclass(frozen=True)
class Observation:
    id: str
    cost: float


@dataclass(frozen=True)
class Cost:
    planning: float = 0.0
    execution: float = 0.0
    verification: float = 0.0
    representation: float = 0.0
    preprocessing: float = 0.0

    @property
    def scalar(self) -> float:
        return sum((self.planning, self.execution, self.verification,
                    self.representation, self.preprocessing))

    def add(self, **delta: float) -> "Cost":
        values = {name: getattr(self, name) for name in self.__dataclass_fields__}
        for name, value in delta.items():
            values[name] += value
        return Cost(**values)


@dataclass(frozen=True)
class State:
    evidence: Mapping[str, str]
    compatible: FrozenSet[str]
    cost: Cost = field(default_factory=Cost)


@dataclass(frozen=True)
class Certificate:
    hypothesis_ids: tuple[str, ...]
    evidence: tuple[tuple[str, str], ...]
    decision: str


@dataclass(frozen=True)
class Result:
    status: str
    decision: str | None
    certificate: Certificate | None
    state: State
    reason: str | None = None


class FiniteProblem:
    """Explicit deterministic problem used by the reference kernel."""

    def __init__(self, hypotheses: Sequence[Hypothesis], observations: Sequence[Observation]):
        if not hypotheses:
            raise ValueError("hypotheses must not be empty")
        ids = [h.id for h in hypotheses]
        if len(ids) != len(set(ids)):
            raise ValueError("hypothesis ids must be unique")
        obs_ids = [o.id for o in observations]
        if len(obs_ids) != len(set(obs_ids)):
            raise ValueError("observation ids must be unique")
        by_id = {h.id: h for h in hypotheses}
        for h in hypotheses:
            missing = {o.id for o in observations} - set(h.observations)
            if missing:
                raise ValueError(f"hypothesis {h.id} lacks observations: {missing}")
        self.hypotheses = by_id
        self.observations = {o.id: o for o in observations}

    def initial_state(self) -> State:
        return State(evidence={}, compatible=frozenset(self.hypotheses))

    def apply(self, state: State, observation_id: str, value: str) -> State:
        if observation_id not in self.observations:
            raise KeyError(observation_id)
        if observation_id in state.evidence:
            raise ValueError("an observation may only be executed once")
        compatible = frozenset(
            h_id for h_id in state.compatible
            if self.hypotheses[h_id].observations[observation_id] == value
        )
        obs = self.observations[observation_id]
        return State(
            evidence={**state.evidence, observation_id: value},
            compatible=compatible,
            cost=state.cost.add(execution=obs.cost),
        )

    def decision_set(self, state: State) -> FrozenSet[str]:
        return frozenset(self.hypotheses[h].decision for h in state.compatible)

    def certificate(self, state: State) -> Certificate | None:
        decisions = self.decision_set(state)
        if len(state.compatible) == 0 or len(decisions) != 1:
            return None
        decision = next(iter(decisions))
        return Certificate(
            hypothesis_ids=tuple(sorted(state.compatible)),
            evidence=tuple(sorted(state.evidence.items())),
            decision=decision,
        )

    def verify(self, certificate: Certificate) -> bool:
        if not certificate.hypothesis_ids:
            return False
        if any(h_id not in self.hypotheses for h_id in certificate.hypothesis_ids):
            return False
        compatible = {
            h_id for h_id, h in self.hypotheses.items()
            if all(h.observations[k] == v for k, v in certificate.evidence)
        }
        if compatible != set(certificate.hypothesis_ids):
            return False
        decisions = {self.hypotheses[h].decision for h in compatible}
        return decisions == {certificate.decision}


def certified_stop(problem: FiniteProblem, state: State) -> Result | None:
    certificate = problem.certificate(state)
    if certificate is None:
        return None
    if not problem.verify(certificate):
        return Result("INVALID_INSTANCE", None, None, state, "verifier rejected internal certificate")
    return Result("CERTIFIED_DECISION", certificate.decision, certificate, state)


def abstain(problem: FiniteProblem, state: State, reason: str) -> Result:
    return Result("ABSTAIN", None, None, state, reason)
