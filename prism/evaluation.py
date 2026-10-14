"""Component-wise benchmark accounting for finite PRISM runs.

This module is evaluation-only: it does not influence selectors, stopping, or
the exact solver. Hidden-world labels are read only while scoring a completed
run. Costs with different units are reported as a vector unless a benchmark
supplies an explicit scalarization.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from math import isfinite
from typing import ClassVar, Sequence

from .generators import Generated
from .runner import Outcome


@dataclass(frozen=True)
class CostVector:
    """Per-run costs; None means unavailable or not measured, never zero.

    Planning is required so a policy cannot silently receive free planning.
    Execution is taken from the completed runner outcome.
    """

    planning: float
    execution: float
    verification: float | None = None
    representation: float | None = None
    preprocessing: float | None = None
    memory: float | None = None
    communication: float | None = None

    COMPONENTS: ClassVar[tuple[str, ...]] = (
        "planning", "execution", "verification", "representation",
        "preprocessing", "memory", "communication",
    )

    def __post_init__(self) -> None:
        for name in self.COMPONENTS:
            value = getattr(self, name)
            if value is not None and (not isfinite(value) or value < 0):
                raise ValueError(f"{name} cost must be finite and nonnegative")

    def weighted_total(self, weights: dict[str, float]) -> float:
        """Scalarize only when the benchmark explicitly supplies every weight."""
        if set(weights) != set(self.COMPONENTS):
            raise ValueError("weights must specify every cost component")
        if any(not isfinite(weight) or weight < 0 for weight in weights.values()):
            raise ValueError("weights must be finite and nonnegative")
        if any(getattr(self, name) is None for name in self.COMPONENTS):
            raise ValueError("cannot scalarize a cost vector with unmeasured components")
        return sum(getattr(self, name) * weights[name] for name in self.COMPONENTS)


@dataclass(frozen=True)
class RunMetrics:
    policy: str
    run_id: str
    status: str
    decision: str | None
    correct_decision: bool | None
    incorrect_non_abstention: bool
    abstained: bool
    correct_abstention: bool
    costs: CostVector


@dataclass(frozen=True)
class CostSummary:
    cold_start: CostVector
    amortized: CostVector
    tail: CostVector


@dataclass(frozen=True)
class PolicySummary:
    policy: str
    runs: int
    certified_decision_rate: float
    incorrect_non_abstention_rate: float
    abstention_rate: float
    correct_abstention_rate: float
    invalid_instances: int
    costs: CostSummary


def score_run(
    generated: Generated,
    outcome: Outcome,
    *,
    policy: str,
    run_id: str,
    costs: CostVector,
) -> RunMetrics:
    """Score a completed run against hidden truth and attach its measured costs."""
    result = outcome.result
    certified = result.status == "CERTIFIED_DECISION"
    abstained = result.status == "ABSTAIN"
    correct = (
        result.decision == generated.world_table[generated.hidden_id]["decision"]
        if certified else None
    )
    decision_set = generated.declared.decision_set(result.state)
    correct_abstention = abstained and (
        not result.state.compatible or len(decision_set) != 1
    )
    # The solver's actual recorded execution cost is authoritative, preventing
    # the evaluator from accidentally accepting a caller's free/understated run.
    recorded_costs = replace(costs, execution=outcome.execution_cost)
    return RunMetrics(
        policy=policy,
        run_id=run_id,
        status=result.status,
        decision=result.decision,
        correct_decision=correct,
        incorrect_non_abstention=certified and correct is False,
        abstained=abstained,
        correct_abstention=correct_abstention,
        costs=recorded_costs,
    )


def _aggregate_component(records: Sequence[RunMetrics], name: str, mode: str) -> float | None:
    values = [getattr(record.costs, name) for record in records]
    if any(value is None for value in values):
        return None
    measured = [value for value in values if value is not None]
    if mode == "mean":
        return sum(measured) / len(measured)
    if mode == "max":
        return max(measured)
    raise ValueError(mode)


def summarize_policy(records: Sequence[RunMetrics]) -> PolicySummary:
    """Summarize one policy; the first record is its cold-start run."""
    if not records:
        raise ValueError("at least one run is required")
    policy = records[0].policy
    if any(record.policy != policy for record in records):
        raise ValueError("all records must belong to one policy")
    if len({record.run_id for record in records}) != len(records):
        raise ValueError("run_id values must be unique within a policy")

    def vector(mode: str) -> CostVector:
        values = {
            name: _aggregate_component(records, name, mode)
            for name in CostVector.COMPONENTS
        }
        return CostVector(**values)

    count = len(records)
    certified = sum(record.correct_decision is not None for record in records)
    return PolicySummary(
        policy=policy,
        runs=count,
        certified_decision_rate=certified / count,
        incorrect_non_abstention_rate=sum(
            record.incorrect_non_abstention for record in records
        ) / count,
        abstention_rate=sum(record.abstained for record in records) / count,
        correct_abstention_rate=sum(
            record.correct_abstention for record in records
        ) / count,
        invalid_instances=sum(record.status == "INVALID_INSTANCE" for record in records),
        costs=CostSummary(
            cold_start=records[0].costs,
            amortized=vector("mean"),
            tail=vector("max"),
        ),
    )
