"""Auditable structural transformations for finite PRISM problems.

The first transformation quotients hypotheses that have identical observation
vectors AND the same decision. It preserves decision sets under every evidence
assignment, but it may change a uniform prior over hypotheses. Callers must not
use the quotient as a probability-preserving rewrite when duplicate hypotheses
carry distinct prior mass.
"""
from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from .reference import FiniteProblem, Hypothesis, Observation


@dataclass(frozen=True)
class DecisionEquivalenceQuotient:
    """A decision-preserving quotient plus an explicit scope of its guarantee."""

    problem: FiniteProblem
    original_to_representative: tuple[tuple[str, str], ...]
    original_hypothesis_count: int
    quotient_hypothesis_count: int
    transform_runtime_seconds: float
    preserves_decision_sets: bool
    preserves_uniform_hypothesis_prior: bool

    @property
    def removed_hypothesis_count(self) -> int:
        return self.original_hypothesis_count - self.quotient_hypothesis_count

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self.original_to_representative)


def decision_equivalence_quotient(
    problem: FiniteProblem,
) -> DecisionEquivalenceQuotient:
    """Merge only hypotheses identical in observations and target decision.

    The representative is the lexicographically smallest hypothesis ID in
    each equivalence class, making the transformation deterministic.

    Guarantee: for any evidence assignment, the set of possible decisions is
    unchanged. Non-guarantee: uniform probability over hypothesis IDs is not
    preserved if one class contains more than one original hypothesis.
    """
    started = perf_counter()
    groups: dict[tuple[tuple[tuple[str, str], ...], str], list[str]] = {}
    for hypothesis_id, hypothesis in problem.hypotheses.items():
        key = (tuple(sorted(hypothesis.observations.items())), hypothesis.decision)
        groups.setdefault(key, []).append(hypothesis_id)

    transformed_hypotheses = []
    mapping: list[tuple[str, str]] = []
    for (observation_items, decision), members in sorted(groups.items()):
        representative = min(members)
        transformed_hypotheses.append(
            Hypothesis(representative, dict(observation_items), decision)
        )
        mapping.extend((member, representative) for member in members)

    transformed_observations = [
        Observation(obs_id, observation.cost)
        for obs_id, observation in sorted(problem.observations.items())
    ]
    transformed = FiniteProblem(transformed_hypotheses, transformed_observations)
    original_count = len(problem.hypotheses)
    quotient_count = len(transformed.hypotheses)
    return DecisionEquivalenceQuotient(
        problem=transformed,
        original_to_representative=tuple(sorted(mapping)),
        original_hypothesis_count=original_count,
        quotient_hypothesis_count=quotient_count,
        transform_runtime_seconds=perf_counter() - started,
        preserves_decision_sets=True,
        preserves_uniform_hypothesis_prior=(original_count == quotient_count),
    )


def verify_decision_equivalence_quotient(
    original: FiniteProblem,
    quotient: DecisionEquivalenceQuotient,
) -> bool:
    """Independently check the quotient mapping and its claimed preservation.

    This structural check is sufficient because every original hypothesis is
    mapped to a representative with exactly the same observation vector and
    decision. It does not validate probability preservation.
    """
    transformed = quotient.problem
    mapping = quotient.mapping

    if len(mapping) != len(quotient.original_to_representative):
        return False
    if set(mapping) != set(original.hypotheses):
        return False
    if set(original.observations) != set(transformed.observations):
        return False
    for obs_id, observation in original.observations.items():
        if transformed.observations[obs_id].cost != observation.cost:
            return False

    representatives = set(transformed.hypotheses)
    if set(mapping.values()) != representatives:
        return False

    for original_id, representative_id in mapping.items():
        if representative_id not in transformed.hypotheses:
            return False
        source = original.hypotheses[original_id]
        target = transformed.hypotheses[representative_id]
        if source.decision != target.decision:
            return False
        if dict(source.observations) != dict(target.observations):
            return False

    if quotient.original_hypothesis_count != len(original.hypotheses):
        return False
    if quotient.quotient_hypothesis_count != len(transformed.hypotheses):
        return False
    if quotient.removed_hypothesis_count < 0:
        return False
    if quotient.preserves_decision_sets is not True:
        return False
    expected_prior_preservation = len(original.hypotheses) == len(transformed.hypotheses)
    if quotient.preserves_uniform_hypothesis_prior != expected_prior_preservation:
        return False
    return True
