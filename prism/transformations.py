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

@dataclass(frozen=True)
class DominatedObservationPruning:
    """Remove observations dominated by a no-more-expensive richer observation."""

    problem: FiniteProblem
    retained_observation_ids: tuple[str, ...]
    removed_by: tuple[tuple[str, str], ...]
    original_observation_count: int
    retained_observation_count: int
    transform_runtime_seconds: float
    preserves_decision_semantics: bool
    preserves_uniform_hypothesis_prior: bool
    preserves_optimal_expected_cost: bool

    @property
    def removed_observation_count(self) -> int:
        return self.original_observation_count - self.retained_observation_count

    @property
    def dominators(self) -> dict[str, str]:
        return dict(self.removed_by)


def _observation_determines(problem: FiniteProblem, source_id: str, target_id: str) -> bool:
    """True when equal source values always imply equal target values."""
    hypotheses = list(problem.hypotheses.values())
    for left in hypotheses:
        for right in hypotheses:
            if (
                left.observations[source_id] == right.observations[source_id]
                and left.observations[target_id] != right.observations[target_id]
            ):
                return False
    return True


def prune_dominated_observations(
    problem: FiniteProblem,
) -> DominatedObservationPruning:
    """Remove B only if a retained A determines B and costs no more.

    If A determines B, querying A provides at least the information in B. If
    cost(A) <= cost(B), any policy using B can be simulated by querying A,
    deriving B's value, and exploiting any extra information from A. Thus the
    optimal expected execution cost under the same hypothesis distribution
    cannot increase. Equal-cost equivalent observations are resolved
    deterministically by lexicographic ID order.

    This transformation keeps every hypothesis and its multiplicity, so it
    preserves a uniform prior over hypothesis IDs.
    """
    started = perf_counter()
    candidates = sorted(
        problem.observations,
        key=lambda obs_id: (problem.observations[obs_id].cost, obs_id),
    )

    def dominates(source_id: str, target_id: str) -> bool:
        if source_id == target_id:
            return False
        source_cost = problem.observations[source_id].cost
        target_cost = problem.observations[target_id].cost
        if source_cost > target_cost:
            return False
        if not _observation_determines(problem, source_id, target_id):
            return False
        # If the two observations encode exactly the same partition at equal
        # cost, retain the lexicographically smaller ID. If source is strictly
        # more informative, it dominates regardless of identifier order.
        equivalent = _observation_determines(problem, target_id, source_id)
        return source_cost < target_cost or not equivalent or source_id < target_id

    retained = [
        candidate for candidate in candidates
        if not any(dominates(other, candidate) for other in candidates)
    ]
    removed_by: list[tuple[str, str]] = []
    for candidate in candidates:
        if candidate in retained:
            continue
        dominators = [kept for kept in retained if dominates(kept, candidate)]
        if not dominators:
            # Defensive fallback: an invalid dominance relation must not
            # silently delete an operation.
            retained.append(candidate)
            continue
        chosen = min(
            dominators,
            key=lambda obs_id: (problem.observations[obs_id].cost, obs_id),
        )
        removed_by.append((candidate, chosen))

    retained_set = set(retained)
    transformed_hypotheses = [
        Hypothesis(
            hypothesis_id,
            {obs_id: value for obs_id, value in hypothesis.observations.items()
             if obs_id in retained_set},
            hypothesis.decision,
        )
        for hypothesis_id, hypothesis in problem.hypotheses.items()
    ]
    transformed_observations = [
        Observation(obs_id, problem.observations[obs_id].cost)
        for obs_id in retained
    ]
    transformed = FiniteProblem(transformed_hypotheses, transformed_observations)
    return DominatedObservationPruning(
        problem=transformed,
        retained_observation_ids=tuple(sorted(retained)),
        removed_by=tuple(sorted(removed_by)),
        original_observation_count=len(problem.observations),
        retained_observation_count=len(transformed.observations),
        transform_runtime_seconds=perf_counter() - started,
        preserves_decision_semantics=True,
        preserves_uniform_hypothesis_prior=True,
        preserves_optimal_expected_cost=True,
    )


def verify_dominated_observation_pruning(
    original: FiniteProblem,
    pruning: DominatedObservationPruning,
) -> bool:
    """Verify every removed operation is safely dominated by a retained one."""
    transformed = pruning.problem
    retained = set(pruning.retained_observation_ids)
    dominators = pruning.dominators
    original_ids = set(original.observations)
    removed = original_ids - retained

    if retained != set(transformed.observations):
        return False
    if not retained <= original_ids or set(dominators) != removed:
        return False
    if len(dominators) != len(pruning.removed_by):
        return False
    if set(original.hypotheses) != set(transformed.hypotheses):
        return False

    for hypothesis_id, source in original.hypotheses.items():
        target = transformed.hypotheses[hypothesis_id]
        if source.decision != target.decision:
            return False
        expected = {obs_id: source.observations[obs_id] for obs_id in retained}
        if dict(target.observations) != expected:
            return False

    for obs_id in retained:
        if transformed.observations[obs_id].cost != original.observations[obs_id].cost:
            return False

    for removed_id, dominator_id in dominators.items():
        if dominator_id not in retained:
            return False
        if original.observations[dominator_id].cost > original.observations[removed_id].cost:
            return False
        if not _observation_determines(original, dominator_id, removed_id):
            return False

    if pruning.original_observation_count != len(original.observations):
        return False
    if pruning.retained_observation_count != len(transformed.observations):
        return False
    if pruning.removed_observation_count != len(removed):
        return False
    if pruning.preserves_decision_semantics is not True:
        return False
    if pruning.preserves_uniform_hypothesis_prior is not True:
        return False
    if pruning.preserves_optimal_expected_cost is not True:
        return False
    return True
