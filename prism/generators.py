"""Deterministic finite benchmark generators for PRISM."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random

from .reference import FiniteProblem, Hypothesis, Observation


@dataclass(frozen=True)
class Generated:
    problem: FiniteProblem
    hidden_id: str
    declared_ids: tuple[str, ...]


def _problem(rows, costs):
    hypotheses = [Hypothesis(hid, values, decision) for hid, values, decision in rows]
    observations = [Observation(name, cost) for name, cost in costs.items()]
    return FiniteProblem(hypotheses, observations)


def sparse_binary(seed: int = 0, n: int = 6, support: int = 2) -> Generated:
    """Decision depends on a small parity-like support; others are distractors."""
    if not 1 <= support <= n:
        raise ValueError("support must satisfy 1 <= support <= n")
    rng = Random(seed)
    rows = []
    for mask in range(1 << n):
        bits = {f"x{i}": str((mask >> i) & 1) for i in range(n)}
        decision = str(sum(int(bits[f"x{i}"]) for i in range(support)) % 2)
        rows.append((f"h{mask:0{n}b}", bits, decision))
    costs = {f"x{i}": float(1 + rng.randrange(5)) for i in range(n)}
    hidden = rng.randrange(1 << n)
    ids = tuple(row[0] for row in rows)
    return Generated(_problem(rows, costs), f"h{hidden:0{n}b}", ids)


def misspecified(seed: int = 0) -> Generated:
    """The hidden world exists, but is intentionally omitted from the declared class."""
    generated = sparse_binary(seed=seed, n=3, support=2)
    hidden = generated.hidden_id
    declared = tuple(h for h in generated.declared_ids if h != hidden)
    declared_hypotheses = [generated.problem.hypotheses[h] for h in declared]
    problem = FiniteProblem(declared_hypotheses, list(generated.problem.observations.values()))
    return Generated(problem, hidden, declared)


def parity(n: int = 4) -> Generated:
    if n < 1:
        raise ValueError("n must be positive")
    rows = []
    for mask in range(1 << n):
        bits = {f"x{i}": str((mask >> i) & 1) for i in range(n)}
        rows.append((f"h{mask:0{n}b}", bits, str(mask.bit_count() % 2)))
    problem = _problem(rows, {f"x{i}": 1.0 for i in range(n)})
    return Generated(problem, "h" + format(0, f"0{n}b"), tuple(row[0] for row in rows))
