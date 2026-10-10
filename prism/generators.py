"""Deterministic finite benchmark generators for PRISM.

Each generator returns:
  - `declared`: the FiniteProblem the solver is allowed to reason over;
  - `world_table`: the full observation table of every world, including the
    hidden one. Only the oracle may read `world_table`.
  - `hidden_id`: the id of the true world (oracle-only).
"""

from __future__ import annotations

from dataclasses import dataclass
from random import Random

from .reference import FiniteProblem, Hypothesis, Observation


@dataclass(frozen=True)
class Generated:
    declared: FiniteProblem
    world_table: dict  # id -> {"observations": {...}, "decision": str}
    hidden_id: str


def _build(rows, costs):
    world_table = {hid: {"observations": dict(values), "decision": decision}
                   for hid, values, decision in rows}
    hyps = [Hypothesis(hid, values, decision) for hid, values, decision in rows]
    obs = [Observation(name, cost) for name, cost in costs.items()]
    return FiniteProblem(hyps, obs), world_table


def sparse_binary(seed: int = 0, n: int = 4, support: int = 2) -> Generated:
    """Decision = parity of the first `support` bits; other bits are distractors."""
    if not 1 <= support <= n:
        raise ValueError("support must satisfy 1 <= support <= n")
    rng = Random(seed)
    rows = []
    for mask in range(1 << n):
        bits = {f"x{i}": str((mask >> i) & 1) for i in range(n)}
        decision = str(sum(int(bits[f"x{i}"]) for i in range(support)) % 2)
        rows.append((f"h{mask:0{n}b}", bits, decision))
    costs = {f"x{i}": float(1 + rng.randrange(5)) for i in range(n)}
    hidden = f"h{rng.randrange(1 << n):0{n}b}"
    declared, table = _build(rows, costs)
    return Generated(declared, table, hidden)


def misspecified(seed: int = 0, n: int = 3, support: int = 2) -> Generated:
    """The true world is real, but deliberately removed from the declared class."""
    base = sparse_binary(seed=seed, n=n, support=support)
    hidden = base.hidden_id
    rows = [
        (hid, entry["observations"], entry["decision"])
        for hid, entry in base.world_table.items() if hid != hidden
    ]
    costs = {o.id: o.cost for o in base.declared.observations.values()}
    declared, _ = _build(rows, costs)
    return Generated(declared, base.world_table, hidden)


def parity(n: int = 4) -> Generated:
    """Decision = parity of all bits: every variable is decision-critical."""
    if n < 1:
        raise ValueError("n must be positive")
    rows = []
    for mask in range(1 << n):
        bits = {f"x{i}": str((mask >> i) & 1) for i in range(n)}
        rows.append((f"h{mask:0{n}b}", bits, str(bin(mask).count("1") % 2)))
    declared, table = _build(rows, {f"x{i}": 1.0 for i in range(n)})
    return Generated(declared, table, f"h{0:0{n}b}")
