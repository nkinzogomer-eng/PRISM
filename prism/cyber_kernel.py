"""D2.4D: model-relative, domain-independent goal-dependency search.

Combines standard backwards dependency slicing and state projection (both
well-established techniques). It is NOT a sound source analyzer, an EVM or a
new-vulnerability detector. Caller must provide complete action effects/reads.
Absent trusted effect metadata, report UNKNOWN; never interpret pruning as safe.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, fields, is_dataclass
from time import perf_counter
from typing import Callable, Hashable

Action = tuple[str, int]


@dataclass(frozen=True)
class Effect:
    reads: frozenset[str]
    writes: frozenset[str]


@dataclass(frozen=True)
class Domain:
    name: str
    scenario: str
    start: object
    actions: tuple[Action, ...]
    effects: dict[str, Effect]
    goal_fields: frozenset[str]
    transition: Callable[[object, Action], object | None]
    violated: Callable[[object], bool]
    provenance: str = "researcher-model"


@dataclass(frozen=True)
class Result:
    mode: str
    found: bool
    verdict: str
    plan: tuple[Action, ...]
    expanded: int
    attempted: int
    generated: int
    elapsed_seconds: float
    selected_actions: int
    original_actions: int
    frontier_fields: tuple[str, ...]


def model_fields(domain: Domain) -> frozenset[str]:
    if not is_dataclass(domain.start):
        raise ValueError("state must be a dataclass; external/opaque state UNKNOWN")
    available = frozenset(f.name for f in fields(domain.start))
    if not available or not domain.goal_fields or not domain.goal_fields <= available:
        raise ValueError("no complete goal/state declaration")
    if not domain.actions or not isinstance(domain.provenance, str):
        raise ValueError("incomplete domain")
    for action in domain.actions:
        if not isinstance(action, tuple) or len(action) != 2 or action[0] not in domain.effects:
            raise ValueError("missing effect declaration: UNKNOWN")
        effect = domain.effects[action[0]]
        if not effect.reads <= available or not effect.writes <= available or not effect.writes:
            raise ValueError("invalid effects: UNKNOWN")
    return available


def dependency_frontier(domain: Domain) -> tuple[frozenset[str], tuple[Action, ...]]:
    """Fixed-point dependencies: selected ops write an important field.

    A sound stuttering reduction requires complete reads/writes for every
    operation, including guards and external effects. Not guaranteed here.
    """
    model_fields(domain)
    important = set(domain.goal_fields)
    changed = True
    while changed:
        changed = False
        for action in domain.actions:
            spec = domain.effects[action[0]]
            if spec.writes & important:
                updated = important | set(spec.reads)
                if updated != important:
                    important = updated
                    changed = True
    selected = tuple(a for a in domain.actions
                     if domain.effects[a[0]].writes & important)
    if not selected:
        raise ValueError("no operations can alter goal: UNKNOWN")
    return frozenset(important), selected


def state_key(state: object, names: tuple[str, ...]) -> tuple[Hashable, ...]:
    return tuple(getattr(state, field) for field in names)


def verify_trace(domain: Domain, plan: tuple[Action, ...]) -> bool:
    state = domain.start
    for action in plan:
        state = domain.transition(state, action)
        if state is None:
            return False
    return domain.violated(state)


def search(domain: Domain, *, mode: str, depth: int = 5,
           max_expanded: int = 20000) -> Result:
    if mode not in ("full", "slice", "quotient"):
        raise ValueError("unknown policy")
    if depth < 0 or depth > 12 or max_expanded < 1:
        raise ValueError("invalid resource budget")
    all_fields = model_fields(domain)
    relevant, selected = dependency_frontier(domain)
    alphabet = domain.actions if mode == "full" else selected
    key_fields = tuple(sorted(relevant if mode == "quotient" else all_fields))
    started = perf_counter()
    queue = deque([(domain.start, ())])
    seen = {(state_key(domain.start, key_fields), 0)}
    expanded = generated = attempted = 0
    while queue and expanded < max_expanded:
        state, plan = queue.popleft()
        expanded += 1
        if domain.violated(state):
            if not verify_trace(domain, plan):
                raise AssertionError("non-reproducible discovered plan")
            return Result(mode, True, "FOUND_MODEL_WITNESS", plan, expanded,
                          attempted, generated, perf_counter() - started,
                          len(alphabet), len(domain.actions), tuple(sorted(relevant)))
        if len(plan) == depth:
            continue
        for action in alphabet:
            attempted += 1
            successor = domain.transition(state, action)
            if successor is None:
                continue
            signature = (state_key(successor, key_fields), len(plan) + 1)
            if signature in seen:
                continue
            seen.add(signature)
            generated += 1
            queue.append((successor, plan + (action,)))
    return Result(mode, False, "UNKNOWN_BUDGET" if queue else "NOT_FOUND_IN_FINITE_MODEL",
                  (), expanded, attempted, generated, perf_counter() - started,
                  len(alphabet), len(domain.actions), tuple(sorted(relevant)))


def audit_effects(domain: Domain, *, depth: int = 3,
                  max_states: int = 5000) -> dict:
    """Dynamic write-set check on reachable sample; does not prove read-set soundness."""
    attributes = model_fields(domain)
    queue = deque([(domain.start, 0)])
    seen = {(domain.start, 0)}
    examined = steps = 0
    while queue and examined < max_states:
        state, dist = queue.popleft()
        examined += 1
        if dist == depth:
            continue
        for act in domain.actions:
            successor = domain.transition(state, act)
            if successor is None:
                continue
            steps += 1
            actual = {n for n in attributes if getattr(state, n) != getattr(successor, n)}
            undeclared = actual - domain.effects[act[0]].writes
            if undeclared:
                raise ValueError(f"undeclared effects {act[0]}: {sorted(undeclared)}")
            key = (successor, dist + 1)
            if key not in seen:
                seen.add(key)
                queue.append(key)
    return {"visited": examined, "transitions_audited": steps,
            "exhausted": bool(queue),
            "read_set_proved": False, "write_set_exhaustively_proved": not queue}
