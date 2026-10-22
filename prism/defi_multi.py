"""D2.2 multi-property, bounded abstract research model.

This models a *synthetic* financial fixture authored alongside the engine.
It cannot infer contract semantics or security properties from Solidity.
All model positives must be independently replayed in Foundry; a model
miss within the budget is UNKNOWN, not a claim of absence.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from heapq import heappush, heappop
from itertools import count
from time import perf_counter

INITIAL_COLLATERAL = 100
INITIAL_STABLE = 100
INITIAL_POOL = 1000
NORMAL_PRICE = 2
ACTIONS = (("deposit", 10), ("deposit", 20), ("borrow", 10),
           ("borrow", 100), ("withdraw", 10), ("withdraw", 20),
           ("repay", 10), ("repay", 20), ("price", 20), ("price", 2))
PROPERTIES = ("unauthorized_oracle_write", "unsafe_collateral_withdrawal",
              "unfunded_debt_repayment")
CASES = ("oracle_bug", "withdraw_bug", "repay_bug", "safe")
MAX_DEPTH = 4


@dataclass(frozen=True)
class Flags:
    oracle_owner_only: bool = True
    debt_safe_withdraw: bool = True
    repay_requires_transfer: bool = True


def flags_for(case: str) -> Flags:
    if case not in CASES:
        raise ValueError("unknown fixture variation")
    return Flags(oracle_owner_only=case != "oracle_bug",
                 debt_safe_withdraw=case != "withdraw_bug",
                 repay_requires_transfer=case != "repay_bug")


@dataclass(frozen=True)
class State:
    owned_collateral: int = INITIAL_COLLATERAL
    locked: int = 0
    owned_stable: int = INITIAL_STABLE
    pool_stable: int = INITIAL_POOL
    price: int = NORMAL_PRICE
    debt: int = 0
    unauthorized_price_write: bool = False
    unsafe_withdrawal: bool = False
    unfunded_repayment: bool = False

    @property
    def max_loan(self) -> int:
        return self.locked * self.price // 2

    def conserved(self) -> bool:
        return (self.owned_collateral + self.locked == INITIAL_COLLATERAL
                and self.owned_stable + self.pool_stable == INITIAL_STABLE + INITIAL_POOL)


@dataclass(frozen=True)
class SearchResult:
    case: str
    goal: str
    policy: str
    found: bool
    trace: tuple[tuple[str, int], ...]
    expanded: int
    attempted: int
    generated: int
    exhausted: bool
    seconds: float
    terminal: State | None


def transition(s: State, action: tuple[str, int], flags: Flags) -> State | None:
    op, qty = action
    fields = vars(s).copy()
    if op == "deposit":
        if qty <= 0 or qty > s.owned_collateral:
            return None
        fields["owned_collateral"] -= qty
        fields["locked"] += qty
    elif op == "borrow":
        if qty <= 0 or qty > s.pool_stable or s.debt + qty > s.max_loan:
            return None
        fields["debt"] += qty
        fields["owned_stable"] += qty
        fields["pool_stable"] -= qty
    elif op == "withdraw":
        if qty <= 0 or qty > s.locked:
            return None
        after = s.locked - qty
        if flags.debt_safe_withdraw and s.debt > after * s.price // 2:
            return None
        fields["locked"] = after
        fields["owned_collateral"] += qty
        if s.debt > after * s.price // 2:
            fields["unsafe_withdrawal"] = True
    elif op == "repay":
        if qty <= 0 or qty > s.debt:
            return None
        fields["debt"] -= qty
        if flags.repay_requires_transfer:
            if qty > s.owned_stable:
                return None
            fields["owned_stable"] -= qty
            fields["pool_stable"] += qty
        else:
            fields["unfunded_repayment"] = True
    elif op == "price":
        if qty < 1 or qty > 20 or flags.oracle_owner_only:
            return None
        fields["price"] = qty
        fields["unauthorized_price_write"] = True
    else:
        raise ValueError("unknown contract action")
    state = State(**fields)
    if not state.conserved() or any(x < 0 for x in (
        state.owned_collateral, state.locked, state.owned_stable,
        state.pool_stable, state.debt)):
        raise AssertionError("invalid asset conservation")
    return state


def violated(s: State, goal: str) -> bool:
    if goal == PROPERTIES[0]:
        return s.unauthorized_price_write and s.price != NORMAL_PRICE
    if goal == PROPERTIES[1]:
        return s.unsafe_withdrawal and s.debt > s.max_loan
    if goal == PROPERTIES[2]:
        return s.unfunded_repayment
    raise ValueError("unknown target property")


def relevance(s: State, goal: str) -> tuple[int, int, int, int, int]:
    """Cheap hand-authored property-relevance ordering, not learned strategy."""
    if goal == PROPERTIES[0]:
        return (int(violated(s, goal)), int(s.price != NORMAL_PRICE),
                int(s.unauthorized_price_write), 0, 0)
    if goal == PROPERTIES[1]:
        return (int(violated(s, goal)), int(s.debt > 0),
                int(s.locked > 0), s.debt, -s.locked)
    if goal == PROPERTIES[2]:
        return (int(violated(s, goal)), int(s.debt > 0),
                int(s.locked > 0), s.debt, s.owned_stable)
    raise ValueError("unknown goal")


def search(case: str, goal: str, *, policy: str = "breadth_first",
           depth: int = MAX_DEPTH, budget: int = 50000) -> SearchResult:
    if policy not in ("breadth_first", "goal_first") or depth < 0 or depth > 6 or budget < 1:
        raise ValueError("invalid search policy or budget")
    if goal not in PROPERTIES:
        raise ValueError("unsupported property")
    flags = flags_for(case)
    origin = State()
    t0 = perf_counter()
    seen = {(origin, 0)}
    serial = count()
    if policy == "breadth_first":
        pending = deque([(origin, ())])
    else:
        pending = []
        heappush(pending, (tuple(-n for n in relevance(origin, goal)),
                           0, next(serial), origin, ()))
    expanded = attempted = generated = 0
    while pending and expanded < budget:
        if policy == "breadth_first":
            state, trace = pending.popleft()
        else:
            _, _, _, state, trace = heappop(pending)
        expanded += 1
        if violated(state, goal):
            return SearchResult(case, goal, policy, True, trace,
                                expanded, attempted, generated, False,
                                perf_counter()-t0, state)
        if len(trace) >= depth:
            continue
        for action in ACTIONS:
            attempted += 1
            next_state = transition(state, action, flags)
            if next_state is None:
                continue
            signature = (next_state, len(trace)+1)
            if signature in seen:
                continue
            seen.add(signature)
            generated += 1
            successor_trace = trace + (action,)
            if policy == "breadth_first":
                pending.append((next_state, successor_trace))
            else:
                heappush(pending, (tuple(-n for n in relevance(next_state, goal)),
                                   len(successor_trace), next(serial),
                                   next_state, successor_trace))
    return SearchResult(case, goal, policy, False, (),
                        expanded, attempted, generated, bool(pending),
                        perf_counter()-t0, None)


def replay(case: str, trace: tuple[tuple[str, int], ...]) -> tuple[State, int | None]:
    state = State()
    flags = flags_for(case)
    for i, action in enumerate(trace):
        next_state = transition(state, action, flags)
        if next_state is None:
            return state, i
        state = next_state
    return state, None
