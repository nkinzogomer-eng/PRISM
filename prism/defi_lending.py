"""D2.1 restricted three-contract collateral/oracle/lender state model.

No bytecode analysis, automated property discovery, or sound proof of EVM safety.
The financial property and action alphabet are deliberately researcher-specified,
so comparisons with good invariant fuzzers are mandatory. This model does not
import labels/test contracts. Candidate plans are confirmed by a real local EVM.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from heapq import heappop, heappush
from itertools import count
from time import perf_counter

START_ASSET = 100
START_STABLE = 100
START_POOL = 1000
NORMAL_PRICE = 2
SPIKE_PRICE = 20
MAX_DEPTH = 4
ACTION_SPACE = (
    ("deposit", 10), ("deposit", 20),
    ("change_price", 20), ("change_price", 2),
    ("borrow", 10), ("borrow", 100),
)


@dataclass(frozen=True)
class State:
    collateral_wallet: int = START_ASSET
    collateral_locked: int = 0
    stable_wallet: int = START_STABLE
    pool_stable: int = START_POOL
    oracle_price: int = NORMAL_PRICE
    debt: int = 0

    @property
    def borrow_limit(self) -> int:
        return self.collateral_locked * self.oracle_price // 2

    def invariant_balances(self) -> bool:
        return (self.collateral_wallet + self.collateral_locked == START_ASSET
                and self.stable_wallet + self.pool_stable == START_STABLE + START_POOL)


@dataclass(frozen=True)
class SearchResult:
    policy: str
    guarded_oracle: bool
    found: bool
    plan: tuple[tuple[str, int], ...]
    expanded: int
    attempted: int
    generated: int
    seconds: float
    budget_exhausted: bool
    final: State | None


def transition(state: State, action: tuple[str, int], guarded_oracle: bool) -> State | None:
    op, n = action
    if op == "deposit":
        if n <= 0 or n > state.collateral_wallet:
            return None
        next_state = State(state.collateral_wallet-n, state.collateral_locked+n,
                           state.stable_wallet, state.pool_stable,
                           state.oracle_price, state.debt)
    elif op == "change_price":
        if not 1 <= n <= 100 or guarded_oracle:
            return None
        next_state = State(state.collateral_wallet, state.collateral_locked,
                           state.stable_wallet, state.pool_stable, n, state.debt)
    elif op == "borrow":
        if n <= 0 or n > state.pool_stable or state.debt + n > state.borrow_limit:
            return None
        next_state = State(state.collateral_wallet, state.collateral_locked,
                           state.stable_wallet+n, state.pool_stable-n,
                           state.oracle_price, state.debt+n)
    else:
        raise ValueError("unknown action")
    if not next_state.invariant_balances():
        raise AssertionError("model conservation failure")
    return next_state


def violates_solvency(state: State) -> bool:
    """Excess debt at normal reference price, confirmed by borrower asset delta."""
    return (state.oracle_price == NORMAL_PRICE and state.debt > state.borrow_limit
            and state.stable_wallet > START_STABLE)


def relevance(state: State) -> tuple[int, int, int, int, int]:
    """Heuristic computed from predeclared property; NOT learned or novel."""
    return (int(violates_solvency(state)),
            int(state.debt > 0 and state.oracle_price != NORMAL_PRICE),
            int(state.collateral_locked > 0 and state.oracle_price > NORMAL_PRICE),
            int(state.collateral_locked > 0),
            state.debt)


def search(*, policy: str, guarded_oracle: bool = False, depth: int = MAX_DEPTH,
           state_budget: int = 100000) -> SearchResult:
    if policy not in {"breadth_first", "goal_first"}:
        raise ValueError("invalid policy")
    if depth < 0 or depth > 8 or state_budget < 1:
        raise ValueError("invalid search budget")
    t0 = perf_counter()
    start = State()
    seen = {(start, 0)}
    serial = count()
    if policy == "breadth_first":
        todo = deque([(start, ())])
    else:
        todo = []
        heappush(todo, (tuple(-v for v in relevance(start)), 0, next(serial), start, ()))
    expanded = attempted = generated = 0
    while todo and expanded < state_budget:
        if policy == "breadth_first":
            state, plan = todo.popleft()
        else:
            _, _, _, state, plan = heappop(todo)
        expanded += 1
        if violates_solvency(state):
            return SearchResult(policy, guarded_oracle, True, plan,
                                expanded, attempted, generated,
                                perf_counter()-t0, False, state)
        if len(plan) >= depth:
            continue
        for action in ACTION_SPACE:
            attempted += 1
            next_state = transition(state, action, guarded_oracle)
            if next_state is None:
                continue
            key = (next_state, len(plan)+1)
            if key in seen:
                continue
            seen.add(key)
            generated += 1
            next_plan = plan + (action,)
            if policy == "breadth_first":
                todo.append((next_state, next_plan))
            else:
                heappush(todo, (tuple(-v for v in relevance(next_state)),
                                len(next_plan), next(serial), next_state, next_plan))
    return SearchResult(policy, guarded_oracle, False, (), expanded, attempted,
                        generated, perf_counter()-t0, bool(todo), None)


def replay(plan: tuple[tuple[str, int], ...], *, guarded_oracle: bool) -> tuple[State, int | None]:
    state = State()
    for i, action in enumerate(plan):
        after = transition(state, action, guarded_oracle)
        if after is None:
            return state, i
        state = after
    return state, None
