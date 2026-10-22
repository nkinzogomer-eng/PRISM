"""D2.1 finite transition model for a *local-only* multi-contract lending fixture.

A human-written accounting abstraction of SpotPricePool + CollateralCustody
+ LendingMarket; not extracted from Solidity, and not a complete EVM analyzer.
It proposes candidate traces whose balances must be independently checked by
Foundry. Unknown or unmodeled contract behavior is not ruled out by this model.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, asdict
from heapq import heappop, heappush
from itertools import count
from time import perf_counter

C_INITIAL = 100
Q_INITIAL = 200
LENDER_INITIAL = 500
POOL_RESERVE = 100
LTV = 75
DEPTH = 4

# Same actions and numeric domain in each search policy; no label lookup.
ACTIONS = (
    ("pump", 50), ("pump", 100),
    ("pledge", 10), ("pledge", 20), ("pledge", 40),
    ("borrow", 10), ("borrow", 20), ("borrow", 40), ("borrow", 60),
    ("unwind", 25), ("unwind", 50),
)


@dataclass(frozen=True)
class CreditState:
    q_wallet: int = Q_INITIAL
    c_wallet: int = C_INITIAL
    q_reserve: int = POOL_RESERVE
    c_reserve: int = POOL_RESERVE
    pledged: int = 0
    debt: int = 0
    lender_q: int = LENDER_INITIAL

    def conserved(self) -> bool:
        return (self.q_wallet + self.q_reserve + self.lender_q ==
                Q_INITIAL + POOL_RESERVE + LENDER_INITIAL and
                self.c_wallet + self.c_reserve + self.pledged ==
                C_INITIAL + POOL_RESERVE and
                min(asdict(self).values()) >= 0)

    def price100(self) -> int:
        return self.q_reserve * 100 // self.c_reserve

    def fair_credit_limit(self) -> int:
        return self.pledged * LTV // 100

    def score(self) -> tuple[int, ...]:
        over = max(0, self.debt - self.fair_credit_limit())
        # Hand-authored, property-aware ordering. Not a learned or new algorithm.
        return (int(violation(self)), int(over > 0),
                int(self.debt > 0), int(self.pledged > 0),
                int(self.price100() > 100), over)


@dataclass(frozen=True)
class Result:
    policy: str
    guarded: bool
    found: bool
    plan: tuple[tuple[str, int], ...]
    expanded: int
    attempted: int
    generated: int
    elapsed_seconds: float
    exhausted: bool
    terminal: CreditState | None


def step(s: CreditState, action: tuple[str, int], *, guarded: bool) -> CreditState | None:
    op, amount = action
    if amount <= 0:
        return None
    if op == "pump":
        if amount > s.q_wallet or s.c_reserve <= 1:
            return None
        new_q = s.q_reserve + amount
        new_c = s.q_reserve * s.c_reserve // new_q
        if not (0 < new_c < s.c_reserve):
            return None
        nxt = CreditState(s.q_wallet - amount,
                          s.c_wallet + s.c_reserve - new_c,
                          new_q, new_c, s.pledged, s.debt, s.lender_q)
    elif op == "unwind":
        if amount > s.c_wallet:
            return None
        new_c = s.c_reserve + amount
        new_q = s.q_reserve * s.c_reserve // new_c
        if not (0 < new_q < s.q_reserve):
            return None
        nxt = CreditState(s.q_wallet + s.q_reserve - new_q,
                          s.c_wallet - amount, new_q, new_c,
                          s.pledged, s.debt, s.lender_q)
    elif op == "pledge":
        if amount > s.c_wallet:
            return None
        nxt = CreditState(s.q_wallet, s.c_wallet - amount,
                          s.q_reserve, s.c_reserve, s.pledged + amount,
                          s.debt, s.lender_q)
    elif op == "borrow":
        price100 = 100 if guarded else s.price100()
        limit = s.pledged * price100 * LTV // 10000
        if s.debt + amount > limit or amount > s.lender_q:
            return None
        nxt = CreditState(s.q_wallet + amount, s.c_wallet,
                          s.q_reserve, s.c_reserve, s.pledged,
                          s.debt + amount, s.lender_q - amount)
    else:
        raise ValueError("unknown action")
    if not nxt.conserved():
        raise AssertionError("asset conservation broken")
    return nxt


def violation(s: CreditState) -> bool:
    """Only at restored market baseline: an underwater uncollateralized loan.

    Liquid assets exceed initial assets while the attacker leaves the pledged
    collateral behind; this is potential default/bad debt, not a proof of a
    profitable real-world strategy with fees, liquidations or market impact.
    """
    return (
        s.q_reserve == POOL_RESERVE and s.c_reserve == POOL_RESERVE
        and s.debt > s.fair_credit_limit()
        and s.q_wallet + s.c_wallet > Q_INITIAL + C_INITIAL
    )


def replay(plan: tuple[tuple[str, int], ...], guarded: bool) -> tuple[CreditState, int | None]:
    state = CreditState()
    for i, action in enumerate(plan):
        nxt = step(state, action, guarded=guarded)
        if nxt is None:
            return state, i
        state = nxt
    return state, None


def explore(policy: str = "goal_first", guarded: bool = False,
            depth: int = DEPTH, budget: int = 30000) -> Result:
    if policy not in {"breadth_first", "goal_first"}:
        raise ValueError("unsupported policy")
    if depth < 0 or depth > 7 or budget < 1:
        raise ValueError("invalid search bounds")
    start = perf_counter()
    initial = CreditState()
    if policy == "breadth_first":
        queue = deque([(initial, ())])
    else:
        queue = []
        heappush(queue, (tuple(-v for v in initial.score()), 0, 0, initial, ()))
    serial = count(start=1)
    seen = {(initial, 0)}
    expanded = attempted = generated = 0
    while queue and expanded < budget:
        if policy == "breadth_first":
            state, plan = queue.popleft()
        else:
            _, _, _, state, plan = heappop(queue)
        expanded += 1
        if violation(state):
            return Result(policy, guarded, True, plan, expanded, attempted,
                          generated, perf_counter()-start, False, state)
        if len(plan) >= depth:
            continue
        for action in ACTIONS:
            attempted += 1
            nxt = step(state, action, guarded=guarded)
            if nxt is None:
                continue
            key = (nxt, len(plan)+1)
            if key in seen:
                continue
            seen.add(key)
            generated += 1
            updated = plan + (action,)
            if policy == "breadth_first":
                queue.append((nxt, updated))
            else:
                heappush(queue, (tuple(-v for v in nxt.score()), len(updated),
                                 next(serial), nxt, updated))
    return Result(policy, guarded, False, (), expanded, attempted, generated,
                  perf_counter()-start, bool(queue), None)
