"""D2.0 exploratory finite-state DeFi vault trace search.

A PURPOSELY RESTRICTED mathematical abstraction of the local Solidity fixture.
Search never imports oracle labels or test contracts. Candidate traces MUST be
independently executed in Foundry before being counted as observed violations.

Goal-first uses a manually designed property relevance heuristic. It is not
automated discovery of a new algorithm, a symbolic EVM, or a sound smart-contract
analyzer. Exhaustive BFS over exactly the same actions is a necessary comparator.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from heapq import heappop, heappush
from itertools import count
from time import perf_counter

INITIAL = 200
AMOUNTS = (1, 10, 100)
ACTION_SPACE = tuple((op, amount) for op in ("deposit_attacker", "donate", "deposit_victim")
                     for amount in AMOUNTS) + (("redeem_attacker", 0),)
MAX_DEPTH = 4


@dataclass(frozen=True)
class State:
    vault_assets: int = 0
    attacker_shares: int = 0
    victim_shares: int = 0
    attacker_wallet: int = INITIAL
    victim_wallet: int = INITIAL
    zero_share_victim_deposit: bool = False

    @property
    def share_supply(self) -> int:
        return self.attacker_shares + self.victim_shares

    def conservation(self) -> bool:
        return self.vault_assets + self.attacker_wallet + self.victim_wallet == 2 * INITIAL


@dataclass(frozen=True)
class SearchResult:
    policy: str
    protected: bool
    found: bool
    plan: tuple[tuple[str, int], ...]
    states_expanded: int
    transitions_attempted: int
    states_generated: int
    wall_seconds: float
    budget_exhausted: bool
    terminal: State | None


def transition(s: State, action: tuple[str, int], *, protected: bool) -> State | None:
    """One transition, approximating only the audited functions in VaultFixture.

    Unsupported interactions are intentionally UNKNOWN, never claimed safe.
    """
    op, amount = action
    if op == "donate":
        if amount <= 0 or amount > s.attacker_wallet:
            return None
        next_state = State(s.vault_assets + amount, s.attacker_shares,
                           s.victim_shares, s.attacker_wallet - amount,
                           s.victim_wallet, s.zero_share_victim_deposit)
    elif op in ("deposit_attacker", "deposit_victim"):
        wallet = s.attacker_wallet if op == "deposit_attacker" else s.victim_wallet
        if amount <= 0 or amount > wallet:
            return None
        if s.share_supply == 0:
            minted = amount
        elif s.vault_assets > 0:
            minted = amount * s.share_supply // s.vault_assets
        else:
            return None
        if protected and minted == 0:
            return None
        next_state = State(
            s.vault_assets + amount,
            s.attacker_shares + (minted if op == "deposit_attacker" else 0),
            s.victim_shares + (minted if op == "deposit_victim" else 0),
            s.attacker_wallet - (amount if op == "deposit_attacker" else 0),
            s.victim_wallet - (amount if op == "deposit_victim" else 0),
            s.zero_share_victim_deposit or (op == "deposit_victim" and minted == 0),
        )
    elif op == "redeem_attacker":
        if s.attacker_shares == 0 or s.share_supply == 0:
            return None
        assets = s.attacker_shares * s.vault_assets // s.share_supply
        next_state = State(
            s.vault_assets - assets, 0, s.victim_shares,
            s.attacker_wallet + assets, s.victim_wallet,
            s.zero_share_victim_deposit,
        )
    else:
        raise ValueError("unsupported action")
    if not next_state.conservation() or any(x < 0 for x in (
        next_state.vault_assets, next_state.attacker_shares, next_state.victim_shares,
        next_state.attacker_wallet, next_state.victim_wallet,
    )):
        raise AssertionError("conservation or nonnegative balances broken")
    return next_state


def violated(s: State) -> bool:
    """Confirmable goal, NOT a general financial safety theorem."""
    return (s.zero_share_victim_deposit and s.attacker_wallet > INITIAL
            and s.victim_wallet < INITIAL)


def _relevance(s: State) -> tuple[int, int, int, int, int]:
    """Goal-relevance ordering, not a completeness claim or learned policy.

    Researcher-defined stages derive from the financial property: share supply,
    asset/share imbalance, zero-share victim deposit, and measurable loss.
    No paths are pruned by this heuristic; the search still has an explicit cap.
    """
    has_shares = s.attacker_shares > 0
    ratio_high = s.share_supply > 0 and s.vault_assets > s.share_supply
    dilution = (s.vault_assets - s.share_supply) if ratio_high else 0
    return (
        int(violated(s)),
        int(s.zero_share_victim_deposit),
        int(ratio_high and has_shares),
        int(has_shares),
        dilution,
    )


def search(*, policy: str = "goal_first", protected: bool = False,
           depth: int = MAX_DEPTH, state_budget: int = 50000) -> SearchResult:
    if policy not in ("goal_first", "breadth_first"):
        raise ValueError("policy must be goal_first or breadth_first")
    if depth < 0 or depth > 8 or state_budget < 1:
        raise ValueError("invalid search limits")
    started = perf_counter()
    origin = State()
    # Include depth in visited identity so the bounded search does not assume
    # a cycle is irrelevant. Avoid dropping alternate paths when key differs.
    seen = {(origin, 0)}
    serial = count()
    if policy == "breadth_first":
        frontier = deque([(origin, ())])
    else:
        frontier = []
        heappush(frontier, (tuple(-x for x in _relevance(origin)), 0, next(serial), origin, ()))
    expanded = generated = attempted = 0
    while frontier and expanded < state_budget:
        if policy == "breadth_first":
            state, plan = frontier.popleft()
        else:
            _, _, _, state, plan = heappop(frontier)
        expanded += 1
        if violated(state):
            return SearchResult(policy, protected, True, plan, expanded, attempted,
                                generated, perf_counter() - started, False, state)
        if len(plan) == depth:
            continue
        for action in ACTION_SPACE:
            attempted += 1
            successor = transition(state, action, protected=protected)
            if successor is None:
                continue
            signature = (successor, len(plan)+1)
            if signature in seen:
                continue
            seen.add(signature)
            generated += 1
            sequence = plan + (action,)
            if policy == "breadth_first":
                frontier.append((successor, sequence))
            else:
                goodness = _relevance(successor)
                heappush(frontier, (
                    # Best-first property relevance (not necessarily shortest path).
                    # The same finite action alphabet and depth apply to BFS.
                    tuple(-x for x in goodness), len(sequence),
                    next(serial), successor, sequence,
                ))
    return SearchResult(policy, protected, False, (), expanded, attempted,
                        generated, perf_counter() - started,
                        bool(frontier), None)


def replay(plan: tuple[tuple[str, int], ...], *, protected: bool) -> tuple[State, int | None]:
    """First rejected operation is returned instead of pretending it succeeded."""
    current = State()
    for index, action in enumerate(plan):
        successor = transition(current, action, protected=protected)
        if successor is None:
            return current, index
        current = successor
    return current, None
