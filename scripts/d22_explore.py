"""D2.2 generate independently executable EVM witnesses across three properties.

This is *not* an analyzer of Solidity: the mathematical model is hand authored.
The generation step cannot consult the Foundry EVM test results. It reports
all 12 property/variant combinations, including negative controls and budgets.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from prism.defi_multi import CASES, PROPERTIES, State, search, replay, violated

POSITIVE_CASES = dict(zip(CASES[:3], PROPERTIES))


def code_step(step: tuple[str, int]) -> str:
    op, amount = step
    if op == "deposit":
        return f"actor.deposit(collateral, market, {amount});"
    if op == "borrow":
        return f"actor.borrow(market, {amount});"
    if op == "withdraw":
        return f"actor.withdraw(market, {amount});"
    if op == "repay":
        return f"actor.repay(loan, market, {amount});"
    if op == "price":
        return f"actor.changePrice(oracle, {amount});"
    raise ValueError("bad model action")


def state_assertions(s: State, tag: str) -> str:
    specs = (
        ("collateral.balanceOf(address(actor))", s.owned_collateral, "collateral-wallet"),
        ("collateral.balanceOf(address(market))", s.locked, "locked-collateral"),
        ("loan.balanceOf(address(actor))", s.owned_stable, "stable-wallet"),
        ("loan.balanceOf(address(market))", s.pool_stable, "stable-pool"),
        ("market.debt(address(actor))", s.debt, "debt"),
        ("market.locked(address(actor))", s.locked, "market-locked"),
        ("oracle.price()", s.price, "price"),
    )
    return "\n        ".join(
        f'require({key} == {value}, "{tag}-{label}");'
        for key,value,label in specs
    )


def create_test(case: str, goal: str, trace: tuple[tuple[str,int],...]) -> str:
    positive, rejected = replay(case, trace)
    if rejected is not None or not violated(positive, goal):
        raise ValueError("generated trace is not a model witness")
    safe, safe_reject = replay("safe", trace)
    trace_code = "\n        ".join(code_step(s) for s in trace)
    if goal == PROPERTIES[0]:
        predicate = ('require(address(actor) != oracle.owner() && oracle.price() != 2, '
                     '"D22_ORACLE_AUTH_WITNESS");')
    elif goal == PROPERTIES[1]:
        predicate = ('require(market.debt(address(actor)) > market.limit(address(actor)), '
                     '"D22_WITHDRAW_SOLVENCY_WITNESS");')
    elif goal == PROPERTIES[2]:
        predicate = ('require(market.debt(address(actor)) == 0 && '
                     'loan.balanceOf(address(actor)) > 100 && '
                     'loan.balanceOf(address(market)) < 1000, '
                     '"D22_UNFUNDED_REPAY_WITNESS");')
    else:
        raise ValueError("bad security property")

    if safe_reject is not None:
        if safe_reject != len(trace)-1:
            raise ValueError("expected patched failure at last step")
        prefix = "\n        ".join(code_step(s) for s in trace[:safe_reject])
        last = code_step(trace[safe_reject]).rstrip(";")
        protected = f'''
        {prefix}
        bool blocked = false;
        try {last} {{ blocked = false; }} catch {{ blocked = true; }}
        require(blocked, "safe-variant-failed-to-reject");
        {state_assertions(safe, "safe")}'''
    else:
        if violated(safe, goal):
            raise ValueError("patched model still violates goal")
        protected = f'''
        {trace_code}
        {state_assertions(safe, "safe")}'''

    id_name = {"oracle_bug": "Oracle", "withdraw_bug": "Withdraw",
               "repay_bug": "Repay"}[case]
    return f'''
    function testGenerated{id_name}BugWitness() external {{
        (D22Coin collateral, D22Coin loan, D22Oracle oracle,
            D22Credit market, D22Actor actor) = deploy({{"oracle_bug":1,"withdraw_bug":2,"repay_bug":3}[case]});
        {trace_code}
        {state_assertions(positive, "unsafe")}
        {predicate}
    }}

    function testGenerated{id_name}SafeControl() external {{
        (D22Coin collateral, D22Coin loan, D22Oracle oracle,
            D22Credit market, D22Actor actor) = deploy(0);
        {protected}
    }}
'''


def generate_evm_source(positives: dict[str, tuple[str, tuple[tuple[str,int],...]]]) -> str:
    tests = "\n".join(create_test(case,*positives[case]) for case in CASES[:3])
    return '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// Generated from D2.2 model WITHOUT using the raw EVM baseline reports.
import {D22Coin, D22Oracle, D22Credit, D22Actor} from "../src/MultiRisk.sol";

contract D22GeneratedWitnessTest {
    function deploy(uint8 variant) internal returns (
        D22Coin collateral, D22Coin loan, D22Oracle oracle,
        D22Credit market, D22Actor actor
    ) {
        collateral = new D22Coin();
        loan = new D22Coin();
        oracle = new D22Oracle(variant != 1);
        market = new D22Credit(collateral, loan, oracle, variant != 2, variant != 3);
        actor = new D22Actor();
        collateral.mint(address(actor), 100);
        loan.mint(address(actor), 100);
        loan.mint(address(market), 1000);
    }
''' + tests + "\n}\n"


def run(root: Path, out: Path) -> dict:
    source = root / "src" / "MultiRisk.sol"
    if not source.is_file():
        raise FileNotFoundError(source)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    positives = {}
    for case in CASES:
        for prop in PROPERTIES:
            baseline = search(case, prop, policy="breadth_first")
            candidate = search(case, prop, policy="goal_first")
            if baseline.exhausted or candidate.exhausted:
                raise RuntimeError("unresolved search budget; cannot score an absence")
            if baseline.found != candidate.found:
                raise RuntimeError("search policies disagree; incomplete exploration")
            expected = POSITIVE_CASES.get(case) == prop
            if expected != baseline.found:
                raise RuntimeError(f"fixture contract expectation inconsistent: {case}, {prop}")
            if candidate.found:
                final, rejected = replay(case, candidate.trace)
                if rejected is not None or not violated(final, prop):
                    raise RuntimeError("candidate failed model replay")
                positives[case] = (prop, candidate.trace)
            rows.append({
                "case_id": case, "property_id": prop,
                "expected_dev_label": expected,
                "baseline": asdict(baseline),
                "goal_first": asdict(candidate),
            })
    if set(positives) != set(POSITIVE_CASES):
        raise RuntimeError("missing or duplicated property witness")
    target = root / "test" / "D22GeneratedWitness.t.sol"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate_evm_source(positives), encoding="utf-8")
    record = {
        "phase": "DeFi D2.2",
        "status": "MODEL_ONLY_NOT_EVM_CONFIRMED",
        "contract_sha256": sha256(source.read_bytes()).hexdigest(),
        "evm_replay_sha256": sha256(target.read_bytes()).hexdigest(),
        "cross_product": rows,
        "positive_candidate_count": len(positives),
        "negative_model_count": len(rows)-len(positives),
        "limitations": [
            "Researcher-authored vulnerable and corrected cases and oracle labels",
            "Public synthetic fixtures and fixed property definitions; not blind holdout",
            "No automated derivation of program model from Solidity",
            "No claim of recall on real DeFi protocols or unknown bugs",
            "Only bounded action alphabet and depth, confirmed EVM traces not universal proofs",
            "Goal-first heuristic hand-designed for property, not benchmark-independent",
            "Foundry stateful handler may find all cases; no unique PRISM discovery claim",
        ],
    }
    (out / "candidate-and-model.json").write_text(
        json.dumps(record, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    for row in rows:
        print("D22_MODEL",row["case_id"],row["property_id"],
              "found",row["goal_first"]["found"],
              "bfs_expanded",row["baseline"]["expanded"],
              "goal_expanded",row["goal_first"]["expanded"])
    return record


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--root", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    args = cli.parse_args()
    run(args.root,args.output)
