"""Generate Solidity EVM replay from a discovered D2.1 candidate, then verify independently."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from prism.defi_lending import search, replay, violates_solvency, START_ASSET, START_STABLE, START_POOL


def step(action: tuple[str, int]) -> str:
    op, n = action
    return {
        "deposit": f"attacker.approveAndDeposit(collateral, lender, {n});",
        "change_price": f"attacker.alterPrice(oracle, {n});",
        "borrow": f"attacker.takeLoan(lender, {n});",
    }[op]


def generate(path: Path, plan: tuple[tuple[str, int], ...], final, reject: int) -> None:
    operations = "\n        ".join(step(x) for x in plan)
    prefix = "\n        ".join(step(x) for x in plan[:reject])
    blocked = step(plan[reject])
    code = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
// Auto-generated from the D2.1 model trace; outcomes checked on independent EVM.
import {{DemoAsset, DemoPriceOracle, DemoLender, DemoTrader}} from "../src/LendingFixture.sol";

contract D21GeneratedReplayTest {{
    function deploy(bool guarded) internal returns (
        DemoAsset collateral, DemoAsset stable, DemoPriceOracle oracle,
        DemoLender lender, DemoTrader attacker
    ) {{
        collateral = new DemoAsset();
        stable = new DemoAsset();
        oracle = new DemoPriceOracle(guarded, 2);
        lender = new DemoLender(collateral, stable, oracle);
        attacker = new DemoTrader();
        collateral.mint(address(attacker), {START_ASSET});
        stable.mint(address(attacker), {START_STABLE});
        stable.mint(address(lender), {START_POOL});
    }}

    function testGeneratedCrossContractViolation() external {{
        (DemoAsset collateral, DemoAsset stable, DemoPriceOracle oracle,
            DemoLender lender, DemoTrader attacker) = deploy(false);
        {operations}
        require(collateral.balanceOf(address(attacker)) == {final.collateral_wallet}, "model-actor-collateral");
        require(collateral.balanceOf(address(lender)) == {final.collateral_locked}, "model-locked");
        require(stable.balanceOf(address(attacker)) == {final.stable_wallet}, "model-actor-stable");
        require(stable.balanceOf(address(lender)) == {final.pool_stable}, "model-pool");
        require(lender.debt(address(attacker)) == {final.debt}, "model-debt");
        require(oracle.price() == {final.oracle_price}, "model-price");
        require(lender.debt(address(attacker)) > lender.currentBorrowLimit(address(attacker)),
                "not-undercollateralized");
        require(stable.balanceOf(address(attacker)) > {START_STABLE}, "no-profit-in-stable");
    }}

    function testGeneratedTraceRejectedByGuardedOracle() external {{
        (DemoAsset collateral, DemoAsset stable, DemoPriceOracle oracle,
            DemoLender lender, DemoTrader attacker) = deploy(true);
        {prefix}
        bool rejected;
        try attacker.alterPrice(oracle, {plan[reject][1]}) {{ rejected = false; }}
        catch {{ rejected = true; }}
        require(rejected, "patched-oracle-accepted-unauthorized-edit");
        require(oracle.price() == 2, "patched-oracle-price-mutated");
        require(lender.debt(address(attacker)) == 0, "patched-oracle-debt");
        require(stable.balanceOf(address(attacker)) == {START_STABLE}, "patched-oracle-stable");
    }}
}}
'''
    path.write_text(code, encoding="utf-8")


def run(root: Path, out: Path) -> dict:
    source = root / "src" / "LendingFixture.sol"
    if not source.is_file():
        raise FileNotFoundError(source)
    results = [
        search(policy=p, guarded_oracle=g)
        for g in (False, True) for p in ("breadth_first", "goal_first")
    ]
    bfs, goal, protected_bfs, protected_goal = results
    if not bfs.found or not goal.found or protected_bfs.found or protected_goal.found:
        raise RuntimeError("unexpected model classification")
    final, reject = replay(goal.plan, guarded_oracle=False)
    safe, rejected_at = replay(goal.plan, guarded_oracle=True)
    if reject is not None or not violates_solvency(final) or rejected_at is None:
        raise RuntimeError("candidate was not model-verified")
    if goal.plan[rejected_at][0] != "change_price":
        raise RuntimeError("protected variant rejects unexpected call")
    root_test = root / "test"
    root_test.mkdir(parents=True, exist_ok=True)
    target = root_test / "D21GeneratedReplay.t.sol"
    generate(target, goal.plan, final, rejected_at)
    out.mkdir(parents=True, exist_ok=True)
    record = {
        "phase": "D2.1",
        "status": "MODEL_CANDIDATE_NOT_YET_EVM_CONFIRMED",
        "source_sha256": sha256(source.read_bytes()).hexdigest(),
        "generated_test_sha256": sha256(target.read_bytes()).hexdigest(),
        "plan": [{"action": a, "amount": n} for a, n in goal.plan],
        "predicted_final": asdict(final),
        "guarded_rejection_index": rejected_at,
        "policies": [asdict(r) for r in results],
        "limits": ["Synthetic owner-controlled oracle and fictitious tokens",
                   "Oracle guard is only a single-property fix",
                   "Manually specified financial model and search heuristic",
                   "Not an EVM symbolic analyzer or unknown vulnerability discovery",
                   "Foundry stateful fuzz may find same violation independently",
                   "No meaningful whole-system timing/risk estimates yet"],
    }
    (out / "candidate.json").write_text(json.dumps(record, indent=2, sort_keys=True)+"\n")
    print("D21_PLAN", record["plan"])
    for r in results:
        print("D21_POLICY", r.policy, "protected", r.guarded_oracle,
              "found", r.found, "expanded", r.expanded, "attempted", r.attempted)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.root, args.output)
