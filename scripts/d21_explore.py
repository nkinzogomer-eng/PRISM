"""D2.1: search for a four-operation cross-contract property violation and
generate Solidity tests. Model predictions are CANDIDATES until Foundry passes.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

from prism.defi_d21_search import (
    DEPTH, CreditState, explore, replay, violation,
)


def action_solidity(action: tuple[str, int]) -> str:
    op, amount = action
    if op == "pump":
        return f"trader.pump(pool, {amount});"
    if op == "pledge":
        return f"trader.pledge(custody, {amount});"
    if op == "borrow":
        return f"trader.borrow(lender, {amount});"
    if op == "unwind":
        return f"trader.unwind(pool, {amount});"
    raise ValueError("unsupported model action")


def render(plan: tuple[tuple[str, int], ...], predicted: CreditState,
           safe: CreditState, rejection_index: int) -> str:
    trace = "\n        ".join(action_solidity(action) for action in plan)
    prefix = "\n        ".join(action_solidity(action) for action in plan[:rejection_index])
    badop, amount = plan[rejection_index]
    if badop != "borrow":
        raise ValueError("control branch must reject credit issuance")
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Generated from search results, NOT a hand-authored exploit assertion.
// These transactions run only on separately deployed local Solidity fixtures.
import {{D21Setup}} from "./D21Setup.sol";

contract D21GeneratedTest is D21Setup {{
    function testGeneratedVulnerableCrossContractCreditViolation() external {{
        deploy(false);
        {trace}
        require(quote.balanceOf(address(trader)) == {predicted.q_wallet},
                "model-eVM-q-wallet-diverged");
        require(collateral.balanceOf(address(trader)) == {predicted.c_wallet},
                "model-eVM-c-wallet-diverged");
        require(pool.reserveQuote() == {predicted.q_reserve},
                "model-eVM-q-reserve-diverged");
        require(pool.reserveCollateral() == {predicted.c_reserve},
                "model-eVM-c-reserve-diverged");
        require(custody.locked(address(trader)) == {predicted.pledged},
                "model-eVM-pledged-diverged");
        require(lender.debt(address(trader)) == {predicted.debt},
                "model-eVM-debt-diverged");
        require(quote.balanceOf(address(lender)) == {predicted.lender_q},
                "model-eVM-lender-reserve-diverged");
        require(pool.spotPriceTimes100() == 100,
                "manipulated-spot-not-restored");
        require(lender.debt(address(trader)) >
                custody.locked(address(trader)) * 75 / 100,
                "reference-LTV-is-not-breached");
        require(quote.balanceOf(address(trader))
                + collateral.balanceOf(address(trader)) > 300,
                "no-liquid-asset-surplus-before-default");
        assertConservation();
    }}

    function testIdenticalGeneratedPrefixRejectedByControl() external {{
        deploy(true);
        {prefix}
        uint256 cashBefore = quote.balanceOf(address(trader));
        bool rejected = false;
        try trader.borrow(lender, {amount}) {{ }} catch {{ rejected = true; }}
        require(rejected, "patched-market-accepted-underwater-loan");
        require(quote.balanceOf(address(trader)) == cashBefore,
                "patched-rejection-changed-wallet");
        require(quote.balanceOf(address(trader)) == {safe.q_wallet},
                "model-control-q-wallet-diverged");
        require(collateral.balanceOf(address(trader)) == {safe.c_wallet},
                "model-control-c-wallet-diverged");
        require(custody.locked(address(trader)) == {safe.pledged},
                "model-control-locked-diverged");
        require(lender.debt(address(trader)) == {safe.debt},
                "model-control-debt-diverged");
        assertConservation();
    }}
}}
'''


def generate(root: Path, output: Path, depth: int = DEPTH,
             budget: int = 30000) -> dict:
    path = root / "src" / "LocalLending.sol"
    if not path.is_file():
        raise FileNotFoundError(path)
    comparisons = [explore(policy=policy, guarded=guarded,
                           depth=depth, budget=budget)
                   for guarded in (False, True)
                   for policy in ("breadth_first", "goal_first")]
    bfs, guided, guarded_bfs, guarded_guided = comparisons
    if not bfs.found or not guided.found:
        raise RuntimeError("model candidate was not found by BOTH search policies")
    if guarded_bfs.found or guarded_guided.found:
        raise RuntimeError("guarded model allows a witness under the declared bounds")
    if guarded_bfs.exhausted or guarded_guided.exhausted:
        raise RuntimeError("guarded model exploration incomplete; cannot state no witness")
    end, rejected = replay(guided.plan, guarded=False)
    if rejected is not None or not violation(end) or end != guided.terminal:
        raise RuntimeError("candidate model trace invalid")
    safe, at = replay(guided.plan, guarded=True)
    if at is None or guided.plan[at][0] != "borrow":
        raise RuntimeError("guarded replay must reject the unsafe borrow")

    generated = root / "test" / "D21Generated.t.sol"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text(render(guided.plan, end, safe, at), encoding="utf-8")
    output.mkdir(parents=True, exist_ok=True)
    report = {
        "phase": "D2.1", "status": "CANDIDATE_AWAITING_EVM",
        "solidity_source_sha256": sha256(path.read_bytes()).hexdigest(),
        "generated_solidity_sha256": sha256(generated.read_bytes()).hexdigest(),
        "plan": [{"op": a, "amount": n} for a, n in guided.plan],
        "expected_final_model_state": asdict(end),
        "guarded_rejection_index": at,
        "guarded_prefix_state": asdict(safe),
        "comparisons": [asdict(x) for x in comparisons],
        "known_limitations": [
            "Human-authored finite-state model, oracle property and action domain",
            "Not a bytecode extractor, formal verifier or confirmed DeFi exploit",
            "A conventional stateful fuzzer is an independent strong baseline",
            "Reference price is a fixed laboratory safety condition",
            "No fees, interest, time, liquidations, MEV, flash loans or real tokens",
            "The pure model search excludes Foundry build, EVM and proof costs",
            "At most a finite search up to declared depth, not universal safety",
        ],
    }
    (output / "candidate.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("D2.1 model candidate (not yet confirmed):", report["plan"])
    for item in comparisons:
        print("RESULT", item.policy, "guarded", item.guarded,
              "found", item.found, "expanded", item.expanded,
              "attempted", item.attempted, "budget_exhausted", item.exhausted,
              "time", round(item.elapsed_seconds, 5))
    print("Foundry proof pending")
    return report


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("--root", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--depth", type=int, default=DEPTH)
    cli.add_argument("--budget", type=int, default=30000)
    args = cli.parse_args()
    generate(args.root, args.output, args.depth, args.budget)


if __name__ == "__main__":
    main()
