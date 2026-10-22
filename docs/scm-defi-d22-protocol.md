# PRISM D2.2: protocol for 3-property/4-variant local DeFi research

**22 October 2026. Development only; no result before CI.**
The experiment deliberately uses an authored laboratory market, not an unaudited real protocol.

## Twelve frozen conditions

Three properties defined *before* evaluating the engine and Foundry:
- **ORACLE_AUTH:** a trader other than the oracle's owner must not update the reference price.
- **WITHDRAW_SOLVENCY:** borrowing then withdrawing collateral must not leave the account above its current loan-to-value limit.
- **REPAY_CONSERVATION:** a reduction in the borrower's debt attributed to a repayment must be matched by an actual transfer of the loan asset from the borrower to the pool.

Four fixture variants: one failing oracle authorization, one failing withdrawal solvency, one forgiving repayments without token transfer, and an all-safe version. Each intentionally injected defect is exposed in only its own variant. Target: **3 known positives / 9 known negatives** across the 4 × 3 grid. These are developer-known labels, NOT a sealed holdout. The results cannot be presented as sensitivity on unknown DeFi bugs.

## Equal-property adversaries

1. **PRISM model:** deterministic bounded model, ten parameterized actions (`deposit`, `borrow`, `withdraw`, `repay`, `price`), depth max four, state budget 50k, guided priority and independent BFS over identical transitions. Search completes all twelve cells, including negatives, without budget exhaustion; incomplete cells cannot be scored as true negatives.
2. **Independent EVM verification:** emit six generated Solidity tests (three vulnerable EVM confirmations and three patched counterfactuals). Check every predicted balance, price and loan balance and property witness. A Python-model result is never called an EVM-confirmed finding before tests succeed.
3. **Strong native baseline:** genuine Foundry **stateful** invariant campaign driven by a handler and `targetContracts()`; 256 runs × 64 operations max, `fail_on_revert=false`, five handler functions (deposit, borrow, withdraw, repay, price). Executes independently of PRISM/its trace. Each intentionally vulnerable fixture must fail with its **correct property-specific reason**; the safe fixture must pass all invariants, including token conservation. Preserve raw Forge JSON; an ordinary fuzz test with predefined transaction order is not an adequate replacement.
4. **Score at property/variant level:** true positives must be backed by independent EVM outcomes and expected-vs-observed property identity; wrong class, duplicated incident, false positive on safe or other-class variant must be counted honestly. Record failures to discover a known positive and budget limits as such. Separate the verification, compilation, model-search and fuzzing costs; do not divide model transitions by Forge elapsed time or imply an overall speedup.

## Scientific limits

The contracts, semantics and heuristic are hand-authored together with the oracle and goal specification: **massive development leakage**. No extraction of properties from source, historical incident inference, novel vulnerability or zero-day discovery. The Foundry handler uses the same property definitions and is a strong **reproduction baseline**, not a complete third-party SAST or multi-contract symbolic analyzer. Absence of a witness in this bounded graph or fuzz campaign is not a formal security proof.

No mainnet forks, no money, no external attack or live target. All assets are synthetic and the price reference is fixed artificially. A real lending market may legitimately be undercollateralized following market moves; this experiment targets specifically unauthorized oracle update and missing checks.

A decisive SCM-specific advance would require better confirmed discovery/precision at equal full-budget cost on **independent blind** real-world cases compared with properly configured Foundry, Echidna, symbolic analyses and strong invariant generators. Do not claim such gains from this experiment.

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_d22_*.py' -v
python -m scripts.d22_explore --root benchmarks/defi/d22 --output reports/d22-ci
cd benchmarks/defi/d22
forge test --match-contract D22GeneratedWitnessTest --json
forge test --match-contract D22AllSafeStatefulTest --json
# Deliberately fail for precisely the named security violation:
forge test --match-contract D22OracleBugStatefulTest --json
forge test --match-contract D22WithdrawBugStatefulTest --json
forge test --match-contract D22RepayBugStatefulTest --json
```
