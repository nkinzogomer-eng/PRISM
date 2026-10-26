# PRISM D2.4O — Euler V1, post-debit guard discovery calibration

**26 October 2026 — narrow positive source-level result, NOT a validated
economic exploit, novel class or zero-day.** This is a **retrospective** test:
the Euler incident and its missing post-donation health check were already
publicly known when the rule was developed. The implementation was also
improved after inspecting Euler's source, so this is not a blind holdout.

## Reproducibility and exact historical source

- Official archival upstream: https://github.com/euler-legacy-xyz/euler-contracts
- Last relevant `EToken.sol` source change before the incident:
  `b1ee3265853628d5a529081d7908c38404201b4e` (September 2022).
- Filename: `contracts/modules/EToken.sol`.
- Git blob SHA-1: `8ab8d85a96b328f16c6004bb87c2ee8fdcb93b82`.
- Source SHA-256: `e16bcbe5efa32f3b0538ed3f6ec29a2d64dbbff622b9712d129191731a79cd8b`.
- No RPC, chain access, model call, paid API or GPU is required by the trial.

## Result

1. Inspect **25** function declarations, identifying **4** functions with
   source evidence of potentially decreasing account balances.
2. Infer, from three *peer* functions (`withdraw`, `burn`, `transferFrom`), a
   common post-debit `checkLiquidity` obligation. The detection rule does not
   list `donateToReserves` as a searched-for target method.
3. Find one source-only anomaly: `donateToReserves` reduces the caller's
   eToken balance via a derived replacement and lacks that post-debit check.
4. Additional tests reject misleading evidence from unrelated balance
   increases, check-before-debit ordering and both braced and unbraced
   conditional checks. A controlled, **human-added** post-debit check removes
   the source anomaly; this does not independently validate an upstream fix.

### Measured outcome

| Gate | Result |
| --- | --- |
| Historical source pinned and SHA-256 verified | PASS |
| Exactly one historical source-level candidate | PASS (`donateToReserves`) |
| Guard post-position and conditional negatives | PASS |
| Hypothesis derivation independent of function's incident name | PASS on constructed rename |
| Actual Euler V1 EVM exploit replay | **NOT RUN / UNKNOWN** |
| Demonstrated drain/profit with limited upfront capital | **NOT PROVEN** |
| Novel vulnerability or zero-day | **0** |
| Matched baseline advantage | **NOT MEASURED** |

The source signal agrees with Euler's published analysis of the March 2023
incident: https://www.euler.finance/blog/war-peace-behind-the-scenes-of-eulers-240m-exploit-recovery .
Agreement is corroboration of a **known root-cause hypothesis**, not an
independent proof of economic impact or scientific generalization.

### Verification environment / failure trace

- Baseline local Python suite before D2.4O: 404 tests, with one previously
  expected failure.
- D2.4O introduces ten additional adversarial/unit tests.
- The historic public Euler V1 repository was successfully cloned into a
  temporary directory and read from the pinned commit; read-only status.
- An attempt to execute Euler's original Hardhat `reservesDonate.js` tests
  stopped before Solidity compilation: Hardhat requires compiler 0.8.10,
  whose download failed via the execution environment proxy. The installed
  Hardhat 2.11.2 also warns that Node 24 is unsupported. This is a **blocked
  verification**, never to be counted as a passed EVM test.

## Engineering changes

- `prism/d24o_guard_consistency.py`: bounded, self-contained peer-invariant
  generator, explicit UNKNOWN semantics, no incident-name lookup.
- `scripts/d24o_historical_euler.py`: pinned upstream, source SHA, verdict
  schema, JSON artifact, no capacity to upgrade source hypothesis to exploit.
- `tests/test_d24o_*`: multiple positive and adversarial negative controls.
- `.github/workflows/d24o-euler-retrospective-guard.yml`: CPU-only remote
  reproduction, including immutable hash and no-false-claims assertions.

## Scientific conclusion and next independent proof gate

There is a **positive engineering advance**: PRISM can infer a concrete
post-debit obligation from three methods and highlight a historically real
source omission without matching an incident-specific function name. But the
rule was tailored during a retrospective analysis and is lexical; it cannot
yet reason over all inheritance, aliases, check paths or debt valuations.

Next, supply an independent EVM test of an indebted account donating
collateral on the **exact original historical sources**, measure account
health and liquidity/liquidation feasibility before and after, then run an
identical control with the guard restored. This requires a pinned suitable
compiler and complete protocol harness. Only after that proof can we test a
**separately frozen, previously uninspected** family for real generalization.

All source-only results MUST remain **UNVERIFIED** with respect to exploitable
vulnerabilities, irrespective of whether the automated source test passes.
