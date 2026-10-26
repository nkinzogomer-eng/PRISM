# PRISM D2.4O — Euler V1, post-debit guard discovery calibration

**26 October 2026 — narrow positive source-level result AND an independently
executed historical EVM account-health regression, NOT an extracted-profit
exploit, novel class or zero-day.** This is a **retrospective** test:
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
| Native Euler V1 EVM debt-health regression | **PASS: 1 original + 1 guard-control** |
| Full flash-loan/liquidation protocol-drain reproduction | **NOT PROVEN** |
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
- D2.4O introduces thirteen additional adversarial/unit tests.
- The historic public Euler V1 repository was successfully cloned into a
  temporary directory and read from the pinned commit; read-only status.
- A first local attempt to execute Euler's original Hardhat tests stopped
  before compilation: the 0.8.10 compiler download failed via the local
  environment proxy, and Hardhat warned that Node 24 is unsupported.
- The first **CI** native attempt failed before testing because the pinned
  2022 repository lacks a `package-lock.json`, making `npm ci` inapplicable.
- Repair: pin Node 18 on CI, install historical dependencies without lifecycle
  scripts using `npm install`, then run the real historical Solidity code
  on a local Hardhat EVM. This check **passed** with two independently
  executed JavaScript tests.

### Independently executed historical behavior

The original protocol's `EToken.sol` is verified against the exact historical
SHA-256 before execution. The native assertions first establish a healthy
account, with its TST2 collateral value approximately `0.6225` and the
TST debt liability value approximately `0.5`. Donating its collateral shares
to reserves then succeeds **on original Euler V1**, leaving collateral value
`0` while the debt liability remains approximately `0.5`.

The separate counterfactual adds **one** human-authored `checkLiquidity(account)`
call within `donateToReserves`, recompiles, and proves that the same proposed
donation is rejected with `e/collateral-violation`; the account's prior
collateral and debt values remain intact. Both tests execute Euler's real
module sources and normal test deployment harness on a local native EVM. The
counterfactual is not presented as an independently published patched revision.

**Independent green run:**
https://github.com/nkinzogomer-eng/PRISM/actions/runs/40335609330

This proves the historical missing-health-check consequence for a small
predeclared scenario; it does **not** reproduce the complete flash-loan,
liquidation bonus, full drainage, attacker profit or fee-neutrality sequence.

## Engineering changes

- `prism/d24o_guard_consistency.py`: bounded, self-contained peer-invariant
  generator, explicit UNKNOWN semantics, no incident-name lookup.
- `scripts/d24o_historical_euler.py`: pinned upstream, source SHA, verdict
  schema, JSON artifact, no capacity to upgrade source hypothesis to exploit.
- `tests/test_d24o_*`: multiple positive and adversarial negative controls.
- `benchmarks/defi/d24o/*.js` and `scripts/d24o_euler_native.py`: real protocol
  EVM regression, same-input guarded negative control, source restoration and
  full before/after stdout/stderr audit artifacts.
- `.github/workflows/d24o-euler-retrospective-guard.yml`: CPU-only remote
  reproduction, including immutable hash and no-false-claims assertions.

## Scientific conclusion and next independent proof gate

There is a **positive engineering advance**: PRISM can infer a concrete
post-debit obligation from three methods and highlight a historically real
source omission without matching an incident-specific function name. But the
rule was tailored during a retrospective analysis and is lexical; it cannot
yet reason over all inheritance, aliases, check paths or debt valuations.
An external native Ethereum execution has now **validated the resulting
known-class behavioral anomaly** on real historical code, but the scenario
and verification condition were human-authored in full awareness of the bug.

Next, automate a source-derived action sequence and cost-aware threat model
with real account/asset ledgers and a flash-loan repayment check, rather than
providing the sensitive sequence in a fixture. For independent generalization,
register a **separately frozen, previously uninspected** family and demand
actual EVM witnesses, patched controls, honest abstention and normalized
resource comparisons. Do not use this Euler run as a blinded score.

All source-only results MUST remain **UNVERIFIED** with respect to exploitable
vulnerabilities, irrespective of whether the automated source test passes.
