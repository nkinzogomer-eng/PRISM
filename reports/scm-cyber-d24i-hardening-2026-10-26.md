# PRISM SCM-Cyber D2.4I — EVM verification gate, final laboratory evidence

Date: 2026-10-26. Status: **PASS for the bounded engineering gate**;
**NO-GO for claims of blind security discovery or scientific superiority**.

## Audit trail (public, immutable CI runs)

- Initial native EVM run, successful: [40296275622](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40296275622).
- First seeded attempt, failed: [40296822722](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40296822722).
- Exact reason diagnostic, failed: [40297344507](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40297344507).
- Per-trial failure-cache isolation, successful: [40297658920](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40297658920).
- **Mandatory three-budget seeded sweep, successful**: [40298101216](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40298101216).
- Source holdout companion on the same final revision: [40298101004](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40298101004).

GitHub Actions pins Foundry v1.3.6 for these EVM checks. The test input is a
purpose-built local D2.2 Solidity lab with exactly three **prelabelled**
mutations and one safe control. There are no real deposits or network attacks.

## Final locked EVM experiment

| Dimension | Actual observed result |
| --- | --- |
| Known mutant types | unauthorized oracle price update, insolvency-causing withdrawal, debt forgiveness without funded repayment |
| Safe control | 1 purpose-built safe variant |
| Independently selected Foundry seeds | fixed integers 1–8 |
| Budgets executed for **every** seed | 32 runs × 16 steps; 64 × 32; 256 × 64 |
| Native `forge test` processes | **96** (8 seeds × 3 budgets × 4 variants) |
| Detection of all known mutants | **8/8 seeds at each of the 3 budgets** |
| Spurious cross-family property counterexamples | **0 in this matrix** |
| Safe-control violations | **0 in this matrix** |
| Total native subprocess wall seconds, three-budget sweep | **65.3364 s** summed, not a single program execution time |
| Separate initial 64 × 32 campaign | 3/3 known mutants, 0 spurious, one budget attempt |
| New independent real vulnerabilities | **0** |
| Real Ciel-generated hypotheses exercised | **0** (proposer simulated) |
| Claimed verified Ciel security conclusions | **0** (`UNVERIFIED` by contract) |

Local complete Python regression: **325 tests executed; 324 passed and one
existing intentional expected failure**. The CI EVM workflow separately ran **44 D2.4I** and
**28 D2.4H** Python tests, then real Foundry EVM runs.

## Failure-driven correction and stronger follow-up

The first reproducibility stress run did **not** pass. Seed 1 at 32 × 16
returned `invariant_OracleOwnerOnly replay failure` instead of the expected
`D22_ORACLE_AUTH_WITNESS`. PRISM correctly rejected the result as an unknown
native-harness failure; it did not count the failure as a detected vulnerability.
Foundry's failure persistence had carried a prior counterexample into a
different seed/depth trial. We introduced distinct temporary invariant and
fuzz failure-persistence directories for **every** Forge invocation and
added a regression test that ensures one invocation cannot replay another's
failure artifact.

The isolated low-budget sweep then passed for eight seeds. Because passing
early is insufficient hardening, a new revision required **all three**
budgets to execute unconditionally for each seed; it also checks that a
late regression is not excused by an early success. The final CI run passed
this mandatory 96-process sweep. Raw stdout/stderr and JSON evaluations are
retained as workflow artifacts for independent inspection.

## Precisely what is — and is not — verified

- A **genuine** Foundry EVM run produces independently authored invariant
  verdicts; PRISM parses strict test inventories, reasons, process status,
  negative controls and output hashes, then checks a generic finite-trace
  hypothesis contract. Model proposals cannot rewrite the observer's data.
- The observations currently imported to Ciel/PRISM are **boolean invariant
  outcomes**, not independent transaction-level balance/debt traces. The
  Foundry invariant source encodes the security semantics; therefore this
  does **not** prove the semantics for an unknown protocol.
- The benchmark contains deliberately injected, already-known defect
  families and an explicit map to the expected mutant. This demonstrates
  known-defect verification on a controlled fixture, **not** novel class
  discovery, zero-day identification, or superiority over standard tools.
- The sum of subprocess wall durations in GitHub-hosted CI is not a calibrated
  CPU/GPU benchmark on consumer hardware. No statistically controlled
  precision/recall comparison against Echidna, Slither, Medusa, or auditors
  was executed in this stage.
- The separate four-package source holdout remained a negative result:
  **0 candidates, 0 new flaws** in its preregistered scope.

## Stop criterion for this specific engineering gate

All preset seeds, budgets, mutations, negative controls and Python oracles
passed on an independent CI runner. Stop expanding this **labelled** fixture:
extra repetitions of the same known defects would not establish novelty.
Freeze this as an integration baseline, retaining the unsuccessful runs in
the audit trail.

## Next scientific gate (not yet attempted)

1. Freeze an unseen DeFi contract cohort and a vulnerability-family holdout
   **before** generating any candidates or tuning PRISM to their labels.
2. Allow Ciel to propose syntactically and semantically bounded invariants,
   including candidates that do not match the three existing families.
3. Verify candidates through independently observable EVM transaction/state
   traces plus differential or metamorphic reference checks; distinguish
   semantic counterexample, harness error, false positive and unknown.
4. Measure recall, false positive rate, time, CPU and memory against frozen
   baseline tools on the same machine and budget; keep all negative results.

Until those tests exist and pass, neither zero-day discovery nor being
"unbeatable" on known classes is an evidenced claim.
