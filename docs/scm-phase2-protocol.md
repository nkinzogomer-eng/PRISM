# SCM-PRISM Phase 2: reference baselines and reproducible measurements

**Status:** protocol implemented; Phase 2 remains unchecked until the expanded suite passes and its results are reviewed.

## Purpose

Establish reproducible reference measurements before any new structural planner is implemented. This phase tests the measurement apparatus and existing finite PRISM methods, not general SCM superiority.

## Compared methods

- Fixed-cost observation order: transparent low-overhead baseline.
- Seeded random order: reproducible weak baseline.
- Decision-disagreement order: existing decision-focused heuristic.
- Adaptive greedy: existing adaptive heuristic; planning cost must not be free.
- Exact expected-cost solver: small-instance optimum relative to the declared hypothesis class and implicit uniform prior, not external truth or a scalable baseline.
- Decision-equivalence quotient: representation reduction and decision-set preservation; it does not necessarily preserve the uniform prior over hypothesis IDs.
- Dominated-observation pruning: only removes an observation when a retained observation determines it for every declared hypothesis and costs no more.

## Reproducibility

- Fixed integer seeds, range recorded in output.
- No third-party Python dependencies.
- The runner writes machine-readable JSON and Markdown to its output directory. The CI test uses a temporary directory and prints summaries into the job log; local runs can retain files by choosing a persistent output directory.
- 100 seeds per seeded family by default; allowed range 20–200.
- Wall-clock timings are diagnostics only. Abstract operation-cost units are not converted into seconds or energy.

## Hard acceptance gates

1. Existing unit tests and benchmark steps pass.
2. The expanded 100-seed suite completes in CI.
3. The independent quotient verifier passes every generated run.
4. The independent dominated-pruning verifier passes every run.
5. Exact expected execution cost before and after dominated pruning agrees on every run.
6. Outputs include decision quality, abstention/wrong-certificate rates, execution cost, planning and elapsed time, exact references, transformation counts/costs, environment, seeds, and limitations.
7. Misspecification results remain visible and are not averaged into in-class correctness.
8. No structural planner or production algorithm is added during Phase 2.

## Failure and negative-result policy

Any verifier failure, exact-optimum mismatch, missing metric, nondeterministic correctness result for fixed seeds, or CI failure blocks the phase. If adaptive selection is worse than fixed-cost order, report that plainly. If a transformation shrinks representation without reducing operation cost, report representation compression only. High wrong-certificate rates under omitted-world tests remain a failure of external-world reliability. Noisy timing differences remain inconclusive.

## Scope limits

These are synthetic finite deterministic tasks, not real-world cyber, financial-flow, or astronomy benchmarks. They provide no evidence of vulnerability discovery, prevention, repair, or zero-day capability. Phase 2 does not prove H-SCM-1.

## Decision rule

Review the generated report after CI. Check Phase 2 only if all gates pass and limitations/negative results are documented. Phase 3 should then test one controlled structural transformation against these baselines with held-out cases and explicit counterexamples.
