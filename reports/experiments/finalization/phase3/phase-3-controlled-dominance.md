# SCM-PRISM Phase 3: controlled structural-computation experiment

- Protocol version: 1
- Runs per regime: 100
- Seeds: 0–99
- Python: 3.12.3
- Platform: Linux-6.18.38+-x86_64-with-glibc2.39
- Synthetic finite deterministic experiments only.

## Regime results

| Regime | Runs | Mean observations before → after | Mean removed | Runs with removal | Mean exact cost before → after | Mean delta | Verifier | Decision sets | Cost never increased |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| favorable | 100 | 3.00 → 2.00 | 1.00 | 100 | 2.5000 → 2.5000 | 0.000000 | True | True | True |
| cost_reversal | 100 | 3.00 → 3.00 | 0.00 | 0 | 4.5000 → 4.5000 | 0.000000 | True | True | True |
| unrelated | 100 | 3.00 → 3.00 | 0.00 | 0 | 3.6000 → 3.6000 | 0.000000 | True | True | True |
| equal_cost_duplicate | 100 | 4.00 → 3.00 | 1.00 | 100 | 3.6000 → 3.6000 | 0.000000 | True | True | True |
| chain | 100 | 4.00 → 2.00 | 2.00 | 100 | 2.5000 → 2.5000 | 0.000000 | True | True | True |

## Wall-clock diagnostics

Pipeline wall time is estimated as transform time + transformed exact-solver time and compared with the untransformed exact-solver time. All values are runner-dependent diagnostics; abstract operation-cost units are not added to seconds.

| Regime | Transform (s) | Solver before (s) | Solver after (s) | Pipeline before (s) | Pipeline after (s) | Paired delta (s) |
|---|---:|---:|---:|---:|---:|---:|
| favorable | 0.000024213 | 0.000252483 | 0.000111744 | 0.000252483 | 0.000135957 | -0.000116526 |
| cost_reversal | 0.000018452 | 0.000243409 | 0.000242003 | 0.000243409 | 0.000260454 | 0.000017046 |
| unrelated | 0.000017887 | 0.000202748 | 0.000234836 | 0.000202748 | 0.000252723 | 0.000049975 |
| equal_cost_duplicate | 0.000039495 | 0.000509758 | 0.000222587 | 0.000509758 | 0.000262083 | -0.000247675 |
| chain | 0.000030571 | 0.000496371 | 0.000135605 | 0.000496371 | 0.000166176 | -0.000330195 |

## Omitted-world counterexample

- Declared-class verifier passed: **True**
- Omitted world violates declared dominance: **True**
- Interpretation: The rewrite is valid relative to the declared class only; this does not establish external-world completeness.

## Hard gates

- all_independent_verifiers_passed: **True**
- all_decision_sets_preserved: **True**
- exact_expected_cost_never_increased: **True**
- counterexample_exposes_model_relative_scope: **True**
- positive_and_negative_regimes_present: **True**
- equal_cost_tie_break_is_safe: **True**
- chain_dominance_reduces_multiple_observations: **True**

## Limits

- Only one existing transformation is studied: dominated-observation pruning.
- Decision and exact-cost claims are relative to finite deterministic declared hypothesis classes.
- Abstract operation-cost units and wall-clock seconds are separate dimensions and are not added together.
- Solver wall time is diagnostic and reflects the exact reference solver, not a deployed policy.
- Favorable families are deliberately structured to satisfy transformation preconditions.
- No real-world cybersecurity, finance, astronomy, repair, or zero-day efficacy was measured.
