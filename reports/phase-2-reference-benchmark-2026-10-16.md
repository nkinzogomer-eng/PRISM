# SCM-PRISM Phase 2 reference benchmark — 2026-10-16

## Reproduction record

- Repository: nkinzogomer-eng/PRISM
- Pull request: #11 (Phase 2 benchmark suite)
- Primary measurement CI run: https://github.com/nkinzogomer-eng/PRISM/actions/runs/38967359906
- Final regression rerun after recording the report and phase status: https://github.com/nkinzogomer-eng/PRISM/actions/runs/38967580574
- Environment: Ubuntu hosted runner, Python 3.12.15, Linux x86_64
- Protocol version: 1
- Seeded run range: integers 0–99, 100 instances per seeded family
- Controls: one fixed parity instance (not a 100-instance estimate)
- Suite result: PASS; 52 tests ran, 51 passed and 1 pre-existing, explicitly marked expected-failure test remained expected-failing (`test_KNOWN_FAILURE_misspecified_world_must_not_be_certified_wrongly`). The new Phase 2 subprocess gate passed; existing comparison and transformation benchmark steps passed.

This report records the actual CI output. Correctness/cost results are reproducible for fixed seeds; wall-clock timings are runner-dependent diagnostics.

## Policy comparison

All percentages below are rates over each family. Execution cost is the generator's abstract operation-cost unit.

| Family | Policy | Runs | Certificates | Correct | Wrong certificate | Abstention | Mean execution cost | Mean planning (s, diagnostic) | Mean elapsed (s, diagnostic) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Sparse binary | Fixed-cost | 100 | 100% | 100% | 0% | 0% | 8.51 | 0.000002 | 0.000202 |
| Sparse binary | Seeded random | 100 | 100% | 100% | 0% | 0% | 10.25 | 0.000011 | 0.000195 |
| Sparse binary | Decision-disagreement | 100 | 100% | 100% | 0% | 0% | 12.21 | 0.000041 | 0.000232 |
| Sparse binary | Adaptive greedy | 100 | 100% | 100% | 0% | 0% | 11.72 | 0.000032 | 0.000091 |
| Misspecified | Fixed-cost | 100 | 100% | 48% | 52% | 0% | 4.91 | 0.000002 | 0.000119 |
| Misspecified | Seeded random | 100 | 100% | 29% | 71% | 0% | 6.74 | 0.000011 | 0.000119 |
| Misspecified | Decision-disagreement | 100 | 100% | 0% | 100% | 0% | 5.38 | 0.000021 | 0.000124 |
| Misspecified | Adaptive greedy | 100 | 100% | 14% | 86% | 0% | 5.07 | 0.000013 | 0.000046 |
| Parity control | Fixed-cost | 1 | 100% | 100% | 0% | 0% | 4.00 | 0.000002 | 0.000189 |
| Parity control | Seeded random | 1 | 100% | 100% | 0% | 0% | 4.00 | 0.000010 | 0.000192 |
| Parity control | Decision-disagreement | 1 | 100% | 100% | 0% | 0% | 4.00 | 0.000041 | 0.000218 |
| Parity control | Adaptive greedy | 1 | 100% | 100% | 0% | 0% | 4.00 | 0.000029 | 0.000084 |

### Exact expected-cost reference

| Family | Instances | Mean expected execution cost | Mean exact-solver runtime |
|---|---:|---:|---:|
| Sparse binary | 100 | 6.06 abstract units | 0.000782 s |
| Parity control | 1 | 4.00 abstract units | 0.000916 s |

The exact solver's expected cost is relative to the declared hypothesis class and its implicit uniform prior. It is not directly comparable to one policy's realized cost on a hidden world, and it is not an external-truth oracle.

## Structural transformation checks

| Metric | Decision-equivalence quotient | Dominated-observation pruning |
|---|---:|---:|
| Runs | 100 | 100 |
| Input size | 10 hypotheses | 2 observations |
| Output size | 8 hypotheses | 1 observation |
| Mean representation reduction | 20% | 50% |
| Independent verifier | 100/100 passed | 100/100 passed |
| Mean exact expected cost before | Not used as a probability-preserving rewrite | 1.00 abstract units |
| Mean exact expected cost after | Not used as a probability-preserving rewrite | 1.00 abstract units |
| Exact optimum preserved every run | Not claimed for uniform-prior quotient | Yes |
| Mean transformation runtime | 0.000028812 s | 0.000016193 s |

The quotient preserves decision sets, but merging duplicate hypothesis IDs changes their relative mass under a uniform prior. It must not be used as a probability-preserving rewrite. Its 20% representation reduction did not establish lower operation cost or total end-to-end cost.

Dominated-observation pruning is only applied when the retained observation determines the removed observation across every declared hypothesis and costs no more. This targeted experiment supports that specific rule under its finite deterministic assumptions, not a universal reduction theorem.

## Findings and negative results

1. **The fixed-cost baseline wins on the sparse-binary family.** Its mean cost (8.51) is lower than random (10.25), adaptive greedy (11.72), and decision-disagreement (12.21). The current adaptive heuristic is not an improvement on this task.
2. **The exact solver's mean expected cost is 6.06 under the declared model.** This is a useful reference optimum for small instances, but not a claim that a deployed policy can realize that expected cost on every hidden world.
3. **Model misspecification remains a severe reliability failure.** All policies certified a decision relative to the incomplete declared class in every run, yet their wrong-certificate rates were 52–100%. The runner abstained 0% of the time. A model-relative certificate is therefore insufficient evidence of external-world correctness.
4. **Decision-equivalence quotienting compresses the representation but does not prove execution savings.** The prior 20-seed benchmark also found no operation-cost improvement; this 100-seed suite confirms 20% representation reduction and successful verification, not runtime superiority.
5. **Dominated-observation pruning passes its narrow preservation test.** It halves the observation set and preserves the exact expected cost in all 100 constructed instances. The test family is deliberately favorable to the rule.
6. **Timing values are too small and runner-dependent to support portable speedup claims.** No energy, peak memory, real-world data, or real workload efficacy was measured.

## Phase 2 decision

**Engineering/reproducibility gate: PASS.** The 100-seed suite, independent transformation checks, exact-cost preservation checks, and existing regression suite passed in CI.

**Scientific superiority gate: NOT ESTABLISHED.** H-SCM-1 remains unproven. No general SCM advantage is demonstrated. The strongest result is a verified, narrowly scoped dominated-observation reduction under explicit assumptions; the clearest negative result is the persistent false-certification problem when the declared world set is incomplete.

These experiments do not validate real-world cybersecurity, financial-flow analysis, astronomy, zero-day discovery, incident repair, or Red Team/Blue Team performance.
