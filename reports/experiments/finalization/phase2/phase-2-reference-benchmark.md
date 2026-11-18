# SCM-PRISM Phase 2 reference benchmark

- Protocol version: 1
- Runs per seeded family: 100
- Python: 3.12.3
- Platform: Linux-6.18.38+-x86_64-with-glibc2.39
- Scope: finite synthetic deterministic instances only.

## Policy comparison

# PRISM finite synthetic policy comparison

- Seed policy: integer seeds 0..99; parity control has fixed hidden world
- Runs per seeded family: 100
- Synthetic finite deterministic tasks only; not evidence of real-world cyber efficacy.

| Family | Policy | Runs | Certified | Correct certified | Wrong certificate | Abstention | Mean execution cost (units) | Mean planning (s) | Mean elapsed (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| misspecified | adaptive_greedy | 100 | 1.000 | 0.140 | 0.860 | 0.000 | 5.070000 | 0.000009 | 0.000049 |
| misspecified | decision_disagreement_order | 100 | 1.000 | 0.000 | 1.000 | 0.000 | 5.380000 | 0.000015 | 0.000095 |
| misspecified | fixed_cost | 100 | 1.000 | 0.480 | 0.520 | 0.000 | 4.910000 | 0.000001 | 0.000105 |
| misspecified | random_order | 100 | 1.000 | 0.290 | 0.710 | 0.000 | 6.740000 | 0.000007 | 0.000091 |
| parity_control | adaptive_greedy | 1 | 1.000 | 1.000 | 0.000 | 0.000 | 4.000000 | 0.000022 | 0.000087 |
| parity_control | decision_disagreement_order | 1 | 1.000 | 1.000 | 0.000 | 0.000 | 4.000000 | 0.000027 | 0.000189 |
| parity_control | fixed_cost | 1 | 1.000 | 1.000 | 0.000 | 0.000 | 4.000000 | 0.000001 | 0.000146 |
| parity_control | random_order | 1 | 1.000 | 1.000 | 0.000 | 0.000 | 4.000000 | 0.000006 | 0.000144 |
| sparse_binary | adaptive_greedy | 100 | 1.000 | 1.000 | 0.000 | 0.000 | 11.720000 | 0.000024 | 0.000092 |
| sparse_binary | decision_disagreement_order | 100 | 1.000 | 1.000 | 0.000 | 0.000 | 12.210000 | 0.000029 | 0.000172 |
| sparse_binary | fixed_cost | 100 | 1.000 | 1.000 | 0.000 | 0.000 | 8.510000 | 0.000002 | 0.000155 |
| sparse_binary | random_order | 100 | 1.000 | 1.000 | 0.000 | 0.000 | 10.250000 | 0.000007 | 0.000144 |

## Exact reference (declared model only)

| Family | Runs | Mean expected execution cost (units) | Mean solver runtime (s) |
|---|---:|---:|---:|
| sparse_binary | 100 | 6.060000 | 0.000680 |
| parity_control | 1 | 4.000000 | 0.000802 |

## Interpretation limits

- Synthetic finite deterministic instances only; no external-world or real vulnerability claims.
- A declared-class certificate can be wrong when the true world is omitted; this is scored separately.
- Execution cost is the generator's abstract operation-cost unit, not wall-clock seconds.
- Planning, verification, and elapsed seconds are hardware/runner dependent.
- The exact solver is an expected execution-cost reference under the declared model; its planning/runtime is reported separately.

## Decision-equivalence quotient

| Metric | Result |
|---|---:|
| Runs | 100 |
| Mean hypotheses before -> after | 10.000 -> 8.000 |
| Mean reduction fraction | 20.000% |
| Independent checks all passed | True |
| Mean transformation time (seconds; diagnostic) | 0.000021402 |

Execution-cost results before and after are in the JSON artifact under decision_equivalence_quotient.before and .after.
The quotient preserves decision sets but does not preserve a uniform prior over hypothesis IDs in general.

## Dominated-observation pruning

| Metric | Result |
|---|---:|
| Runs | 100 |
| Mean observations before -> after | 2.000 -> 1.000 |
| Mean reduction fraction | 50.000% |
| Independent checks all passed | True |
| Exact expected cost before -> after | 1.000000 -> 1.000000 abstract units |
| Exact optimum preserved in every run | True |
| Mean transformation time (seconds; diagnostic) | 0.000011149 |

## Hard gates

- quotient_independent_checks: **True**
- pruning_independent_checks: **True**
- pruning_exact_optimum_preserved: **True**
- uniform_prior_preserved_by_pruning: **True**

## Interpretation limits

- Synthetic finite deterministic instances only; no real-world cyber, finance, or astronomy efficacy claim.
- Execution costs are abstract operation-cost units and cannot be added to seconds without an explicit calibration.
- Wall-clock values are runner-dependent diagnostics, not portable speedup claims.
- The exact solver is a small-instance reference relative to the declared model and its implicit uniform prior.
- The quotient preserves decision sets but not necessarily the uniform prior over hypothesis IDs.
- The dominated-observation result applies only where its finite deterministic dominance witness is valid.
- A certificate over an incomplete declared hypothesis class can still disagree with hidden truth.
