# PRISM finite synthetic policy comparison — 2026-10-15

## Protocol

- Implementation: PRISM comparison script in `scripts/run_comparison.py`.
- Runtime: GitHub Actions, Ubuntu 24.04, Python 3.12.
- Seeded families: 20 fixed seeds (`0..19`) each for `sparse_binary(n=4, support=2)` and `misspecified(n=3, support=2)`.
- Control: one `parity(n=4)` instance. This generator currently fixes its hidden world, so it is a single control case, not a 20-instance estimate.
- Compared policies: fixed-cost order, seeded random order, decision-disagreement order, and adaptive greedy selection.
- Exact reference: expected observation execution cost from the exact solver on the declared model, for sparse-binary and parity only.
- The hidden world is used only for post-run scoring. A certificate is evaluated separately for model-relative validity and agreement with hidden truth.

## Results

### Decision quality and abstract execution cost

| Family | Policy | Runs | Certified | Correct certified | Incorrect certificate | Abstention | Mean execution cost (units) |
|---|---|---:|---:|---:|---:|---:|---:|
| Sparse binary | Adaptive greedy | 20 | 100% | 100% | 0% | 0% | 11.95 |
| Sparse binary | Decision-disagreement order | 20 | 100% | 100% | 0% | 0% | 12.35 |
| Sparse binary | Fixed-cost order | 20 | 100% | 100% | 0% | 0% | 9.50 |
| Sparse binary | Random order | 20 | 100% | 100% | 0% | 0% | 10.30 |
| Parity control | Adaptive greedy | 1 | 100% | 100% | 0% | 0% | 4.00 |
| Parity control | Decision-disagreement order | 1 | 100% | 100% | 0% | 0% | 4.00 |
| Parity control | Fixed-cost order | 1 | 100% | 100% | 0% | 0% | 4.00 |
| Parity control | Random order | 1 | 100% | 100% | 0% | 0% | 4.00 |
| Misspecified | Adaptive greedy | 20 | 100% | 10% | 90% | 0% | 5.20 |
| Misspecified | Decision-disagreement order | 20 | 100% | 0% | 100% | 0% | 5.45 |
| Misspecified | Fixed-cost order | 20 | 100% | 45% | 55% | 0% | 5.05 |
| Misspecified | Random order | 20 | 100% | 25% | 75% | 0% | 6.65 |

“Certified” means the finite verifier accepted a decision relative to the declared hypothesis class. “Correct certified” means that decision also matched the hidden world's decision. These are deliberately separate metrics.

### Exact expected execution-cost reference

| Family | Instances | Mean expected cost (units) | Mean solver runtime (seconds) |
|---|---:|---:|---:|
| Sparse binary | 20 | 6.20 | 0.001129 |
| Parity control | 1 | 4.00 | 0.001182 |

The exact solver's expected cost is relative to its declared hypothesis model. It is not an end-to-end cost baseline: solver runtime is shown separately, and the expected-cost number is not directly comparable to the realized cost of a policy on an individual hidden world.

## Interpretation

1. **No SCM advantage is demonstrated here.** On the sparse-binary family, fixed-cost order has lower mean execution cost (9.50 units) than adaptive greedy (11.95), decision-disagreement order (12.35), and random order (10.30). The current adaptive heuristic is not an improvement on this benchmark.
2. **The parity control behaves as expected.** Every policy needs all four bits, so all incur 4.00 execution-cost units. This is one control instance only.
3. **The misspecification failure remains severe.** All four policies obtain model-relative certificates on all 20 runs, yet those decisions are wrong in 55–100% of runs depending on policy. A certificate over an incomplete declared class does not establish real-world correctness.
4. **The result supports stronger misspecification handling, not a claim of success.** PRISM needs a calibrated abstention or independent validation strategy when model completeness is uncertain. The current runner cannot infer universal model completeness from finite observations.
5. **Planning-time numbers are not decision-grade evidence at this scale.** They are sub-millisecond measurements on a shared CI runner and are sensitive to runtime noise. Execution-cost units are abstract generator costs, not seconds.

## Limitations and next scientific gate

- These are synthetic finite deterministic tasks, not real programs, vulnerabilities, astronomy data, or evidence of zero-day discovery.
- The seeded families are small; the parity control has only one instance.
- The exact solver's cost assumes the declared class and its implicit uniform distribution; the misspecified family is excluded from the exact reference.
- No confidence intervals or broad hardware comparison are claimed.
- Next: preserve these results as the baseline, then add audited structural transformations and compare them against the same baselines on held-out instances. The first target should be a specific transformation with explicit preservation conditions, measured cost, and a counterexample suite.
