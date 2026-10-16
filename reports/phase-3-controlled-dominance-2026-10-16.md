# SCM-PRISM Phase 3 controlled structural-computation experiment — 2026-10-16

## Reproduction record

- Repository: nkinzogomer-eng/PRISM
- Pull request: #12
- CI run: https://github.com/nkinzogomer-eng/PRISM/actions/runs/38969083638
- Environment: Ubuntu hosted runner, Python 3.12.15, Linux x86_64
- Protocol version: 1
- Runs: 100 fixed seeds per regime, five regimes (500 total instances)
- Regression suite: 53 tests ran; 52 passed and one pre-existing, explicitly marked expected-failure test remained expected-failing.
- The Phase 2 reference benchmark also ran as part of the same test suite; the legacy comparison and transformation benchmark steps passed.

## Regime results

| Regime | Runs | Observations before → after | Mean removed | Runs with removal | Exact expected cost before → after | Mean delta | Verifier | Decision sets preserved | Cost never increased |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Favorable dominance | 100 | 3 → 2 | 1 | 100/100 | 2.50 → 2.50 | 0.00 | 100/100 | 100/100 | 100/100 |
| Cost reversal | 100 | 3 → 3 | 0 | 0/100 | 4.50 → 4.50 | 0.00 | 100/100 | 100/100 | 100/100 |
| Unrelated observations | 100 | 3 → 3 | 0 | 0/100 | 3.60 → 3.60 | 0.00 | 100/100 | 100/100 | 100/100 |
| Equal-cost duplicate | 100 | 4 → 3 | 1 | 100/100 | 3.60 → 3.60 | 0.00 | 100/100 | 100/100 | 100/100 |
| Chained dominance | 100 | 4 → 2 | 2 | 100/100 | 2.50 → 2.50 | 0.00 | 100/100 | 100/100 | 100/100 |

Across all 500 instances, every independent verifier passed, every exhaustive decision-set comparison passed, and the exact expected execution cost never increased. The mean exact expected-cost delta was exactly zero in every regime.

## Wall-clock diagnostics

The following values are paired runner diagnostics in seconds. “Pipeline after” is estimated as transformation wall time plus transformed exact-solver wall time; “pipeline before” is the untransformed exact-solver time. They are not abstract operation-cost units and are not portable performance guarantees.

| Regime | Transform mean (s) | Solver before (s) | Solver after (s) | Pipeline before (s) | Pipeline after (s) | Paired delta (s) |
|---|---:|---:|---:|---:|---:|---:|
| Favorable dominance | 0.000035374 | 0.000288025 | 0.000123255 | 0.000288025 | 0.000158630 | -0.000129396 |
| Cost reversal | 0.000024875 | 0.000281445 | 0.000277933 | 0.000281445 | 0.000302808 | +0.000021363 |
| Unrelated observations | 0.000023917 | 0.000232444 | 0.000267403 | 0.000232444 | 0.000291320 | +0.000058876 |
| Equal-cost duplicate | 0.000057342 | 0.000605166 | 0.000255945 | 0.000605166 | 0.000313287 | -0.000291879 |
| Chained dominance | 0.000045293 | 0.000585201 | 0.000149508 | 0.000585201 | 0.000194801 | -0.000390400 |

The timing signal is suggestive on this tiny exact-solver workload, but not sufficient for a speedup claim: these measurements are sub-millisecond, run on a shared hosted runner, and use a tiny exact reference solver. A dedicated repeated benchmark on target hardware and larger instances is needed to establish a robust wall-clock benefit.

## Adversarial model-scope test

- The independent verifier accepted the transformation relative to the declared hypothesis class.
- A deliberately omitted external world violated the declared relationship between the rich and coarse observations.
- This is not a contradiction in the verifier: the verifier checks the declared finite class, not whether that class covers the real world.

Therefore, the transformation's guarantee is conditional on the declared model being adequate. This experiment reinforces the existing requirement to distinguish internal certificates from external-world truth.

## Interpretation and decision

**Phase 3 engineering gate: PASS.** The existing dominated-observation transformation survived 500 controlled cases across favorable, negative, equal-cost, and chained regimes. Its safety checks correctly refused to prune when the cheaper observation was not dominated or when observations were unrelated.

**SCM scientific superiority: NOT ESTABLISHED.** Abstract optimal execution cost was unchanged in all regimes; the observed benefit was reduced representation size in regimes with valid dominance. Wall-clock results are only preliminary diagnostics. The experiment does not establish that a general SCM controller reduces total computation on arbitrary problems.

No production transformation was changed. No real-world cybersecurity, finance, astronomy, vulnerability discovery, zero-day, Red Team/Blue Team, or incident-repair task was tested.
