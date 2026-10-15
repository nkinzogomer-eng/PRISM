# Decision-equivalence quotient benchmark — 2026-10-15

## Protocol

- 20 fixed seeds on a synthetic finite deterministic problem.
- Each instance contains 8 distinct observation vectors plus 2 duplicate hypotheses that exactly match an existing observation vector and decision.
- Policies evaluated before and after the quotient: fixed-cost order, decision-disagreement order, seeded random order, and adaptive greedy.
- Hidden-world table and sampled hidden world are held constant before and after transformation.
- Structural verifier checks each quotient mapping independently.

## Results

- Mean declared hypothesis count: **10 → 8** (20% representational reduction).
- Independent structural checks: **20/20 passed**.
- Mean transformation time on the GitHub Actions runner: approximately **0.000045 seconds**. This is a noisy microbenchmark, not a portable performance claim.
- All policies achieved 100% correct certified decisions on these in-class cases before and after transformation; no wrong certificates or abstentions occurred.

| Policy | Mean execution cost before | Mean execution cost after | Change |
|---|---:|---:|---:|
| Fixed-cost order | 4.00 | 4.00 | 0.00 |
| Decision-disagreement order | 4.00 | 4.00 | 0.00 |
| Random order | 3.75 | 3.75 | 0.00 |
| Adaptive greedy | 4.00 | 4.00 | 0.00 |

Execution cost is the generator's abstract operation-cost unit, not wall-clock seconds.

## Interpretation

1. The transformation's decision-preservation claim passed the independent checks.
2. It reduced the declared hypothesis count by 20% in the targeted redundant family.
3. **It did not reduce realized operation cost in this experiment.** The transformation's benefit here is representational compression only; any claim of runtime or energy savings would need direct measurements on a larger workload.
4. The quotient does not preserve a uniform prior over hypothesis IDs when duplicates are removed. It must not be used as a probability-preserving rewrite, and the exact solver's uniform-prior expected cost may change.
5. This is a targeted synthetic validation of one transformation, not evidence that SCM generally outperforms existing methods.

## Next gate

Measure the transformation's own cost against the cost of any computation it saves, add larger and adversarially chosen cases, and only then test a second transformation such as safe constraint elimination or decision-focused slicing. Each transformation must have an explicit preservation claim and counterexample tests.
