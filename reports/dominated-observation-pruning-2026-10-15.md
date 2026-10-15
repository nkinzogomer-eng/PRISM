# Dominated-observation pruning benchmark — 2026-10-15

## Protocol

- 20 fixed seeds on a small finite deterministic model.
- The model has two observations: `rich` costs 1 unit and reveals a two-bit value; `coarse` costs 2 units and reveals only the first bit.
- The decision is determined by the second bit.
- The transformation removes an observation only when a retained observation determines it across every declared hypothesis and costs no more.
- The independent verifier checks the dominance witness and the transformed problem's preserved hypotheses, decisions, retained observation values, and costs.

## Results

| Metric | Result |
|---|---:|
| Runs | 20 |
| Mean observations before | 2 |
| Mean observations after | 1 |
| Observation-count reduction | 50% |
| Independent checks passed | 20/20 |
| Mean exact expected execution cost before | 1.00 units |
| Mean exact expected execution cost after | 1.00 units |
| Uniform hypothesis prior preserved | Yes |
| Mean transformation runtime on CI runner | approximately 0.000023 seconds |

## Interpretation

This targeted case verifies the intended property: the more expensive coarse observation is determined by a cheaper richer observation, so removing the coarse operation preserves the exact optimal expected execution cost while reducing the operation set by 50%.

The result does **not** establish general SCM superiority. The model is deliberately constructed to satisfy the dominance precondition, and timing is a noisy microbenchmark. The important contribution is the auditable rule and its verifier: a transformation is applied only when the declared model provides a checkable witness.

## Limits

- The proof is relative to the declared finite deterministic hypothesis class.
- It does not establish that the declared class contains the real world.
- No real program, vulnerability, astronomy dataset, or large-scale workload was evaluated.
- The next validation should include adversarial cases where observations are nearly—but not fully—determined by another observation, as well as larger hypothesis spaces.
