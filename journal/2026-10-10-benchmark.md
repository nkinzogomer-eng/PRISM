# PRISM Benchmark Step: 2026-10-10

## Completed

The first executable reference layer is now specified for finite deterministic hypothesis spaces.

Added:

- `docs/benchmark.md`: instance schema, sufficiency rule, certificate requirements, costs, generator families, baselines, metrics, and acceptance gates.
- `prism/reference.py`: explicit hypotheses, observations, immutable states, cost accounting, decision partitions, certificate construction, independent verification, and explicit abstention.
- `tests/test_reference.py`: contract tests for decision sufficiency, non-identification, certificate rejection, inconsistency handling, abstention, and invalid operations.

## Deliberate limits

This is not yet the PRISM selector. It is the semantic reference layer. No planning heuristic is allowed to hide inside it. The hidden world, adaptive policies, noisy outcomes, probabilistic risk, symbolic hypotheses, and domain adapters remain outside this first layer.

## Important design choice

The reference layer treats a decision as certified only when the compatible hypotheses all imply exactly one decision and the independent verifier accepts the certificate. It does not infer correctness from a unique model, high information gain, or a successful execution alone.

## Next step

Add deterministic replay and the exact optimal adaptive-policy solver for small instances. Then compare simple policies before introducing PRISM's structural selector.

## Stop condition

If the reference semantics cannot pass its contract tests or if the exact-policy comparison exposes an unsound stopping rule, no higher-level PRISM mechanism should be added.
