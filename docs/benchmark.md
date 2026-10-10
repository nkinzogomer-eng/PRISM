# PRISM Finite Benchmark

Status: reference benchmark specification.

## Purpose

This benchmark tests the PRISM kernel before any domain adapter. It separates decision sufficiency from model identification and makes planning cost measurable.

## Instance schema

```text
Instance = {
  hypotheses: finite list of Hypothesis,
  observations: finite list of Observation,
  hidden_world: one hypothesis used only by the generator,
  target: DecisionTarget,
  initial_evidence: Evidence,
  budget: CostVector,
  semantics: deterministic | probabilistic | adversarial,
  verifier: independent certificate checker
}
```

The solver receives every field except `hidden_world`. The hidden world is used only to score correctness after execution. A benchmark runner must prevent the solver from reading generator metadata or test labels.

### Hypothesis

Each hypothesis defines:

```text
Hypothesis = {
  id,
  observation_value(observation_id),
  decision(target),
  metadata_for_analysis_only
}
```

### Observation

```text
Observation = {
  id,
  cost,
  possible_values,
  value_for(hypothesis)
}
```

An observation is deterministic in the first benchmark. An operation reveals its value for the hidden world and filters compatible hypotheses to those with the same value.

## Decision sufficiency

For compatible hypothesis set `H`, define:

```text
D(H) = { h.decision(target) for h in H }
```

The state is decision-sufficient exactly when `len(D(H)) == 1`. Full hypothesis identification is not required.

A certificate contains the declared hypothesis-class identifier, observed operation/value pairs, compatible hypothesis identifiers or an independently checkable symbolic equivalent, the unique decision, and the verifier version.

The verifier recomputes compatibility and decision invariance. It must reject a certificate with an empty hypothesis set, multiple decisions, unknown observations, or unsupported assumptions.

## Cost accounting

Every run reports planning, execution, verification, representation, preprocessing, memory, and communication costs. The initial simulator uses scalar planning and execution costs, but the vector remains part of the interface.

## Required generator families

1. Sparse relevance.
2. Distractors.
3. Heterogeneous costs.
4. Misleading information gain.
5. Parity.
6. Dense dependency.
7. Misspecification, where the hidden world is omitted from the declared hypothesis class.

## Baselines

Random eligible observation, fixed order, maximum hypothesis reduction, maximum decision disagreement, cost-normalized decision disagreement, exact optimal adaptive policy for small instances, and the PRISM transparent bounded selector.

The exact policy is an execution-cost reference. Its planning cost must not be silently treated as free.

## Required metrics

Certified decision rate, incorrect non-abstention rate, correct abstention rate, abstention rate, total cost by component, gap to exact execution optimum, planning overhead, certificate verification cost, tail cost, and deterministic replay success.

## Acceptance gates

Before adding domain adapters:

1. zero incorrect certified decisions on in-class deterministic instances;
2. zero accepted certificates with multiple compatible decisions;
3. correct abstention on omitted-world instances;
4. exact-policy comparison on small instances;
5. explicit losses on parity and dense controls;
6. all costs included in every comparison;
7. fixed seeds and reproducible traces.
