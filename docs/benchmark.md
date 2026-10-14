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

Each observation defines:

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

A certificate contains the declared hypothesis-class identifier, explicit scope, observed operation/value pairs, compatible hypothesis identifiers or an independently checkable symbolic equivalent, the unique decision, and the verifier version. The finite reference verifier can accept only `declared_hypothesis_class` scope. External-world scope requires an independent validator; without one, consumers requiring that guarantee must abstain.

The verifier recomputes compatibility and decision invariance. It must reject a certificate with an empty hypothesis set, multiple decisions, unknown observations, or unsupported assumptions. A model-relative certificate on an omitted-world instance is scored against the hidden world, so incorrect non-abstentions remain visible even though the relative claim itself verifies.

## Cost accounting

Each completed run reports a component vector:

```text
planning, execution, verification, representation,
preprocessing, memory, communication
```

The order-policy evaluator measures planning and certificate-checking time in seconds. It passes the policy a declared-only view with no hidden-world table. Observation execution is reported using the benchmark's declared operation cost model. Each benchmark must state the measurement method and units for every component.

Planning is mandatory for every policy run; a baseline never receives free planning by omission. An unavailable measurement is recorded as unknown, not zero. Representation, preprocessing, memory, and communication remain unknown unless the benchmark supplies measurements for them.

Report the component vector for the first run in the measured sequence, the component-wise arithmetic mean across repeated runs (amortized cost), and component-wise maximum (tail cost). The first run is not a process-level cold start unless process initialization is included in the measurement. Do not add unlike units into one number. A scalar total is valid only when the benchmark declares weights for every component and all required measurements are available.

The exact solver currently reports expected observation execution cost only. It is an execution-cost reference, not a free end-to-end baseline; solver planning/runtime cost remains unmeasured until the benchmark supplies it.

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

Certified decision rate, incorrect non-abstention rate, correct abstention rate, abstention rate, invalid-instance count, first-run and amortized cost by component, component-wise tail cost, gap to exact execution optimum, planning overhead, certificate verification cost, and deterministic replay success.

Rates use all runs as their denominator. A correct decision means a certified decision equal to the hidden decision. An incorrect non-abstention is a certified decision that disagrees with hidden truth. A correct abstention is an `ABSTAIN` result where the final declared state is contradictory or still contains multiple possible decisions.

## Acceptance gates

Before adding domain adapters:

1. zero incorrect certified decisions on in-class deterministic instances;
2. zero accepted certificates with multiple compatible decisions;
3. correct model-relative scope labeling on omitted-world instances, with incorrect non-abstentions scored against the hidden world;
4. contradiction produces abstention;
5. exact-policy comparison on small instances;
6. explicit losses on parity and dense controls;
7. all measurable costs included in every comparison, with unknown costs reported explicitly;
8. fixed seeds and reproducible traces.
