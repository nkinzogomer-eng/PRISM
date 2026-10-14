# PRISM Operational Architecture

Status: pre-implementation design. This document turns the core specification into implementable contracts.

## 1. Separation of responsibilities

PRISM has two layers.

### Core controller

The core manages immutable evidence state, hypothesis compatibility, decision partitions, operation selection, budgets, provenance, stopping, and abstention.

### Domain adapter

An adapter supplies hypothesis compatibility, operation semantics and execution, the decision function, safe bounds/dependencies, witness construction, independent verification, and domain-specific failure classification.

The adapter must not provide hidden labels, future observations, or an oracle unavailable to comparison baselines.

## 2. Immutable state

At iteration `t`:

```text
State_t = {
  evidence,
  constraints,
  hypothesis_view,
  decision_partition,
  bounds,
  dependency_summary,
  remaining_budget,
  provenance
}
```

Operations return new information. They do not erase prior evidence. Every derived object records its parents. The initial assumptions and their provenance are part of the state.

An empty or invalid hypothesis set is not a certified answer. It is an inconsistency requiring abstention.

## 3. Hypothesis view

The core supports two implementations:

1. explicit finite hypotheses for exact validation;
2. symbolic or implicit hypotheses for scalable adapters.

The interface is:

```text
compatible(state) -> HypothesisView
possible_decisions(view) -> DecisionSet
explain_compatibility(view) -> EvidenceRef
```

An implicit view must declare whether it is exact, a sound over-approximation, an under-approximation, or a heuristic. Only exact or sound over-approximate views may support a hard certified decision.

## 4. Decision partition

PRISM reasons over decisions, not only hypotheses:

```text
DecisionPartition = {
  decision -> compatible hypotheses or symbolic region
}
```

Stopping is legal only when exactly one decision remains and the verifier accepts the witness. Unique-model identification is not required unless requested.

If the partition is empty, contradictory, or contains multiple decisions, PRISM must not silently choose one.

## 5. Operation contract

Every operation has:

```text
Operation = {
  id,
  precondition,
  input_refs,
  outcome_space,
  exactness,
  cost_model,
  executor,
  predicted_effect,
  provenance
}
```

The executor returns:

```text
Outcome = {
  value,
  validity,
  actual_cost_vector,
  evidence_refs,
  failure_status
}
```

Timeout, unsupported operation, invalid input, resource exhaustion, nondeterminism, and execution error are first-class outcomes. They are never silently converted into ordinary evidence.

## 6. Transparent bounded selection

The first implementation uses no learned weights. For each eligible operation `q`, estimate:

```text
score(q) = expected decision progress(q) / expected total cost(q)
```

Decision progress is expected separation of competing decisions, not raw hypothesis elimination. The estimate includes execution, state update, verification, and planning overhead.

If no reliable estimate exists, a declared fallback policy is used and recorded. Unknown value is never treated as zero cost. Candidate generation itself is measured and may be stopped by a planning budget.

## 7. Results

The controller returns exactly one of:

- `CERTIFIED_DECISION`: decision, witness, verifier result, final state, and complete cost trace.
- `ABSTAIN`: structured reason, unresolved decision set, remaining budget, limitations, and trace.
- `INVALID_INSTANCE`: malformed problem contract or adapter violation.

Timeout is normally `ABSTAIN`, not `INVALID_INSTANCE`.

## 8. Certificates

A certificate states its quantifier scope: declared hypothesis class, probability/risk model, adversarial world set, or domain invariant.

The finite reference implementation emits certificates with scope `declared_hypothesis_class`. Its verifier recomputes compatibility and decision invariance only within that class. It rejects an external-world scope because it has no independent external validator or attestation interface.

An omitted true world can therefore still produce a model-relative certificate, including one whose decision is wrong for that hidden world. This is the known misspecification failure and remains separately scored by the benchmark. A consumer requiring an external-world guarantee must have an independent validator that supports that claim; without one, it must abstain. Held-out checks may find some omissions, but cannot prove the hypothesis class complete.

The verifier does not trust the controller's internal decision. If checking is incomplete, the certificate is rejected or marked uncertified.

## 9. Reproducibility

The reference controller supports a seed and deterministic tie-breaking. Every run records adapter version, instance hash, seed, operation order, outcomes, cost vector, verifier result, software metadata, and hardware metadata.

Nondeterministic adapters report the source and confidence model. Repeated runs are required before performance claims.

## 10. Reference lifecycle

```text
validate contract
initialize immutable state
while budget remains:
    derive compatible hypothesis view
    derive decision partition
    attempt certified stopping
    classify unsupported or inconsistent state
    enumerate eligible operations within planning budget
    score using declared policy
    execute one operation
    append outcome and cost
return abstention
```

No adapter may bypass certified stopping, budget accounting, or provenance.

## 11. Tests before domain adapters

The reference implementation must test immediate sufficiency, one-operation sufficiency, equal-cost alternatives, misleading information gain, unnecessary model identification, contradictory observations, empty hypotheses, omitted true hypotheses, timeout, unsupported operations, verifier rejection, zero/nonzero costs, planning cost exceeding direct execution, parity/dense controls, and deterministic replay from a trace.

Passing tests establishes that the kernel obeys its contract. It does not establish research novelty.
