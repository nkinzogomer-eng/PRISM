# PRISM Core Specification

Status: research specification, not a validated theory.

## 1. Problem contract

A PRISM instance is:

```text
Instance = (State, Hypotheses, Operations, Outcomes, Decision, Cost, Verifier)
```

- `State`: current evidence and derived constraints.
- `Hypotheses`: candidate explanations, models, or behaviors.
- `Operations`: observations, transformations, simulations, solver calls, or tests.
- `Outcomes`: possible results of each operation.
- `Decision`: the target output or property to determine.
- `Cost`: time, memory, energy, money, communication, or a declared vector.
- `Verifier`: an independent procedure for checking a decision witness.

A domain adapter must define these interfaces. The core must not assume that the domain is cyber, astronomy, software, or machine learning.

## 2. Decision sufficiency

Let `H(S)` be the hypotheses compatible with state `S`. A decision `d` is sufficient relative to the declared hypothesis class when:

```text
for every h in H(S): decision(h) = d
```

This is a relative guarantee. It does not prove correctness if the true explanation is outside the hypothesis class or if the observation model is wrong.

A probabilistic adapter may replace this with an explicit risk bound. An adversarial adapter may require agreement for every admissible world. The adapter must declare which semantics it uses.

## 3. Distinctions

A distinction is a partition of compatible hypotheses that could produce different target decisions, certificates, or domain-relevant behaviors.

PRISM must prefer distinctions that are:

- decision-relevant;
- cheap to test;
- structurally explainable;
- independently verifiable;
- transferable beyond one memorized instance.

The number of hypotheses eliminated is not enough. A large reduction that leaves opposite decisions unresolved is inferior to a small reduction that proves the target decision.

## 4. Main loop

```text
PRISM(problem, budget):
    S <- initial evidence
    trace <- empty provenance record

    repeat while budget remains:
        H <- compatible_hypotheses(S)
        B <- derive_safe_bounds_and_dependencies(S, H)

        if decision_invariant(H, target):
            w <- build_witness(S, H, target)
            if verify(w):
                return CERTIFIED_DECISION(target, w, trace)

        if unsupported_or_misspecified(S):
            return ABSTAIN(reason, trace)

        candidates <- generate_operations(S, H, B)
        candidates <- remove_operations_provably_irrelevant(candidates, B)

        if candidates is empty:
            return ABSTAIN(unresolved, trace)

        q <- select_operation(candidates, S, H, B, budget)
        if estimated_planning_cost(q) >= estimated_decision_value(q):
            return ABSTAIN(planning_not_worth_cost, trace)

        result, actual_cost <- execute(q)
        S <- update_state(S, q, result)
        trace <- append(trace, q, result, actual_cost)
        budget <- budget - actual_cost

    return ABSTAIN(budget_exhausted, trace)
```

This is deliberately a controller, not a universal solver. `compatible_hypotheses`, `derive_safe_bounds`, `generate_operations`, and `verify` are domain adapters or interchangeable engines.

## 5. Required invariants

1. **Trace integrity:** every derived claim points to input evidence or a recorded operation.
2. **Sound stopping:** a certified decision is returned only after the verifier accepts it.
3. **No silent assumption expansion:** adding hypotheses or assumptions is recorded explicitly.
4. **Monotonic evidence:** an operation may refine state, but cannot erase uncertainty without justification.
5. **Budget accounting:** planning, conversion, execution, caching, and verification are counted.
6. **Abstention honesty:** failure to prove sufficiency is not treated as a negative decision.

## 6. Cost model

Use additive accounting for sequential work:

```text
C_total = C_representation + C_planning + C_execution + C_verification
          + C_memory + C_communication + C_preprocessing
```

Report a resource vector when a scalar would hide trade-offs. Report cold-start and amortized cost separately.

The core is allowed to lose when computing relevance or planning costs more than direct execution. That is a required negative result, not an implementation bug.

## 7. What could be novel

The individual techniques are established. The research claim, if any, must be narrower:

> A domain-independent controller can discover and test decision-relevant distinctions, stop on an independently verified sufficiency certificate, and remain cost-effective after planning and verification costs are included.

This claim is falsifiable. It must be compared against decision-gain, value-of-information, random/fixed policies, exact small-instance policies, and domain-specialized tools.

## 8. Known failure modes

PRISM is expected to lose on:

- parity and dense dependencies;
- one-shot tiny instances;
- tasks where every input can change the decision;
- adversarial hidden dependencies;
- misspecified hypothesis classes;
- mature specialized solvers;
- cases where semantic relevance is harder than evaluation;
- representations whose conversion cost dominates.

A system that never loses is probably leaking benchmark structure or using an unfair oracle.

## 9. Minimal validation before expansion

Before adding learning, LLMs, e-graphs, distributed execution, or domain-specific automation, validate:

1. exact decision invariance on finite hypothesis spaces;
2. independent certificate checking;
3. complete end-to-end cost accounting;
4. correct abstention under misspecification;
5. reproducible gains on at least one nontrivial family;
6. explicit losses on negative-control families.
