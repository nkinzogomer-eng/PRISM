# PRISM Core Audit: 2026-10-10

## Audit conclusion

The previous core specification was conceptually correct but not yet implementation-ready. It named the right components without fully defining their contracts, failure behavior, exactness status, or lifecycle. This entry records the corrections required before coding.

## Decisions made

1. PRISM remains an algorithmic controller, not a domain tool.
2. The core will separate controller logic from domain adapters.
3. The first reference implementation will support explicit finite hypotheses so correctness can be checked exhaustively.
4. Symbolic and implicit hypothesis views may be added later, but must declare whether they are exact, sound over-approximations, under-approximations, or heuristics.
5. The controller has three valid results: certified decision, abstention, or invalid instance.
6. Timeouts, unsupported operations, contradictory evidence, and verifier failures are explicit states, never silently treated as evidence.
7. The first selector is transparent and bounded. No learned policy enters the kernel before the reference semantics are tested.
8. Planning, preprocessing, representation conversion, execution, memory, communication, and verification are part of the measured cost.

## Ambiguities closed

### Decision versus model identification

PRISM stops when the decision partition contains exactly one decision and the verifier accepts the witness. It does not need a unique surviving model unless the requested task is model identification.

### Hypothesis-class validity

A certificate is always relative to a declared hypothesis class or uncertainty model. If the true model may be outside that class, the system cannot claim world-level correctness; the adapter must expose this limitation and PRISM must support abstention.

### Relevance

Dependency and bound analyses may remove an operation only when their declared semantics prove that the operation cannot affect the target decision. Heuristic relevance may prioritize operations but cannot by itself justify certified stopping.

### Cost

The objective is a resource vector. A scalar score may be used for selection only after the user or benchmark declares the scalarization. Raw operation count is not a universal cost.

### Failure behavior

Execution failure is not a negative observation. It is recorded as a failure outcome with status and cost. The adapter must define whether the failure itself carries valid domain evidence.

## Core risk register

| Risk | Consequence | Required control |
|---|---|---|
| False compatibility result | Unsound decision | exact finite reference implementation and independent checks |
| Hypothesis class omission | False certificate | misspecification tests and abstention |
| Planning explosion | No end-to-end gain | hard planning budget and cost accounting |
| Misleading information gain | Irrelevant operations selected | score decision separation, not hypothesis count |
| Verifier shares controller bug | False confidence | independent implementation for reference tests |
| Hidden oracle in adapter | Invalid benchmark | interface review and information parity |
| Nondeterministic execution | Irreproducible results | seeds, replay traces, repeated runs |
| Dense/parity structure | No pruning | mandatory negative controls |
| Representation conversion dominates | PRISM slower | cold-start and amortized reporting |

## Implementation gate

Do not add cyber, astronomy, LLM, distributed, or learned components until the following are implemented and tested:

- immutable state and provenance;
- finite hypothesis view;
- decision partition;
- operation contract;
- transparent bounded selection;
- certificate verifier interface;
- structured abstention;
- complete cost vector;
- deterministic replay;
- adversarial unit tests listed in `docs/architecture.md`.

## Next work item

Write the benchmark schema and reference simulator. The simulator must make it possible to compare PRISM against baselines and exact optimal policies on small instances before any claim about a new capability.
