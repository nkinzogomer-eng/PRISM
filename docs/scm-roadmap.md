# SCM → PRISM: staged research and implementation roadmap

**Plan version:** 1.0  
**Last reviewed:** 2026-10-16

## Phase tracker

- [x] **Phase 0 — scientific contract:** approved by the project owner on 2026-10-16. The core must operate without an external AI model; correctness and verifiability cannot be traded away for speed; all costs and strong baselines must be counted.
- [x] **Phase 1 — theoretical audit:** source-backed audit, falsifiable candidate hypothesis, Phase 2 protocol, documentation checks, and repository CI completed. H-SCM-1 itself remains unproven.
- [x] **Phase 2 — baselines and reference measurements.** 100-seed synthetic reference suite passed; see [Phase 2 report](../reports/phase-2-reference-benchmark-2026-10-16.md) and [protocol](scm-phase2-protocol.md). Scientific superiority remains unproven.
- [x] **Phase 3 — controlled structural-computation experiments.** 500 controlled synthetic instances passed; see [Phase 3 report](../reports/phase-3-controlled-dominance-2026-10-16.md) and [protocol](scm-phase3-protocol.md). Only one narrow transformation was validated; general SCM superiority remains unproven.
- [ ] **Phase 4 — authorized cyber Red Team + Blue Team, repair, and independent verification.**
- [ ] **Phase 5 — optional Ciel orchestration, only after core value is measured.**
- [ ] **Phase 6 — generalization to other domains, including finance and astronomy.**

Detailed status: [SCM phase register](scm-phase-status.md).  
Phase 1 deliverable: [theoretical audit](scm-phase1-theory-audit.md).

**A checked phase means its planning/engineering exit criteria were met; it does not mean that a research hypothesis has been proven.** The current SCM advantage hypothesis remains unproven.

---


Status: research plan. This document records intended gates; it is not evidence that the gates have passed.

## Preserve before changing

- Keep the existing finite reference semantics, generators, exact small-instance solver, legacy order-based runner, and historical journals intact.
- Make new execution modes additive until equivalence and regression tests pass.
- Do not describe synthetic results as real-world cyber or astronomy performance.
- Do not call a certificate a guarantee about the external world unless the declared assumptions justify that scope.

## Why PRISM is not yet the full SCM ambition

The current prototype is strongest as a finite decision-sufficiency reference model. Its policies primarily produce observation orders; it does not yet demonstrate general transformation of state, representation, and computation spaces. The specifications describe broader interfaces, but specification alone is not implementation.

SCM remains the research hypothesis: reduce total computation by transforming a problem's representation and plan while preserving decision-relevant guarantees. PRISM is the experimental vehicle for testing that hypothesis.

## Gate 1 — adaptive control without breaking the reference path

Add an opt-in adaptive runner that selects one operation from the current evidence state after each actual observation. Preserve the legacy order-based runner for historical reproducibility.

Acceptance:
- selector receives only the declared problem, current state, and remaining operations;
- hidden-world oracle remains inaccessible to selector;
- unavailable operations and invalid planning costs are rejected;
- planning and execution costs are recorded separately;
- all legacy tests remain unchanged and pass;
- adaptive traces are deterministic when the selector is deterministic.

## Gate 2 — certificate scope and model incompleteness

Keep the known omitted-world failure visible. A certificate over the declared hypothesis class is not, by itself, proof that the class contains the real world.

Acceptance:
- result metadata clearly identifies the scope of a certificate;
- omitted-world tests distinguish model-relative soundness from external-world correctness;
- held-out checks are described as partial detectors, never universal proof of model completeness;
- any non-abstention under model uncertainty is scored against the hidden world in benchmark evaluation.

## Gate 3 — total-cost evaluation

Record, at minimum, planning, execution, verification, representation, and preprocessing costs. Add memory and communication where applicable. Report both cold-start and amortized repeated-run costs.

Acceptance:
- no baseline receives free planning while PRISM is charged;
- report per-component cost, total cost, decision quality, abstention, incorrect non-abstention, and tail cost;
- compare with the exact adaptive solver only on small instances where it is tractable;
- keep random, fixed-cost, disagreement, and simple cost-aware baselines.

## Gate 4 — structural transformations

Introduce transformations as explicit, auditable operations rather than hidden heuristics. Initial candidates may include:
- safe constraint propagation and elimination;
- decision-focused program slicing;
- equivalent representation rewrites with checked preservation conditions;
- incremental recomputation and reuse of prior results;
- selecting a specialized solver when its preconditions hold.

Each transformation must declare preconditions, output representation, preservation claim, actual cost, provenance, and independent validation method. A transformation that cannot justify decision preservation must remain heuristic and cannot strengthen a certificate.

### Gate 4 initial implementation — decision-equivalence quotient

The first audited structural transformation is implemented in `prism/transformations.py`. It merges hypotheses only when both their complete observation vectors and their target decisions are identical. The verifier checks the representative mapping, observation costs, decisions, and observation vectors. Exhaustive small-instance tests compare decision sets across evidence assignments.

Important semantic boundary: this quotient preserves the set of possible decisions for every evidence assignment, but it does **not** necessarily preserve a uniform probability distribution over hypothesis IDs. Therefore it is valid for decision-sufficiency reasoning under the stated semantics, but must not silently replace a probability-weighted model or be used to claim unchanged expected costs. A regression test demonstrates a case where the exact solver's uniform-prior expected cost changes from 1.75 to 1.6667 after quotienting.

This is one verified transformation, not yet a general structural discovery engine. The next work must add transformation provenance, benchmark the cost of finding/applying/verifying transformations, and compare transformed versus untransformed runs on held-out cases. No advantage claim follows from passing preservation tests alone.

### Gate 4 second implementation — dominated-observation pruning

The second audited transformation removes an observation only when a retained observation determines its value for every declared hypothesis and costs no more. The verifier checks that dominance witness, the retained observation costs, and preservation of every hypothesis and decision. Because hypothesis multiplicities remain unchanged, this rewrite preserves the uniform hypothesis prior. Under the deterministic finite cost model, a dominated query can be replaced by its no-more-expensive dominator, so the optimal expected execution cost cannot increase.

This guarantee is narrower than general structural simplification: the dominance relation must be established over the entire declared hypothesis class. It does not prove that the class includes the real world, and it does not license removal of a cheaper but less-informative observation. Equal-cost equivalent observations use deterministic identifier tie-breaking.


## Gate 5 — domain adapters and real benchmarks

Only after the finite gates pass, build narrow adapters for representative tasks.

Cybersecurity:
- start with defensive, labeled vulnerability-analysis/triage benchmarks;
- compare the same underlying tools with fixed orchestration versus PRISM orchestration;
- measure confirmed findings, false positives, missed findings, wall time, CPU/memory, and total tool cost.

Astronomy:
- start with a reproducible public dataset and a well-defined target such as alert prioritization or candidate selection;
- compare against the existing pipeline and simple filters;
- measure scientific recall (especially rare events), false alarms, latency, resource use, and any follow-up observations consumed.

No general performance claim is allowed from one dataset, one seed, or synthetic tasks alone.

## Version gates

### V1 — trustworthy finite controller
Adaptive selection, explicit planning cost, certificate-scope semantics, reproducible traces, and complete finite benchmark reporting.

### V2 — structural controller
A small library of preservation-checked transformations, dependency summaries, incremental reuse, and cost-aware choice among alternative plans.

### V3 — domain-tested SCM–PRISM
At least two independently evaluated task families, with results reproduced on held-out data and explicit negative results. This is not a promise of universal superiority.

## Research claim standard

A claim of advantage must identify:
1. task and decision target;
2. baseline implementations and versions;
3. data splits, seeds, and hardware;
4. all cost components and quality metrics;
5. confidence intervals or repeated-run variability;
6. failure regimes and negative results.

The central hypothesis is supported only if structural/adaptive PRISM improves the cost-quality trade-off over strong baselines on previously unseen instances, with all costs counted and certificate scope respected.
