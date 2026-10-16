# PRISM

PRISM is a domain-adaptable algorithm for discovering hidden distinctions in complex systems.

Its purpose is not to replace domain tools. PRISM is a reasoning core that can sit above them and decide:

- which hypotheses remain compatible with current evidence;
- which distinctions could change the target decision;
- which computation or observation best separates those hypotheses;
- when a result is sufficient;
- when the system must abstain;
- how to produce a reproducible witness or certificate.

PRISM is not initially a fuzzer, LLM agent, solver, or autonomous cyber tool. Those are possible adapters. The first deliverable is a clean, domain-independent algorithm.

## Core objective

Given a problem specification, evidence, candidate explanations, available operations, costs, and a target decision, PRISM seeks a low-cost sequence of operations that produces either:

1. a decision with an independently checkable sufficiency certificate; or
2. a structured abstention explaining what remains unresolved.

## Design principles

- Decision sufficiency is more important than full model identification.
- Planning cost counts as part of total cost.
- Structural relevance is an over-approximation unless proven otherwise.
- No certificate may exceed the assumptions it verifies.
- Unknown, ambiguous, and unsupported are valid outcomes.
- Every claimed gain must survive strong domain-specific baselines.
- The core must remain useful on ordinary hardware.

## Current research status

The hypothesis is unproven. Existing methods already cover many components: program slicing, abstract interpretation, active learning, value of information, constraint propagation, branch-and-bound, incremental computation, and proof certificates. PRISM can only claim novelty through a precise integration and a demonstrated capability to discover useful distinctions that existing baselines miss.

## Code and research notes

- [Core specification](docs/core.md)
- [SCM → PRISM roadmap](docs/scm-roadmap.md)
- [SCM phase tracker](docs/scm-phase-status.md)
- [Phase 1 theoretical audit](docs/scm-phase1-theory-audit.md)
- [Phase 2 reference benchmark protocol](docs/scm-phase2-protocol.md)
- [Phase 2 reference benchmark runner](scripts/run_phase2_reference.py)
- [Phase 3 controlled-experiment protocol](docs/scm-phase3-protocol.md)
- [Phase 3 controlled-experiment runner](scripts/run_phase3_controlled.py)
- [Phase 3 measured results (2026-10-16)](reports/phase-3-controlled-dominance-2026-10-16.md)
- [Phase 4 defensive cybersecurity protocol](docs/scm-phase4-cyber-protocol.md)
- [Phase 4 decision log](journal/2026-10-16-phase4-decision.md)
- [Phase 4 defensive cybersecurity protocol](docs/scm-phase4-cyber-protocol.md)
- [Phase 4 decision log](journal/2026-10-16-phase4-decision.md)
- [Initial research decision log](journal/2026-10-10.md)
- [Adaptive finite runner](prism/adaptive.py)
- [Adaptive runner tests](tests/test_adaptive.py)
