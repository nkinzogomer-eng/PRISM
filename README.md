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
- [Initial research decision log](journal/2026-10-10.md)
- [Adaptive finite runner](prism/adaptive.py)
- [Adaptive runner tests](tests/test_adaptive.py)

## Offline installation and CLI

PRISM has no mandatory runtime dependency and does not call an LLM, remote
service, or network resource. From a clean checkout, create an isolated
environment and install the package locally:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps .
python -m unittest discover -s tests -v
```

The reference CLI emits structured JSON and returns a non-zero status when a
decision cannot be certified. A finite problem file contains `hypotheses` with
`id`, `observations`, and `decision`, plus `observations` with `id` and `cost`:

```bash
python -m prism run problem.json --evidence '{"a":"0"}'
python -m prism verify-certificate problem.json certificate.json
```

The finite verifier certifies only the declared hypothesis class. It rejects
malformed certificates and unsupported external-world claims; it cannot prove
that the declared class contains reality. The CLI is an offline reference
interface, not a domain-specific cyber or DeFi scanner.

## Current readiness statement

The finite reference kernel, its certificate verifier, two verified finite
transformations, benchmark runners, and adversarial regression tests are
implemented. Packaging and a minimal JSON CLI are now available. General SCM
superiority, external-world completeness, real-world vulnerability discovery,
and broad domain generalization remain unproven and are not claimed.
