# SCM conformance matrix

This matrix reflects the `finalization/prism-complete` branch after the audited
changes. `Verified` means a concrete test or executable artifact was run; it
does not mean scientific superiority.

| Requirement | Current state | Evidence | Gap | Action | Acceptance test |
|---|---|---|---|---|---|
| Decision sufficiency over declared hypotheses | Implemented and verified | `prism/reference.py`, `test_reference.py` | Finite deterministic scope only | Keep scope explicit | `test_decision_sufficiency_does_not_require_model_identification` |
| Independent certificate verification | Implemented and verified | `FiniteProblem.verify`, malformed-certificate tests | No external-world validator | Abstain/reject unsupported scope | `test_certificate_rejects_unsupported_external_scope` and malformed certificate tests |
| Honest abstention | Implemented and verified | `abstain`, runner contradiction handling | Rich status taxonomy is not yet an enum/API type | Preserve stable status strings; extend only compatibly | `test_abstention_is_explicit`, contradiction tests |
| Provenance and trace | Partial | Runner records evidence, operations and costs | No general serialized trace/checkpoint API | Keep as next kernel milestone | Replay tests and cost assertions |
| Structural transformations | Partial, verified for two finite rules | `prism/transformations.py`, Phase 2/3 reports | No general graph, slicing, composition or invalidation engine | Do not claim universal SCM | Phase 2/3 independent verifier gates |
| Total cost accounting | Partial | Planning/execution/verification fields and evaluator | Memory, communication, energy and money are unknown unless supplied | Report unknown rather than zero | `test_unmeasured_component_cannot_be_scalarized_as_zero` |
| Determinism/reproducibility | Implemented and verified for reference benchmarks | Seeded generators, replay tests, fixed ordering | External adapters may be nondeterministic | Adapter contract must declare nondeterminism | `test_generator_is_reproducible`, replay tests |
| Offline/model independence | Implemented and verified | No runtime dependencies; local install smoke test | Domain adapters may add dependencies | Keep optional and separately measured | clean venv install and `python -m prism` smoke test |
| CLI/API and structured JSON | Implemented, minimal | `prism/cli.py`, `pyproject.toml` | No network API or persistence service | Keep CLI as reference interface | run/verify-certificate smoke commands |
| Adversarial validation | Partial | omitted-world, parity, contradiction, malformed input tests | No broad holdout or noisy/probabilistic adapter suite | Extend with targeted cases | current 56-test suite and expected failure |
| Comparative benchmarks | Implemented for finite synthetic references | Phase 2/3 runners and reports | No real-world or broad domain advantage evidence | Publish negative results | Phase 2/3 hard gates |
| Cyber/DeFi claims | Not implemented in the core | Existing research branches/reports are separate evidence | No claim of new vulnerability or general efficacy | Keep out of core readiness claim | No acceptance until independently reproduced |

## Status vocabulary

- **Implemented and verified**: code exists and the named test/artifact ran.
- **Partial**: a bounded finite implementation exists, but the broader SCM
  requirement is not implemented.
- **Specified only**: documented contract without a corresponding general
  implementation.
- **Not implemented**: no claim is made for the capability.
