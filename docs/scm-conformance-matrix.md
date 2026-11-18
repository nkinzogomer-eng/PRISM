# SCM conformance matrix

This matrix reflects the finalization branch after the P0 reliability and
reproducibility corrections. `VERIFIED` means a concrete test or executable
artifact was run; it does not mean scientific superiority.

At the current checkpoint, the suite contains **73 tests: 72 successes and one
explicit expected failure**, with no unexpected failure. The expected failure
is the documented omitted-world misspecification case.

| Requirement | Status | Evidence | Gap or limitation | Acceptance evidence |
|---|---|---|---|---|
| Decision sufficiency over declared hypotheses | VERIFIED | `prism/reference.py`, reference tests | Finite deterministic scope only | `test_decision_sufficiency_does_not_require_model_identification` |
| Independent certificate verification | VERIFIED | `prism/verifier.py`, CLI positive/negative tests | Relative to declared class, not external reality | `test_independent_verifier_matches_reference_api_without_generation`, CLI certificate tests |
| Strict cost invariants | VERIFIED | `Observation`, `Cost`, `CostVector`, adaptive validation | Cost units remain adapter-defined | `tests/test_cost_validation.py` covers negative, NaN, infinities, strings, bools and structures |
| Robust CLI input boundary | VERIFIED | Controlled `ERROR` JSON and stable exit code 2 | No remote API or persistence | `tests/test_cli.py` covers missing, unreadable/invalid JSON, malformed structures and evidence |
| Honest abstention | VERIFIED | `abstain`, runner contradiction handling | Status strings remain lightweight rather than typed enums | `test_abstention_is_explicit`, contradiction tests |
| Provenance and trace | PARTIALLY IMPLEMENTED | Runner records evidence, operations and costs | No general serialized trace/checkpoint API | Replay tests; future version scope |
| Structural transformations | EXPERIMENTAL | Two finite verified rules and Phase 2/3 artifacts | No general graph, slicing, composition or invalidation engine | Phase 2/3 independent gates |
| Total cost accounting | PARTIALLY IMPLEMENTED | Planning/execution/verification fields and evaluator | Memory, communication, energy and money are unknown unless measured | `test_unmeasured_component_cannot_be_scalarized_as_zero` |
| Determinism/reproducibility | VERIFIED | Seeded generators, replay tests, committed raw artifacts | External adapters may be nondeterministic | Phase 2/3 JSON metadata and replay tests |
| Offline/model independence | VERIFIED | Local PEP 517 backend and no-index install | Domain adapters may add dependencies | `pip install --no-index --no-deps --no-build-isolation .` |
| CLI and structured JSON | VERIFIED | `prism/cli.py`, `pyproject.toml`, positive/negative paths | Reference CLI only | `tests/test_cli.py`, CLI smoke test |
| Adversarial validation | VERIFIED | Omitted-world, parity, contradiction, malformed input and cost tests | No general probabilistic/noisy adapter suite | 73-test suite; one expected failure retained |
| Comparative benchmarks | VERIFIED | Phase 2 and Phase 3 raw JSON/Markdown artifacts | Finite synthetic evidence only | Both 100-run experiments return `PASS` |
| Cyber/DeFi claims | NOT IMPLEMENTED | No core claim made; PR #36 remains separate | No new vulnerability or general efficacy claim | Intentionally frozen for 0.1.0 |
| General structural SCM engine | NOT IMPLEMENTED | Explicitly frozen in roadmap | Out of 0.1.0 scope | No simulated completion claim |
| Checkpoint/resume and general invalidation | NOT IMPLEMENTED | Explicitly documented limitation | Future version | No simulated completion claim |

## Status vocabulary

- **IMPLEMENTED**: code exists, but this row may not yet have a complete
  acceptance proof.
- **VERIFIED**: implemented and backed by a named executed test or artifact.
- **PARTIALLY IMPLEMENTED**: bounded support exists, broader requirement does
  not.
- **EXPERIMENTAL**: a narrow research implementation with scoped evidence.
- **PROPOSED**: documented future design without current implementation.
- **NOT IMPLEMENTED**: deliberately absent and not claimed for this release.
