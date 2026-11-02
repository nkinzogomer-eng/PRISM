# PRISM core audit — 2026-11-02

## Scope and source state

This audit distinguishes the SCM core from cyber/DeFi experiments and the separate cyber range. No files in the existing `PRISM/` checkout were changed. Its current branch is `research/phase-4-2-structural-selection` at `9e84b533f834b88f5957d00df0705dfa14422d42`; the checkout already has staged Phase 4.2 additions and untracked reports, raw outputs, bytecode caches, and `test-results.txt`. Those local changes were preserved.

GitHub was inspected read-only on 2026-11-02. Repository default branch `main` is `da6980ae9e9b499795fdbf31f137e5a6a0dd5840`. PR #36 is open, not merged, from `arena/5f8d8b29-prism` at `419044d223de85d6ed6bc0accd04c042f7cb5b0b`, based on that `main`. Its changed files are D2.5 and cyber-range documentation, scripts, and artifacts plus README/.gitignore; it changes no `prism/` core module. PR #36 was not merged or modified.

The local mirror predates GitHub's 2026-10-31 push. A local Python interpreter/test runner is unavailable (`python` resolves to a blocked Windows Store alias; `py`, `pytest`, and `uv` are absent). Consequently, this audit did not execute the Python suite against the current GitHub tree. Existing GitHub Actions results are cited as historical evidence, not as tests run in this audit.

## Operational meaning of “complete and ready for use”

“Complete” is relative to an explicit, bounded kernel contract, not a claim that SCM solves arbitrary computation. A ready kernel must:

1. Accept a validated, domain-neutral problem contract and explicit assumptions, evidence, candidate hypotheses/worlds, decision, operations, budget, and verifier.
2. Represent exact finite spaces and sound implicit over-approximations distinctly; never treat a heuristic or under-approximation as proof.
3. Compute decision sufficiency and minimality under declared semantics; return a checkable witness with scope and provenance.
4. Discover or construct transformations from declared operators/constraints, rather than relying only on a hard-coded transformation list. Each transformation states preconditions, preservation relation, cost, dependencies, and invalidation rules.
5. Preserve target-decision semantics under transformations and quotienting, with an independent checker that rejects malformed, stale, or over-scoped certificates.
6. Account for planning, representation, execution, verification, preprocessing, memory, communication, energy, and financial cost where measurable; unknown dimensions remain unknown, never zero. Include cold and amortized costs.
7. Reuse results only with complete provenance and explicit dependency/configuration invalidation; fall back to full recomputation when sound reuse cannot be established.
8. Abstain on empty/inconsistent models, unsupported operations, incomplete coverage, timeouts, verifier failure, resource exhaustion, and potentially misspecified models. A model-relative certificate must never be presented as an external-world guarantee.
9. Provide a stable library API and usable CLI, deterministic replay where promised, versioned persistence/resume, structured errors, and documented security/isolation boundaries.
10. Have targeted unit, property, differential, adversarial, regression, and comparative benchmark evidence for the contract. Passing software tests is not scientific proof of superiority.

## Traceability matrix

Status meanings: **Present (narrow)** means implemented and tested only under the stated finite or experimental contract; **Partial** means some mechanism exists but not the general guarantee; **Absent** means no core implementation/evidence was found on `main`.

| SCM requirement | Requirement interpretation | Current module / evidence | Tests or evidence | Gap / counterexample / failure mode | Status |
|---|---|---|---|---|---|
| General structural representation | Domain-neutral state, evidence, hypotheses, operations, outcomes, decisions, costs, verifier | `docs/core.md` specifies these; `prism/reference.py` implements `Hypothesis`, `Observation`, `FiniteProblem`, `State` | Main CI at `da6980a` passed 2026-10-16; finite reference tests are present in repository | Runtime accepts only explicit finite deterministic observation tables; no general symbolic/implicit model interface or arbitrary transformed representation. A large implicit state space is not representable by this core. | Partial |
| Decision sufficiency | Stop when every compatible hypothesis yields one decision | `FiniteProblem.decision_set`, `certificate`, `certified_stop` in `prism/reference.py` | `tests/test_reference.py`; Phase 2/3 records | Correct only relative to declared hypotheses. An omitted real world can yield a false external answer while the internal certificate verifies. | Present (narrow) |
| Minimality / optimal planning | Find the least-cost operation/policy needed to reach sufficiency, with exactness stated | `prism/optimal.py` exact expected-cost solver; `prism/adaptive.py` state-dependent selection | `tests/test_replay_optimal.py`, `tests/test_adaptive.py`; Phase 2/3 finite experiments | Exact solver is exponential and limited to finite belief states. Adaptive selector is supplied by caller; it is not a general discovered planner and counts only declared scalar planning cost. No scalability guarantee. | Partial |
| Discoverable/construible structural transformations | Generate candidates from the problem structure and declared transformation language | `prism/transformations.py`: decision-equivalence quotient and dominated-observation pruning | Exhaustive small finite tests; `tests/test_transformations.py`, `tests/test_dominated_observation_pruning.py`; roadmap explicitly calls this two narrow transformations | Fixed routines, not a transformation discovery/construction engine. No general representation/program/computation-space rewrite system. Parity/dense dependencies defeat naive structural pruning. | Partial |
| Preservation conditions and certificates | Verify transformation preconditions and decision preservation independently | Quotient verifier and pruning metadata in `prism/transformations.py`; finite certificate verifier in `prism/reference.py` | Finite exhaustive tests; roadmap documents uniform-prior caveat | Verifier is coupled to the same in-process finite model/code; no generic certificate schema, proof kernel, independent process, or external attestation. Quotient preserves decision sets but can change uniform-prior expected cost (documented 1.75 → 1.6667 counterexample). | Partial |
| Equivalence and quotient | Quotient only under a declared equivalence that preserves target semantics | Decision-equivalence quotient groups identical observation vectors and decisions | `reports/decision-equivalence-quotient-2026-10-15.md`; exhaustive small-instance comparison | One finite equivalence relation only; does not preserve all probability/prior semantics or general costs. | Present (narrow) |
| Dependencies and structural relevance | Track semantic dependencies and safely eliminate irrelevant work | Dominated observation pruning; Phase 4.2 experiment adds module-local flow-insensitive AST selection | Phase 4.2 report explicitly records **no-go for deployment**; `tests/test_phase42_structure.py` on research branch | Main core has no dependency graph abstraction. AST selection is conservative and bounded to a cyber scanner pipeline; hidden/cross-file dependencies can invalidate it. | Partial |
| Incremental computation and invalidation | Reuse only results proven valid under unchanged inputs, dependencies, tools, and assumptions | No general core cache. Research branch 4.3B `prism/incremental.py` uses exact byte hashes and scanner-contract matching; branch 4.3C has one B307 suffix certificate | PR #16 and #17 are open research branches, not main; protocols require comparison against full scans and exact-hash baselines | File/module-local assumption; changed rules/config invalidate, but cross-file semantics remain unresolved. Narrow suffix certificate applies only to one rule and one allowlisted edit. No general dependency-aware incremental engine. | Partial (experimental) |
| Incomplete / out-of-model handling | Distinguish model-relative proof from real-world truth; expose unknowns and abstain | Empty compatible state abstains; certificate scope is `declared_hypothesis_class`; adaptive runner returns `declared_class_contradicted` | `tests/test_reference.py`, `tests/test_adaptive.py`; roadmap Gate 2 | Evidence that remains compatible with a misspecified class may still certify the wrong real decision. No completeness oracle exists; held-out checks cannot prove completeness. | Partial |
| Cost-sensitive planning | Compare decision progress against total resource vector | `Cost` has planning, execution, verification, representation, preprocessing scalar fields; Phase 4.3 research modules cover wall-clock selection | Phase 4.3A/B/C protocols state cold cost, setup, scanning, and verification constraints | Core omits memory, communication, energy, monetary cost and uncertainty intervals; scalar addition hides trade-offs. Cost estimates may be missing or incomparable. | Partial |
| Memory / reuse | Reuse work with cold-start and amortized cost reported | Narrow experimental hash/result caches on research branches | Branch protocols compare full scan, fixed cache, and specialized methods | No stable core memory API, persistence format, cache provenance contract, or memory budget. | Absent (core) |
| Independent verification | A separate checker recomputes claims from evidence, not controller assertions | `FiniteProblem.verify` recomputes compatibility and decisions within same class | Certificate rejection tests in `tests/test_reference.py`; PR #36's cyber range has separate evidence workflow but outside core | Same implementation/model boundary is not independent against shared bugs. No standalone verifier/API for third-party adapters. | Partial |
| Errors, recovery, determinism | First-class errors and recoverable/abstaining outcomes; deterministic replay | `Result` statuses; `replay.py`; adaptive runner validates selection and planning-cost inputs | `tests/test_replay_optimal.py`, `tests/test_adaptive.py`; deterministic seed support in generators | No universal error taxonomy/recovery policy. Mutable mappings can undermine practical immutability. Invalid certificate evidence keys can raise during verification rather than return a structured rejection. Nondeterministic executor semantics are not normalized by the core. | Partial |
| Interface/API/CLI | Stable reusable API and operator-facing command-line interface | Python module functions/classes only | Unit tests import modules | No documented versioned public API, package install contract, or core CLI was found on `main`. | Absent |
| Persistence / resume | Save exact state, provenance, and budget; resume with compatibility checks | `replay.py` can replay a supplied in-memory trace | Replay tests | No serialization schema, checkpoint/resume, migration, or crash-recovery tests. | Absent |
| Security and isolation | Core has explicit trust boundaries and safe adapter execution | Core is dependency-free; cyber range is separately scoped under PR #36's `range/` and `docs/cyber-range/` | PR #36 CI `unittest` completed successfully on 2026-10-31; range report is self-reported in PR description | No core sandbox, resource/process isolation, hostile adapter boundary, or security review. Range controls do not make the general kernel complete. | Partial (separate system) |
| Docs / roadmap consistency | State current implementation, experiments, evidence, and gates without overclaiming | `docs/core.md`, `docs/architecture.md`, `docs/scm-roadmap.md`, `docs/scm-phase-status.md` | Main docs clearly state research status and finite limitation | Roadmap/phase register last reviewed 2026-10-16 says Phase 4 is unchecked, while open PRs #13–#18 contain Phase 4 experiments through 4.4 and PRs #19–#35 contain further cyber/DeFi research. Those are not merged into main and must not be counted as core releases. | Contradiction / stale |
| Reproducibility and science | Pin code/data/tools/seeds, preserve raw evidence, compare fair baselines | Phase 2/3 synthetic reports; Phase 4 CI protocols; branch-specific manifests | Main workflow success for `da6980a` (2026-10-16); PR #13, #14, #18, #36 have successful recorded checks | Core experiments are finite/synthetic; Phase 4.3 runs have no check-runs visible for PR heads #15–#17 in the inspected GitHub API. PR #18 CI passed but its report labels results development-only/in-sample. No result establishes general scientific superiority. | Partial |
| AI independence / scope discipline | Core works without model dependency; experimental cyber stays isolated | Core code imports standard library; README and `docs/ai-independence.md`; cyber code is on separate branches/range | PR #36 modifies no `prism/` module; PR #18 protocol says no external model required | This property is currently supported by architecture and inspection, not a broad third-party dependency/security audit. | Present (narrow) |

## Branch, PR, and evidence audit

- `main`: `da6980ae9e9b499795fdbf31f137e5a6a0dd5840`; latest listed `PRISM tests` run succeeded on 2026-10-16 ([run](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38969238128)).
- PR #36: open, not merged; head `419044d223de85d6ed6bc0accd04c042f7cb5b0b`; base `main`. GitHub `unittest` check succeeded ([run](https://github.com/nkinzogomer-eng/PRISM/actions/runs/41199378926)). The PR is D2.5 and cyber range only; do not infer core readiness from its green check.
- PR #13: open Phase 4 benchmark/evidence branch; its `static-baseline` and `unittest` checks succeeded on the branch head ([static baseline](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39554911190), [unit tests](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39554911198)).
- PR #14: open Phase 4.2 conservative AST experiment; check succeeded ([run](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39560635244)); its report's conclusion is explicitly **no-go for deployment**.
- PRs #15, #16, #17: open sequential Phase 4.3 research branches for OR cost, exact-hash incrementality, and one-rule sufficiency. No check runs were returned for the inspected head SHAs. Treat test/evidence status as **NOT VERIFIED in this audit**, not passed.
- PR #18: open and draft, Phase 4.4 goal-first CWE-22 experiment; `goal-first` check succeeded ([run](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39648349289)). Its protocol describes in-sample development results, uncertain/unknown cases, and explicitly says it is not production ready.
- PRs #19–#35 and the cyber range are domain experiments or orchestration work. They are not a general SCM core release and do not satisfy the kernel gates above.

## Targeted validation suite required before a readiness claim

Avoid arbitrary test volume. The following focused suite would target the highest-risk claims:

1. **Certificate malformed-input regressions:** unknown evidence keys, duplicate evidence IDs, forged compatible IDs, duplicate decisions, empty scope, and invalid types must be rejected as a structured result, never throw or certify.
2. **Transformation differential properties:** enumerate small finite problems and compare original/transformed decision sets for every evidence assignment; separately compare prior-weighted expected cost and assert that transformations declaring prior preservation actually preserve it.
3. **Out-of-model counterexamples:** add a hidden real hypothesis compatible with all observed evidence but with an opposite decision; require either external validator support or explicit “model-relative only” status and score incorrect non-abstention.
4. **Incremental differential/adversarial tests:** edits to source bytes, import graph, scanner rules, tool version, flags, working directory, generated files, missing/extra scan records, and cross-file dependencies must either invalidate or match a fresh full run exactly. Keep the exact-hash cache as a strong baseline.
5. **Cost-accounting properties:** verify nonnegative/finite inputs; sum every measured component; preserve unknown values for unavailable memory/energy/USD; compare cold and amortized cost and include planning/checker overhead.
6. **Deterministic replay and recovery:** same input/seed/trace gives identical state and certificate; timeouts, partial outputs, verifier exceptions, and corrupted persistence abstain or fail closed.
7. **API/CLI/persistence contract:** schema validation, versioning, round-trip resume, incompatible-version rejection, interrupted writes, and no hidden model/network requirement.
8. **Benchmarks:** small exact finite oracle plus targeted positive and negative controls; matched full/fixed/cache/SCM arms; held-out real domain only after independent labels. Report quality, abstention, wrong non-abstention, wall/CPU/memory and all available resource costs. A software pass is not a scientific superiority result.

### Execution record for this audit

| Check | Command / source | Result |
|---|---|---|
| Repository and branch metadata | GitHub repository API, branch listing, PR #36, PR list | **EXECUTED** read-only; states and SHAs recorded above |
| Main CI evidence | GitHub Actions workflow runs and check-runs API | **INSPECTED**, not rerun; main run succeeded 2026-10-16 |
| PR 13/14/18/36 checks | GitHub check-runs API | **INSPECTED**, recorded above |
| PR 15/16/17 checks | GitHub check-runs API | **NOT FOUND** for inspected head SHAs; not treated as pass |
| Local test suite | `python -m unittest discover -s tests -v` | **NOT EXECUTED**: Python runtime unavailable in this host |
| Current GitHub `main` source tests | Not fetched into an isolated runnable checkout | **NOT EXECUTED** |
| Benchmarks / scientific replication | CI records and branch protocols only | **NOT EXECUTED in this audit** |

## Verdict

**NO-GO for “complete general SCM kernel” and production use.** The checked-in core is a useful, dependency-free finite reference implementation with model-relative decision certificates, a small exact solver, adaptive finite execution, replay, and two narrow audited transformations. That is the actual guaranteed scope. It is not a general structural discovery engine, a general symbolic planner, a persistent service/CLI, or a complete resource-aware runtime.

**Conditional use is reasonable only for** small explicit finite deterministic problems, with a trusted declared hypothesis class, scalar nonnegative costs interpreted as the current implementation defines them, and a consumer that accepts model-relative certificates and abstentions. Do not use it to claim correctness about an unrepresented external world, complete vulnerability coverage, general cost optimality, or SCM scientific superiority.

### Proven in this audit

- Actual GitHub default branch and PR #36 state/SHA were inspected.
- PR #36 does not change the SCM core and remains open/unmerged.
- Main and selected branch CI records were inspected with dates and scopes kept separate.
- Specifications and code agree that the current core is a finite research reference, not a validated general-purpose kernel.

### Not proven / not executed

- No fresh Python tests or benchmarks ran in this environment.
- PR #15–#17 checks were not present for the examined head SHAs.
- No independent scientific replication, external-world completeness proof, or superiority result exists in the inspected evidence.
- General symbolic-model correctness, general transformation discovery, persistence/resume, production security/isolation, and full resource-vector planning remain unvalidated or absent.

### Next action

Create a clean isolated checkout of `main` plus a new audit branch, install a pinned Python 3.12 toolchain, run the baseline suite, add the malformed-certificate tests and the minimal verifier hardening as the first reversible code change, then run the full unit suite and targeted finite differential properties. Only after those results are recorded should broader transformation, cost-vector, persistence, or API work be split into separate reviewed stages. Keep PR #36 and all cyber experiments outside that core change path.

