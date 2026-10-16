# SCM → PRISM phase register

**Plan version:** 1.0 (working baseline)  
**Last reviewed:** 2026-10-16  
**Rule:** A phase is checked only when its stated exit criteria have been reviewed and met. A checked research-planning phase does not imply that the scientific hypotheses it defines have been proven.

## Status

- [x] **Phase 0 — Scientific contract and constraints.** Approved by the project owner on 2026-10-16.
- [x] **Phase 1 — Theoretical audit and falsifiable research hypothesis.** Audit reviewed; H-SCM-1 and Phase 2 protocol documented; repository CI passed on 2026-10-16.
- [x] **Phase 2 — Baselines and reproducible reference measurements.** 100 fixed seeds per seeded family; all independent checks and exact-cost preservation gates passed; detailed results recorded in the Phase 2 report.
- [ ] **Phase 3 — Controlled structural-computation experiments.**
- [ ] **Phase 4 — Cybersecurity application: authorized Red Team + Blue Team, repair, and independent verification.**
- [ ] **Phase 5 — Optional Ciel orchestration integration, only after measured core value.**
- [ ] **Phase 6 — Generalization to separate domains, including financial-flow analysis and astronomy.**

The phase order is a research sequence, not a guarantee that every phase will succeed or that later phases must proceed unchanged.

## Phase 0 — validated contract

The project owner explicitly approved these non-negotiable constraints:

1. **AI/model independence:** the SCM–PRISM kernel must run and perform its defined core work without an external AI model. Models may be optional proposal-generators in separately measured experiments; they cannot be required dependencies or authoritative verifiers.
2. **Correctness before speed:** a faster result that increases unbounded or unmeasured error is not an improvement.
3. **Strong comparisons:** gains must be measured against relevant, strong baselines, including total planning, preprocessing, transformation, execution, verification, memory, communication, energy (where measurable), and money costs.
4. **Ordinary hardware:** no GPU or remote model is required for the core. Hardware profiles and resource limits must be explicit.
5. **Scientific discipline:** hypotheses are not results; synthetic evidence is not real-world evidence; model-relative certificates do not prove that the model contains reality; negative results and uncertainty stay visible.
6. **Reproducibility and safety:** preserve historical baselines, record versions/seeds/data splits/hardware, and restrict offensive cyber testing to authorized environments.

## Phase 1 — exit criteria

Phase 1 is eligible to be checked when all of the following artifacts exist and have been reviewed:

- [x] A source-backed map of relevant existing theories and methods.
- [x] A limitation/counterexample for each major method family, not just its promise.
- [x] A clear separation between established techniques, the SCM research hypothesis, and claims not yet supported.
- [x] A falsifiable, narrow candidate hypothesis and explicit conditions that would refute or limit it.
- [x] A reproducible Phase 2 benchmark protocol with baselines, resource accounting, and decision-quality criteria.
- [x] A written decision about which claims are currently unsupported and which implementation work remains paused.
- [x] Repository regression CI passes for the documentation change. CI success is not evidence that SCM is superior.

See [Phase 1 theory audit](scm-phase1-theory-audit.md) for the source-backed review, candidate hypothesis, protocol, and limitations.

## Phase 2 — validated reference-measurement gate

- [x] Protocol and falsifiable acceptance gates documented in [Phase 2 protocol](scm-phase2-protocol.md).
- [x] Reproducible runner added; 100 fixed seeds for each seeded family (seeds 0–99), plus one parity control.
- [x] 52 standard-library unit tests passed, including the new subprocess test that executes the 100-seed suite; existing 20-seed comparison and transformation benchmark steps passed.
- [x] Decision-equivalence quotient independent verifier: 100/100 checks passed; mean hypothesis count 10 → 8 (20% reduction).
- [x] Dominated-observation pruning independent verifier: 100/100 checks passed; mean observation count 2 → 1 (50% reduction); exact expected execution cost remained 1.00 before and after in all runs.
- [x] Outputs reviewed and limitations/negative results recorded in [Phase 2 benchmark report](../reports/phase-2-reference-benchmark-2026-10-16.md).
- [x] GitHub Actions run [38967359906](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38967359906) succeeded.

**Scientific conclusion:** Phase 2 validates the benchmark apparatus and narrow transformation contracts only. It does not validate H-SCM-1 or establish general SCM superiority. Fixed-cost order beat adaptive greedy and decision-disagreement on sparse binary cases; omitted-world cases produced 52–100% wrong-certificate rates despite 100% model-relative certification. Phase 3 may begin with these baselines locked.

## Change control

A change to goals, success metrics, or resource assumptions must be recorded in the research log before the relevant evaluation results are examined. If a hypothesis fails, narrow or reject it rather than silently changing the evaluation target. No implementation gate is passed by writing a specification alone.

## Validation snapshot — 2026-10-16

- Documentation consistency assertions: **15/15 passed** (phase markers, AI-model independence, hypothesis/refutation conditions, negative results, baselines, cost accounting, Phase 2 protocol, and navigation links).
- Internal Markdown link resolution: **10/10 passed** against the branch contents.
- No production code was changed in this PR, so no new algorithmic unit test was authored for Phase 1.
- GitHub Actions PR run [38944823840](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38944823840) completed successfully. The standard-library unit-test suite and both existing synthetic benchmark steps passed.

These checks validate documentation consistency and repository regression only. They do not validate H-SCM-1 or prove a computational advantage.
