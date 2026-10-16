# SCM–PRISM Phase 1: theoretical audit and research decision

**Date:** 2026-10-16  
**Status:** Phase 1 audit completed on 2026-10-16; all repository CI steps passed. Scientific claims remain hypotheses until benchmarked.  
**Scope:** Deterministic/model-independent computational core, structural transformation, cost-aware decision sufficiency, later authorized cyber application.  
**Important:** This document is a literature-informed research map, not a claim that SCM has already solved these problems or that the cited methods have been exhaustively surveyed.

## Executive conclusion

The audit does **not** reveal one universal technique that makes arbitrary hard computation cheap. It reveals a set of established mechanisms with different guarantees and failure regimes:

1. Abstract interpretation and sound abstraction can safely over-approximate program behavior, but precision depends on the abstraction and may be lost.
2. Constraint propagation, elimination, symmetry reduction, kernelization, and parameterized algorithms can shrink specific problem classes when their preconditions apply; there is no universal safe reduction that makes every hard instance small.
3. Incremental/self-adjusting computation can reuse work after changes, but dependency tracking, invalidation, and update propagation have their own costs and correctness obligations.
4. E-graphs/equality saturation can compactly represent equivalent expressions, but rewrite growth and extraction cost can dominate; optimal extraction is hard in general, while structural parameters such as low treewidth can make specific cases tractable.
5. Per-instance algorithm selection and solver portfolios are established. PRISM cannot claim novelty merely by selecting a tool based on instance features.
6. Information-gain/value-of-information policies must count the cost of deciding what to inspect. A cheap fixed policy can beat an adaptive policy when planning is expensive or the heuristic is poorly matched to the task.
7. Independent certificates can validate a result relative to formalized inputs and assumptions. They cannot prove that the model is complete or that the modeled environment matches reality.

**Research decision:** do not implement a general structural planner yet. The current evidence supports continued, bounded experimentation with explicit transformations and total-cost accounting, but does not support a general SCM advantage claim. The most defensible candidate contribution is an auditable, model-independent controller that composes verified problem reductions, incremental reuse, and per-instance operation/solver selection only when the predicted benefit exceeds the measured transformation and verification cost. Its novelty is unproven and must be tested against the closest existing methods.

## 1. Theories and what they actually solve

### 1.1 Abstract interpretation and sound abstraction

**Established contribution.** Abstract interpretation formalizes reasoning about concrete program behaviors through an abstract domain, often computing a sound over-approximation. The foundational Cousot–Cousot work unifies many static analyses in a lattice/fixpoint framework.

**Useful to SCM.** Represent a large state space using properties sufficient for a target decision; propagate safe bounds; preserve soundness by tracking the abstraction relation and assumptions.

**Limits/counterexamples.**
- An abstraction can be sound but too imprecise to decide the target property.
- Refinement may repeatedly increase analysis cost.
- A proof is relative to the language semantics, model, and abstraction relation.
- Sound over-approximation is not the same as identifying the actual external world.

**Research implication.** Treat abstractions as explicit typed transformations with a stated preservation property, a precision-loss account, and a verifier. Do not call an abstract result “exact” unless the relevant property is proved exact.

Sources:
- Cousot & Cousot, POPL 1977: https://www.di.ens.fr/~cousot/COUSOTpapers/POPL77.shtml
- Cousot, verification, soundness and abstract induction: https://cs.nyu.edu/~pmc309/COUSOTpapers/PPDP-15.shtml

### 1.2 Constraint propagation, elimination, kernelization, parameterized complexity

**Established contribution.** Constraint solvers and parameterized algorithms reduce or decompose instances using problem-specific structure. Kernelization aims to transform an instance to an equivalent smaller instance whose size is bounded by a parameter; fixed-parameter tractability permits runtime of the form f(k)·n^c for parameter k.

**Useful to SCM.** Search for small sufficient cores, low-width separators, repeated constraints, symmetries, dominated operations, and parameters that explain tractability.

**Limits/counterexamples.**
- Reduction rules are problem-specific and need proof of equivalence or a carefully stated weaker guarantee.
- Some problems have no polynomial kernel under standard complexity assumptions unless unlikely collapses occur.
- A smaller representation is not necessarily faster to solve; the transformation may cost more than it saves.
- A parameter may be large on exactly the difficult instances that matter.

**Research implication.** A transformation must record its preconditions, preserved semantics, output size, runtime, and downstream solve cost. Measure the whole pipeline, not only the reduced instance size.

Sources:
- Downey & Fellows, *Fundamentals of Parameterized Complexity*: https://link.springer.com/book/10.1007/978-1-4471-5559-1
- Cousot & Cousot, abstract interpretation as a unified framework: https://www.di.ens.fr/~cousot/COUSOTpapers/POPL77.shtml

### 1.3 Incremental and self-adjusting computation

**Established contribution.** Self-adjusting computation records dependencies during a computation and re-executes affected parts after inputs change. Research demonstrates substantial speedups on selected workloads, including an OOPSLA system reporting up to 37× on examples with an eight-core machine.

**Useful to SCM.** Preserve verified intermediate results, dependency graphs, and proof fragments across mission steps; invalidate only results affected by a change.

**Limits/counterexamples.**
- The published speedup is workload-specific, not a general multiplier.
- If changes affect most dependencies, recomputation can approach a full rerun while still paying tracking overhead.
- Incorrect invalidation produces stale, unsound results.
- Cache serialization, storage, lookup, and verification costs matter.

**Research implication.** Track dependency provenance and invalidation reasons. Compare cold-start cost, update cost, and amortized repeated-run cost across controlled change sizes.

Source:
- Burckhardt et al., *Two for the Price of One: A Model for Parallel and Incremental Computation*: https://www.microsoft.com/en-us/research/publication/two-for-the-price-of-one-a-model-for-parallel-and-incremental-computation/

### 1.4 E-graphs and equality saturation

**Established contribution.** E-graphs compactly represent many equivalent expressions; equality saturation applies rewrite rules and then extracts a representative under a cost model.

**Useful to SCM.** Explore multiple equivalent representations without destructively committing to the first rewrite; preserve the original candidate while accumulating alternatives.

**Limits/counterexamples.**
- Rewrite saturation may grow too large and must often stop at a resource budget.
- The cost model can misrepresent real runtime, energy, or memory.
- Extraction can be NP-hard in general and heuristics can be arbitrarily suboptimal in worst cases; sparse/low-treewidth structures admit stronger specialized methods.
- Equivalence of expressions is narrower than equivalence of arbitrary problem representations or decision procedures.

**Research implication.** Do not generalize e-graphs to a “universal representation engine” without formal semantics. Investigate whether the PRISM decision-preservation contract can be encoded as a specific equivalence relation, and measure rewrite + extraction + verification cost.

Sources:
- Willsey et al., *egg: Fast and Extensible Equality Saturation*: https://doi.org/10.1145/3815481
- *Fast and Optimal Extraction for Sparse Equality Graphs*: https://doi.org/10.1145/3689801

### 1.5 Program slicing and dependency analysis

**Established contribution.** Program slicing extracts program components relevant to a chosen value or behavior. It is useful for debugging, analysis, testing, and security.

**Useful to SCM.** Restrict vulnerability analysis or verification to dependencies that can affect a security property, a target decision, or an observed failure.

**Limits/counterexamples.**
- The slice depends on the criterion and dependence model.
- Incorrectly modeled aliasing, exceptions, dynamic behavior, or dependencies can make a slice incomplete or unsound.
- A conservative slice may remain very large.
- A smaller slice can miss a behavior if the dependence analysis is wrong.

**Research implication.** Start with established slicers as baselines/adapters; test whether SCM can discover a better criterion or safely compose slices with constraints and operation selection. Do not replace mature analysis without a measured advantage.

Sources:
- Masud & Lisper, semantic correctness of dependence-based slicing: https://doi.org/10.1145/3434489
- *Program slicing of Java programs* (including incompleteness cases for specific dependence graphs): https://doi.org/10.1016/j.jlamp.2022.100826

### 1.6 Algorithm portfolios and per-instance selection

**Established contribution.** Solver portfolios such as SATzilla select among existing algorithms per instance because no single solver dominates every instance family.

**Useful to SCM–PRISM.** Estimate which deterministic tool, solver, transformation, or search strategy is likely to give the best cost-quality trade-off for the current instance and budget.

**Limits/counterexamples.**
- Feature extraction and selection have overhead.
- Selection models can be miscalibrated under distribution shift.
- The selected algorithm can still time out or fail.
- A portfolio may improve benchmark score without introducing a new computational primitive.

**Research implication.** Compare PRISM to a strong instance-specific algorithm selector. If PRISM cannot beat this baseline after selection and feature costs are counted, its claimed value must be narrowed.

Source:
- Xu et al., *SATzilla: Portfolio-based Algorithm Selection for SAT*: https://arxiv.org/abs/1111.2249
- Lindauer et al., *Automatic construction of parallel portfolios via algorithm configuration*: https://doi.org/10.1016/j.artint.2016.05.004

### 1.7 Active information gathering and value of information

**Established contribution.** Active learning, decision-theoretic value of information, and adaptive testing choose what observation to acquire based on its expected utility or its ability to distinguish hypotheses.

**Useful to PRISM.** Select observations by target-decision relevance rather than raw hypothesis count, while considering cost, uncertainty, and the remaining budget.

**Limits/counterexamples.**
- Computing expected value can be more expensive than performing a simple test.
- Expected-value optimization depends on the assumed distribution and utility.
- Worst-case/adversarial domains may invalidate average-case assumptions.
- The current PRISM synthetic comparison already showed fixed-cost order outperforming adaptive greedy on the sparse-binary family (9.50 vs 11.95 abstract execution-cost units), and the adaptive policies produced wrong certificates frequently in the omitted-world family.

**Research implication.** Planning cost must be included. A policy should have a fallback to a simple baseline when estimating the value of planning is not worth its cost. Evaluate both average and tail behavior.

Source:
- Petitet et al., *The computational cost of active information sampling before decision-making under uncertainty*: https://www.nature.com/articles/s41562-021-01116-6

### 1.8 Proof certificates and model adequacy

**Established contribution.** Independent proof checkers can validate solver outputs relative to a formal problem instance. SAT competitions have used independently checked certificates and excluded results whose certificates failed validation.

**Useful to PRISM.** Keep the verifier smaller and independent from the search procedure; preserve traceability and distinguish a result's formal scope.

**Limits/counterexamples.**
- A valid certificate proves a claim about the supplied formal instance, not that the instance captures reality.
- Hidden hypotheses, incorrect observations, wrong semantics, and distribution shift remain outside the proof unless modeled.
- An omitted-world PRISM experiment produced 55–100% wrong certified decisions across tested policies despite 100% model-relative certification. This is a decisive failure mode, not a minor edge case.

**Research implication.** Maintain two separate fields: (a) formal/model-relative verification and (b) external validity/evidence about model adequacy. External validity needs domain-specific validation; it cannot be conjured from a certificate.

Source:
- SAT Competition 2020 paper, certificate checking protocol: https://www.sciencedirect.com/science/article/pii/S0004370221001235

## 2. What the current PRISM evidence says

The following are the project's existing reports, not new experiments from this audit:

- **Finite policy comparison:** on the synthetic sparse-binary family, fixed-cost order averaged 9.50 execution units versus adaptive greedy 11.95 and decision-disagreement 12.35. On the misspecified family, model-relative certificates were wrong in 55–100% of runs depending on policy. Report: https://github.com/nkinzogomer-eng/PRISM/blob/main/reports/finite-policy-comparison-2026-10-15.md
- **Decision-equivalence quotient:** hypotheses reduced from 10 to 8 on a deliberately redundant synthetic family; the verifier passed 20/20 checks, but realized execution cost did not improve. Uniform prior over hypothesis IDs was not preserved. Report: https://github.com/nkinzogomer-eng/PRISM/blob/main/reports/decision-equivalence-quotient-2026-10-15.md
- **Dominated-observation pruning:** observation count reduced from 2 to 1 in a constructed dominance case; 20/20 checks passed and the optimal execution cost remained 1.00 abstract units. This validates the local rule in its stated domain, not general superiority. Report: https://github.com/nkinzogomer-eng/PRISM/blob/main/reports/dominated-observation-pruning-2026-10-15.md

**Interpretation:** the repository has verified some narrow transformations, but has not shown a general cost reduction or an advantage over strong external systems. A structural planner is still premature until a more demanding baseline protocol is established.

## 3. Candidate research hypothesis (narrow and falsifiable)

### H-SCM-1 — verified structure-aware orchestration

For a defined family of deterministic decision problems with repeated substructure, non-uniform operation costs, and a measurable sparse/redundant dependency structure, a model-independent controller that:
1. applies only transformations with explicit machine-checkable preservation conditions;
2. reuses intermediate results only when dependency invalidation is sound; and
3. chooses among simple policies and specialized deterministic solvers per instance,

can achieve the same verified decision quality as the strongest fixed baseline while reducing **total end-to-end cost** (planning + feature extraction + transformation + execution + verification + memory/communication costs) on held-out instances.

This is **not** a claim of novelty yet. Each ingredient has prior art. The research contribution would have to be a specific, reproducible composition or a new decision-preserving transformation/selection principle that outperforms the closest baselines.

### Expected regime and counter-regime

- Expected to help: repeated runs, expensive operations, redundant observations/dependencies, small structural parameters, and a target decision invariant under safe abstraction.
- Expected not to help: tiny one-shot tasks, dense/parity dependencies, rapidly changing inputs, expensive transformation discovery, poor structural features, or tasks where every input can affect the target decision.
- If the controller does not beat the strongest baseline on held-out cases after all costs are counted, reject or narrow H-SCM-1.
- If it only helps one constructed synthetic family, report a narrow special-case result, not a general SCM advantage.

## 4. Phase 2 experimental protocol

### 4.1 First reference benchmark (before cyber)

Use finite deterministic instances first because exact outcomes and exact small-instance optima can be computed. Include:
- redundant observations/hypotheses;
- sparse and dense dependencies;
- parity/dense controls;
- unequal operation costs;
- repeated tasks with controlled input changes;
- omitted-world/misspecified models;
- adversarial near-dominance cases;
- instances where every observation can affect the target decision.

Do not tune and report on the same seeds. Generate a development set, freeze policies and thresholds, then run held-out seeds and adversarial families. Keep generators and hidden truth unavailable to selectors.

### 4.2 Baselines

At minimum:
1. best fixed-cost order;
2. seeded random policy;
3. simple information/decision-gain policy;
4. exact optimal policy on small instances;
5. the best current PRISM policy;
6. a no-transformation run;
7. an ablation for each transformation;
8. an instance-specific solver/algorithm portfolio baseline where a suitable library exists.

For later cyber work, add mature domain tools (e.g. static analysis, fuzzing, symbolic execution, and existing vulnerability benchmarks) rather than comparing only to generic policies.

### 4.3 Metrics and accounting

Report:
- verified decision quality;
- correct certificates, incorrect non-abstentions, abstentions, and unresolved cases separately;
- transformation discovery/application/verifier costs;
- planning, preprocessing, execution, and verification wall time;
- CPU time, peak RSS memory, and operation counts;
- disk/communication costs and monetary costs when relevant;
- cold-start and amortized repeated-run costs;
- median, tail latency (p90/p95 where sample size supports it), variability/confidence intervals;
- hardware, operating system, language/runtime versions, seeds, and exact commit.

A “cost unit” is not seconds. Keep abstract operation costs and measured wall-clock/resources as separate quantities. Do not claim energy improvements without direct measurement or a transparent, justified proxy.

### 4.4 Decision rule

Support H-SCM-1 only if held-out evaluation shows:
- no unacceptable loss in verified decision quality;
- an end-to-end cost improvement over the strongest relevant baseline;
- no hidden oracle leakage;
- preserved guarantees checked independently;
- repeatability across more than one family and no cherry-picked seeds;
- a documented regime where it helps and a counter-regime where it loses.

Use uncertainty intervals and report negative results. The benchmark must be designed before looking at held-out outcomes.

## 5. Model independence contract

The kernel's required operation must work with external AI/model access disabled. The implementation must:
- avoid importing or requiring a model client for core execution;
- expose deterministic, explicit interfaces for any optional advisor;
- treat advisor output as untrusted proposals;
- independently validate any proposed transformation, evidence interpretation, or result;
- report model calls and cost separately in optional-mode experiments;
- test the no-model path in CI.

Ciel may later orchestrate long-running missions and tools, but is not required to make the core algorithms function. Ciel integration must not be used to disguise a model dependency inside the core.

## 6. Research and implementation decisions

**Proceed now**
- preserve current finite reference model and negative results;
- maintain a source-backed theory register;
- add explicit benchmark protocols and full-cost accounting;
- design the next experiments before implementing a general planner.

**Do not proceed yet**
- do not claim a new universal theory;
- do not implement a broad structural planner on the strength of current synthetic wins;
- do not treat hypothesis-count reduction as computation reduction;
- do not merge AI-model dependence into the kernel;
- do not make zero-day discovery or agency-level capability a near-term acceptance claim.

**Phase 1 conclusion:** the theoretical map, limitations, falsifiable candidate hypothesis, and Phase 2 protocol are specified and checked into the repository. The documentation consistency checks passed (15/15 assertions; 10/10 internal links), and repository CI run [38944823840](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38944823840) passed the unit-test suite and both existing benchmark steps. Phase 1 is therefore complete as a research-planning/audit gate. This does **not** validate H-SCM-1 or establish SCM superiority; Phase 2 must test that hypothesis. Current evidence still does not justify a general advantage claim.

## 7. References and source-selection notes

Primary/authoritative sources are preferred where available; one source per family is not an exhaustive systematic review.

1. Cousot & Cousot, 1977, abstract interpretation: https://www.di.ens.fr/~cousot/COUSOTpapers/POPL77.shtml
2. Downey & Fellows, parameterized complexity: https://link.springer.com/book/10.1007/978-1-4471-5559-1
3. Burckhardt et al., incremental/self-adjusting computation: https://www.microsoft.com/en-us/research/publication/two-for-the-price-of-one-a-model-for-parallel-and-incremental-computation/
4. Willsey et al., e-graphs/equality saturation: https://doi.org/10.1145/3815481
5. Lam et al., optimal extraction on sparse equality graphs: https://doi.org/10.1145/3689801
6. Masud & Lisper, slicing correctness: https://doi.org/10.1145/3434489
7. Xu et al., SATzilla algorithm portfolio: https://arxiv.org/abs/1111.2249
8. Petitet et al., active sampling computation cost: https://www.nature.com/articles/s41562-021-01116-6
9. SAT Competition 2020, certificate checking: https://www.sciencedirect.com/science/article/pii/S0004370221001235

This is a targeted audit of the theories most directly connected to the current PRISM design. A later specialized review is required before claiming novelty in a particular cyber or astronomy task.
