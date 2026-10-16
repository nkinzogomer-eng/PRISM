# SCM–PRISM Phase 4: defensive cybersecurity evaluation protocol

**Status:** protocol draft; no empirical gate has passed.  
**Version:** 1.0 — 2026-10-16

## Research question

On public, labeled software-security benchmark cases, can a model-independent PRISM controller select and order existing defensive analysis tools to improve the end-to-end cost/quality trade-off against fair fixed and tool-native baselines, without increasing missed findings or unsupported certifications?

A null or negative result is valid. Freeze the protocol before inspecting held-out results.

## Safety scope

- Use only public benchmark data and local copies, or systems with explicit written authorization.
- Initial experiments are offline and static. No external-target scanning or operational attack activity is required.
- Any remediation test runs in a disposable worktree and is evaluated in a separate clean checkout.
- This phase cannot establish real-world prevention, incident-response autonomy, or previously unknown vulnerability discovery.

## Candidate benchmark

Primary candidate: OWASP Benchmark for Java, pinned to a release/commit and archive SHA-256. Before adoption, verify the source, license, labels, build requirements, and compatibility with the selected analyzers.

Fallback/replication candidate: a pinned subset of NIST SARD/Juliet, only if its licensing, labels, reproducibility, and tool compatibility are documented. Report datasets separately.

The first task is narrow: classify labeled cases for declared categories using static analysis, then evaluate outputs against benchmark labels. Labels are an imperfect reference, not proof of real-world exploitability.

## Dataset lock

Record source URL, release/commit, retrieval date, license, SHA-256, included case IDs, exclusions, label interpretation, runtime/build versions, analyzer versions/configurations, and exact commands. Group near-duplicate cases by source/template family; do not split related templates across development and held-out sets. Publish the split manifest and hashes. The controller must not access hidden labels.

## Comparison arms

All arms use the same inputs, pinned tools/rules, observable metadata, and resource limits.

1. Each analyzer individually in its supported configuration.
2. A predeclared fixed-order policy and an all-tools policy where feasible.
3. A transparent cost-aware policy tuned only on development data.
4. PRISM using the same operation catalogue and observable inputs, logging every selection, estimated/actual cost, evidence update, stop/abstain decision, and certificate scope.
5. An exact optimum only for small cases where tractable, clearly labelled as an oracle.

Include ablations for each PRISM-specific component. No arm gets free preprocessing or planning. Until a real adapter exists, the finite reference runner is not a cybersecurity result.

## Metrics

**Quality:** TP/FP/TN/FN; precision, recall, F1, false-positive and false-negative rates by category; macro and micro averages; abstention and incorrect non-abstention; tool disagreement and ambiguous labels.

**End-to-end costs:** preprocessing, representation conversion, planning, tool execution, normalization, and verification; per-case wall time (median and p90/p95), CPU time, peak memory, I/O where available, tool invocations, and any monetary/network cost. Report cold-start and amortized repeated-run costs separately. Publish the cost vector; do not combine unlike units into an arbitrary score.

**Remediation sub-study:** on a predeclared subset, test patches in disposable worktrees. Record tests before/after, independent confirmation of the original issue, regressions, new findings, patch size, and time/cost. Removing an alert alone does not count as a fix.

## Statistical and adversarial design

Freeze the protocol, splits, tools, metrics, and stopping rules before held-out runs. Use paired per-case comparisons and bootstrap confidence intervals clustered by source/template family. Report effect sizes and uncertainty. Hold out source/template families and, if data permits, a category. Include false cases, ambiguous labels, tool disagreements, timeouts, unsupported files, parser errors, and negative controls. Test whether PRISM abstains when its declared model cannot justify a conclusion. Re-run a fixed subset from a clean environment.

## Falsifiable gates

- **H4-A — reproducibility:** pinned data/tools and machine-readable per-case outputs; errors are accounted for.
- **H4-B — evaluator integrity:** independent evaluator and manually audited sample; hidden labels inaccessible to the controller.
- **H4-C — fair accounting:** every arm is charged for preprocessing, planning, execution, and verification; logs reconstruct results.
- **H4-D — utility:** on locked held-out data, PRISM improves a predeclared cost/quality trade-off over a strong baseline without exceeding a predeclared false-negative or incorrect-certification tolerance. A speed gain caused by missed findings fails.
- **H4-E — remediation:** independent verification shows fixes resolve the target issue without added regressions; this is separate from detection.

Do not mark Phase 4 complete until implementation and evaluation gates pass. If H4-D fails, publish the negative result and narrow or reject the hypothesis.

## Required artifacts

Protocol and decision log; dataset/license/checksum/split manifests; environment lock; reproducible runner; independent evaluator and tests; raw machine-readable results; per-tool, fixed, cost-aware, PRISM, and ablation results; report with uncertainty, failure cases, limits, and full costs; CI for a deterministic subset.

## Limitations

Benchmark labels and source patterns do not represent all production software. Static analyzers differ in language and rule coverage. Template leakage can inflate results. Shared-runner timing is noisy. A certificate is limited to its declared model and verifier; it cannot prove that the model or labels cover reality.

## Current decision

**No empirical conclusion yet.** The next gate is dataset/tool feasibility and a reproducible baseline. This protocol is not evidence that PRISM already performs cybersecurity analysis.
