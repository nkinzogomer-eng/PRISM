# Phase 4 — strong-baseline and competitive-evaluation addendum

**Status:** required protocol extension; no competitive result has been established.  
**Date:** 2026-10-17

## Purpose

The first pilot compares Bandit, Semgrep Community Edition, and a fixed OR policy. This is not a sufficient basis for a claim that PRISM is competitive with leading application-security analysis. The next evaluation must include stronger, appropriately configured baselines and must distinguish different task definitions.

The goal is not to declare one universal "best scanner." Tools differ in supported languages, analysis scope, rule coverage, commercial features, setup cost, and runtime. Results must be reported by benchmark, category/CWE, operating mode, and resource envelope.

## Baseline ladder

### Tier A — reproducible open baselines

1. Bandit, pinned version and configuration.
2. Semgrep Community Edition, pinned CLI version **and immutable rule content**. A moving registry alias is not a frozen ruleset.
3. CodeQL CLI with Python `default` query suite.
4. CodeQL CLI with Python `security-extended` query suite, reported separately from `default`.
5. Fixed combinations declared in advance: OR and, where meaningful, a stricter consensus/triage policy. Any thresholds must be selected only on development data.

Record all commands, database/build steps, query-pack identifiers and hashes, environment variables, tool exit statuses, timeouts, raw outputs, and failures. A tool that cannot run on the pinned benchmark must be marked unsupported/failed, not assigned zero detections.

### Tier B — stronger or paid baselines, when access is legitimate and reproducible

- Semgrep Pro / Pro Engine and applicable Pro rules, if access and licensing permit.
- Other well-supported commercial SAST tools only if the same benchmark can be scanned, their exact product/version/configuration can be recorded, and results can be reproduced or independently audited.

Tier B must not be a prerequisite that blocks open research. Report access limits explicitly. Do not compare a paid, cross-file configuration against a deliberately narrow community configuration and then generalize to the products as a whole.

### Tier C — different analysis modalities (separate leaderboard)

Because OWASP Benchmark for Python is a runnable web application, DAST/IAST results may later be measured in a separate experiment. Do not rank SAST, DAST, and IAST as if they had identical inputs or cost. Runtime tests must run locally in an isolated environment and preserve the same benchmark revision and labels.

## Fairness and task validity

- The current module-level rule ("any finding in a test module means positive") is a coarse smoke-test only. It can count a finding unrelated to the intended CWE as a true positive.
- For the competitive comparison, score findings against the intended case/CWE and source location where the tools expose sufficient metadata. Publish both strict case/CWE scoring and the old coarse metric for continuity.
- Audit the known upstream label concern, `BenchmarkTest00008`, before locking the labels. Record adjudication, exclusions, and sensitivity results; do not silently edit labels to favor a tool.
- Publish per-category/CWE precision, recall, F1, false-positive rate, and false-negative counts. Also report macro averages so large categories do not dominate.
- Separate scanner capability from PRISM's orchestration contribution. Every tool gets its strongest reproducible supported configuration; PRISM must use the same tool inventory and may not gain hidden information unavailable to other policies.
- The controller and policy tuner may see development labels only. Freeze a family-aware development/held-out split, exact configs, thresholds, and stopping rules before held-out scoring.
- Use paired per-case comparisons and confidence intervals clustered by source/template family. Repeat timings in clean runs; report median and p90/p95, cold and warm costs, CPU, peak memory, setup/preprocessing, planning, normalization, verification, and tool invocation counts.
- Keep all raw outputs and machine-readable per-case predictions. Report scanner failures, unsupported cases, timeouts, and parsing errors explicitly.

## Implemented automation (initial)

A separate GitHub Actions workflow, `.github/workflows/phase4-codeql.yml`, now attempts CodeQL Python `default` and `security-extended` analyses on the pinned OWASP Benchmark revision, preserves SARIF, normalizes case-level predictions, scores the coarse metric, and uploads artifacts. The SARIF normalizer has regression tests. The first execution caught two integration errors and was not accepted as a CodeQL benchmark result: the action writes SARIF into a directory containing `python.sarif`, and the initial database source root selected PRISM instead of the nested benchmark checkout. After correcting the source root, the pull-request SARIF still reported zero benchmark alerts despite extracting the 1,230 modules. Inspection showed the SARIF run used `incrementalMode: diff-informed`, so PR-only change filtering can invalidate a full-dataset score when the benchmark is a nested checkout. The CodeQL benchmark workflow now runs on pushes to the research branch (and manual dispatch), not on pull-request events, so the full dataset is analyzed without PR diff filtering. The zero-alert outputs from the earlier runs are explicitly invalid as full-dataset competitive scores. These failures illustrate why tool output and scope are checked before interpreting metrics. The coarse mapping is retained only for continuity and must not be treated as CWE-relevant detection.

## PRISM comparison arms

At minimum compare:

1. Each Tier A tool alone, in its declared configuration.
2. Fixed OR and any fixed sequential policy.
3. A development-tuned cost-aware policy.
4. PRISM controller with ablations of its structural decisions.
5. A transparent best-of-fixed-policy selected on development data (not held-out data).
6. An oracle only on small tractable subsets, clearly labeled non-deployable.

PRISM is not credited merely for selecting the best scanner after seeing labels, using fewer tool calls while missing more vulnerabilities, or shifting costs into preprocessing/planning. It must be compared at matched quality or under a predeclared cost-sensitive utility function with explicit false-negative penalties. Report the full Pareto frontier of quality versus cost rather than one arbitrary composite score.

## Claims and gates

A claim of "better than leading baselines" is allowed only if:

- The held-out split was untouched during design and tuning.
- At least one strong, reproducible baseline suite completed successfully.
- Findings are scored at category/CWE relevance, not only "any finding in module."
- Independent label audit and verifier checks pass.
- PRISM's improvement is practically meaningful, reproducible across repeated runs, and supported by uncertainty estimates.
- No material quality regression is hidden by an aggregate score.
- End-to-end costs include all controller and analysis costs.

Otherwise the conclusion must be narrower (for example, "improves cost/quality over a named fixed policy on these held-out regimes") or negative. Even a positive OWASP result does not establish real-world zero-day discovery, remediation effectiveness, or general superiority across cybersecurity.

## References

- OWASP Benchmark for Python describes v0.1 as a preliminary benchmark and supports SAST, DAST, and IAST: https://github.com/OWASP-Benchmark/BenchmarkPython and https://owasp.github.io/www-project-benchmark/
- CodeQL Python query suites: `default`, `security-extended`, and `security-and-quality`: https://codeql.github.com/docs/codeql-query-help/python/ and https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/python-built-in-queries
- Semgrep Pro rules use additional cross-file/cross-function dataflow capabilities and curated sources, sinks, propagators, and sanitizers: https://semgrep.dev/products/semgrep-code/pro-rules/

These references describe tool capabilities; they do not prove that a tool will score best on this particular dataset.
