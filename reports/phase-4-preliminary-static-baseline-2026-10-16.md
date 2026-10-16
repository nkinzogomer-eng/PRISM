# Phase 4 preliminary static baseline — 2026-10-16

**Status:** pilot diagnostic only; not a held-out result and not evidence of PRISM benefit.

## Environment and data

- Benchmark: OWASP Benchmark for Python v0.1, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.
- Expected-result label CSV Git blob: `f38bbc821529b21476cae68953edb6c95a23ad0e`.
- Label audit: 1,230 unique cases; 452 positive and 778 negative labels across 14 category values.
- Source: 1,230 corresponding `testcode/BenchmarkTestNNNNN.py` modules.
- Environment: GitHub-hosted Ubuntu runner, Python 3.12; Bandit 1.8.6; Semgrep 1.127.1.
- Scoring rule: a case is predicted positive if the tool reports at least one finding in that case's test module.

## Bandit 1.8.6 — first valid run

| Metric | Result |
|---|---:|
| Source modules scanned | 1,230 |
| Modules with ≥1 finding | 352 (28.6%) |
| Raw findings | 533 |
| Cases evaluated | 1,230 (100% coverage) |
| TP | 224 |
| FP | 128 |
| TN | 650 |
| FN | 228 |
| Precision | 63.64% |
| Recall | 49.56% |
| F1 | 55.72% |
| False-positive rate | 16.45% |
| Wall time reported by runner | 5.56 s |

These metrics are relative to the benchmark's supplied binary labels under the coarse “any finding in module” rule. They do not mean that 352 real-world vulnerabilities were confirmed. The result implies that Bandit, under this exact invocation and mapping, failed to flag 228 of the 452 benchmark-positive cases; it also flagged 128 benchmark-negative cases. The case-level mapping may count findings unrelated to the case's intended category/CWE, so the raw finding records must be audited before final claims.

## Semgrep 1.127.1 — first attempt failed

The scanner did not produce valid JSON because its startup failed with `ModuleNotFoundError: No module named 'pkg_resources'` in the OpenTelemetry instrumentation import chain. This is an environment/dependency compatibility failure, not a zero-finding result and not evidence about Semgrep's detection quality.

The workflow now pins `setuptools==80.9.0` to restore the dependency expected by this Semgrep version. The retry must succeed before any two-tool comparison is reported.

## CI evidence

- [Scoring tests and first successful two-tool pilot](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38971933848): workflow succeeded, both analyzers emitted valid JSON, and the scorer evaluated all 1,230 cases for each tool.
- A subsequent runner change adds an explicit fixed all-tools OR baseline; its output is pending and will be reported separately.

## Interpretation and next gates

1. This is an initial, in-sample baseline over all benchmark modules; no development/held-out split has been frozen yet.
2. Semgrep's `p/python` registry ruleset is not immutable in this run. Pin the ruleset content/revision before final comparisons.
3. Audit the known upstream Path Traversal label concern (BenchmarkTest00008) and define any label exclusions before locked evaluation.
4. Examine per-category/CWE results and representative FP/FN cases; “any finding” is only a coarse first mapping.
5. Only after the individual-tool baselines are reproducible should fixed-order, cost-aware, and PRISM orchestration be compared with identical visible inputs and full end-to-end costs.

**Current conclusion:** Bandit provides a measurable but limited first baseline. No PRISM-versus-baseline result exists. Phase 4 remains in progress.
