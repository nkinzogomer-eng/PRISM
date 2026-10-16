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

## Fixed all-tools baseline (OR policy)

The reproducible runner was extended to flag a case if either Bandit or Semgrep reports at least one finding.

| Metric | Bandit | Semgrep | Fixed OR (both tools) |
|---|---:|---:|---:|
| Wall time in this run | 5.47 s | 18.11 s | 23.58 s total |
| Cases flagged | 352 | 153 | 358 |
| TP | 224 | 89 | 227 |
| FP | 128 | 64 | 131 |
| TN | 650 | 714 | 647 |
| FN | 228 | 363 | 225 |
| Precision | 63.64% | 58.17% | 63.41% |
| Recall | 49.56% | 19.69% | 50.22% |
| F1 | 55.72% | 29.42% | 56.05% |
| False-positive rate | 16.45% | 8.23% | 16.84% |

The fixed OR policy finds only **3 additional positive cases** over Bandit alone, while adding 3 false positives and increasing the measured tool runtime from 5.47 s to 23.58 s (about 4.3× in this single run). F1 increases by only 0.33 percentage points and the false-positive rate worsens slightly. This is evidence that naively running both tools and OR-ing their outputs has poor marginal value on this coarse benchmark mapping. It is not yet a statistical claim: timing is a single shared-runner measurement, and category/CWE relevance has not been adjudicated.

## CI evidence

- [Scoring tests and two-tool plus fixed-OR pilot](https://github.com/nkinzogomer-eng/PRISM/actions/runs/38972068969): workflow succeeded, both analyzers emitted valid JSON, and the scorer evaluated all 1,230 cases for each tool and the combined policy.
- The earlier Semgrep failure was a startup dependency issue; pinning `setuptools==80.9.0` resolved it.

## Interpretation and next gates

1. This is an initial, in-sample baseline over all benchmark modules; no development/held-out split has been frozen yet.
2. Semgrep's `p/python` registry ruleset is not immutable in this run. Pin the ruleset content/revision before final comparisons.
3. Audit the known upstream Path Traversal label concern (BenchmarkTest00008) and define any label exclusions before locked evaluation.
4. Examine per-category/CWE results and representative FP/FN cases; “any finding” is only a coarse first mapping.
5. Only after the individual-tool baselines are reproducible should fixed-order, cost-aware, and PRISM orchestration be compared with identical visible inputs and full end-to-end costs.

**Current conclusion:** Bandit provides a measurable but limited first baseline. No PRISM-versus-baseline result exists. Phase 4 remains in progress.


## Follow-up diagnostic — immutable security-only Semgrep configuration (2026-10-17)

A new run used Bandit 1.8.6 and Semgrep CLI 1.181.0 with the Semgrep Community rules repository pinned to commit `17e31e11ebac99fb7dfe1cd288f7a32151b6f3f9`. The Semgrep configuration was restricted to `python/lang/security` and `python/flask/security`. This remains a single-run, in-sample, coarse “any finding in module” comparison against the supplied labels; it is not a held-out result and findings have not been matched to intended CWE/source locations.

| Metric | Bandit 1.8.6 | Semgrep 1.181.0, pinned security rules | Fixed OR | Fixed AND |
|---|---:|---:|---:|---:|
| Tool wall time (single run) | 5.64 s | 22.05 s | 27.69 s total | 27.69 s total |
| Cases flagged | 352 | 371 | 469 | 254 |
| TP | 224 | 173 | 262 | 135 |
| FP | 128 | 198 | 207 | 119 |
| TN | 650 | 580 | 571 | 659 |
| FN | 228 | 279 | 190 | 317 |
| Precision | 63.64% | 46.63% | 55.86% | 53.15% |
| Recall | 49.56% | 38.27% | 57.96% | 29.87% |
| F1 | 55.72% | 42.04% | 56.89% | 38.24% |

The OR policy raises recall by 8.40 percentage points and reduces misses by 38, but adds 79 false positives and raises F1 by only 1.17 percentage points. In this run, the two-tool wall time was about 4.9 times Bandit alone. The AND policy reduces the number of flags but sharply worsens recall and F1. **Neither naïve combination is an adequate SCM result.** These timing ratios are descriptive only because each tool was timed once on a shared hosted runner.

### Category-level signal from the same run

Bandit and Semgrep have complementary but incomplete coverage. In this coarse label mapping, Bandit flags no cases in path traversal, redirect, secure-cookie, trust-boundary, or XSS categories; Semgrep adds some path-traversal and redirect flags and flags secure-cookie cases, but its XSS configuration still misses all positive XSS cases. Both tools show important blind spots in LDAP injection and other categories. These category results need finding-to-CWE/source-location adjudication before being treated as vulnerability detection accuracy.

### Live correction and next experiment

- The unfiltered Semgrep `python/` directory was rejected as too noisy: it flagged all 1,230 cases (precision 36.75%, recall 100%, F1 53.75%) and took 36.04 s in one run.
- The baseline now uses only the pinned Python language-security and Flask-security directories, and the runner records both fixed OR and fixed AND policies.
- Next, inspect the full push-triggered CodeQL SARIF and score; the PR-triggered CodeQL output was diff-informed and is not a valid full-dataset result.
- Then audit category/CWE and location relevance, freeze the family-aware held-out split, and compare a development-tuned cost-aware selector and PRISM with all planning/normalization/verification costs charged. Do not use benchmark labels or category identities as hidden runtime features.
- No PRISM orchestration has yet been tested. No SCM advantage is demonstrated at this stage.


### Follow-up — Bandit-first selective Semgrep (2026-10-17)

I added and ran a fixed sequential policy that first runs Bandit over all 1,230 cases, then runs the same pinned Semgrep security rules only on the 878 cases Bandit did not flag. The policy uses only Bandit's observable findings to decide which files receive the second scan; it does not read benchmark labels for selection.

| Metric | Full fixed OR | Bandit-first selective Semgrep |
|---|---:|---:|
| Bandit wall time | 4.12 s | 4.12 s |
| Semgrep wall time | 16.49 s | 13.07 s |
| Sum of policy tool times | 20.61 s | 17.19 s |
| Cases sent to Semgrep | 1,230 | 878 |
| TP / FP / TN / FN | 262 / 207 / 571 / 190 | 262 / 207 / 571 / 190 |
| Precision | 55.86% | 55.86% |
| Recall | 57.96% | 57.96% |
| F1 | 56.89% | 56.89% |

This preserves the same coarse decisions and saves 3.42 seconds (about 16.6%) versus the full OR run in this single measurement. It is a real execution-cost improvement for this fixed policy, but **not a meaningful quality improvement and not evidence of SCM superiority**. The measured total is still about 4.2 times Bandit alone for only a 1.17-point F1 increase over Bandit, so we must test whether a cost-aware controller can obtain a better trade-off or conclude this tool pair is not worth escalating on this benchmark. Repeat timings and held-out tests are still required.
