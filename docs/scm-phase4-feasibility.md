# Phase 4 feasibility note — 2026-10-16

## Preliminary source checks

Sources reviewed on 2026-10-16:
- OWASP Benchmark Python repository: https://github.com/OWASP-Benchmark/BenchmarkPython
- Expected labels: https://github.com/OWASP-Benchmark/BenchmarkPython/blob/main/expectedresults-0.1.csv
- License: https://github.com/OWASP-Benchmark/BenchmarkPython/blob/main/LICENSE
- Official OWASP Benchmark project description and case counts: https://owasp.org/www-project-benchmark/
- Upstream label concern (BenchmarkTest00008): https://github.com/OWASP-Benchmark/BenchmarkPython/issues/1
- OWASP Benchmark Java: https://github.com/OWASP-Benchmark/BenchmarkJava
- NIST SARD suite catalogue: https://samate.nist.gov/SARD/test-suites/
- Semgrep Community Edition: https://semgrep.dev/products/community-edition


The initial candidate review found a better first fit than Java for the prototype's current environment:

- **OWASP Benchmark for Python v0.1** is the preferred pilot candidate because the current PRISM repository and first evaluator can remain Python-only.
- The candidate is pinned for evaluation to upstream commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (resolved from `main` during this check). The `expectedresults-0.1.csv` Git blob SHA reported by the connector is `f38bbc821529b21476cae68953edb6c95a23ad0e`; record a SHA-256 archive checksum when the data is actually downloaded.
- The upstream README calls v0.1 preliminary. A direct parse of the pinned expected-results file found **1,230 rows, 1,230 unique test IDs, zero duplicate IDs, zero malformed label rows, 452 positive labels, 778 negative labels, and 14 distinct category values**. This differs from a summary count of 13 categories on the OWASP page; use the actual CSV and report the discrepancy rather than silently resolving it.
- The upstream repository declares GPL-3.0. The expected-results CSV contains test ID, category, expected boolean, and CWE.
- An upstream issue reports a possible label problem in Path Traversal case BenchmarkTest00008. It is marked positive in the current CSV; this case must be audited and its disposition logged before held-out scoring.
- OWASP Benchmark for Java v1.2 remains a possible replication, but requires a separate Java/Maven toolchain and has a GPL-2.0 license.
- NIST SARD/Juliet is a possible later replication; its official catalogue lists large Java/C/C++ suites, including 28,881 Juliet Java 1.3 cases. Dataset scale and older synthetic test patterns make it a separate evaluation, not a pool to mix silently with the OWASP benchmark.

## Label distribution observed in the current CSV

| Category | Cases | Positive | Negative |
|---|---:|---:|---:|
| pathtraver | 168 | 65 | 103 |
| sqli | 16 | 5 | 11 |
| xpathi | 186 | 51 | 135 |
| xxe | 28 | 8 | 20 |
| weakrand | 326 | 99 | 227 |
| hash | 151 | 71 | 80 |
| securecookie | 39 | 24 | 15 |
| redirect | 34 | 13 | 21 |
| trustbound | 37 | 18 | 19 |
| codeinj | 53 | 20 | 33 |
| ldapi | 29 | 16 | 13 |
| deserialization | 54 | 18 | 36 |
| xss | 89 | 31 | 58 |
| cmdi | 20 | 13 | 7 |

These counts are a direct parse of the label CSV, not scanner performance. Several categories are small and class balance varies substantially; report category-level metrics and avoid treating the micro-average as sufficient.

## Local toolchain snapshot

At the time of this check, the available execution container reports Python 3.13.5, Java, and Git. Semgrep, Bandit, and Maven were not found on PATH. This is only a snapshot of the current execution container, not a claim about the user's computer or GitHub runners.

## Revised proposed order

1. Pin OWASP Benchmark for Python v0.1 to a commit and checksum; audit license, label CSV, and known label issues.
2. Identify two compatible local static analyzers and pin their versions/configurations. Do not assume they are installed.
3. Build and test a tool-agnostic evaluator for normalized per-case outputs, including unknown/error/unsupported statuses and conservative coverage bounds.
4. Establish individual-tool baselines before implementing any PRISM selector.
5. Only after the baseline is reproducible, define a fair fixed/cost-aware/PRISM comparison and lock the held-out split.

## Limits

This feasibility check is not a scanner run and yields no measured detection or performance results. OWASP Benchmark Python v0.1 is preliminary and must not be used alone to claim broad software-security efficacy. Dataset labels and template-derived cases remain imperfect proxies for production software.
