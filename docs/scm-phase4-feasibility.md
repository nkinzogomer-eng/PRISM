# Phase 4 feasibility note — 2026-10-16

## Preliminary source checks

The initial candidate review found a better first fit than Java for the prototype's current environment:

- **OWASP Benchmark for Python v0.1** is the preferred pilot candidate because the current PRISM repository and first evaluator can remain Python-only.
- Its upstream README calls v0.1 a preliminary release; the OWASP project page lists 1,230 cases across 13 categories.
- The upstream repository provides `expectedresults-0.1.csv` with test ID, category, expected vulnerability boolean, and CWE. The repository declares GPL-3.0.
- A current upstream issue reports a possible false-positive label in Path Traversal case BenchmarkTest00008. This is a concrete reason to retain label-audit and ambiguity reporting rather than treating all expected labels as infallible.
- OWASP Benchmark for Java v1.2 remains a possible replication, but requires a separate Java/Maven toolchain and has a GPL-2.0 license.
- NIST SARD/Juliet is a possible later replication; its official catalogue lists large Java/C/C++ suites, including 28,881 Juliet Java 1.3 cases. Dataset scale and older synthetic test patterns make it a separate evaluation, not a pool to mix silently with the OWASP benchmark.

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
