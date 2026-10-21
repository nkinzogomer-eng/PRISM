# SCM / PRISM Phase 4.3B — verified incremental computation (development only)

**Date: 2026-10-21. Status: experiment, NO superiority claim pending measurement.**
Stacks on Phase 4.3A / PR #15. Main and negative AST-selection PR #14 remain untouched.

## Concrete scientific question

Does a bounded, model-independent cost planner yield a *full-finding-preserving* runtime benefit beyond (a) a complete fresh scan and (b) a strong, conventional SHA-256 file cache with change-only reanalysis?

**Scope:** OWASP Python v0.1 development modules, pinned Bandit 1.8.6 and Semgrep 1.181.0 with immutable community-security rules. The goal is not zero-day discovery, semantic security verification, or proving program correctness.

## The three arms, what is and is not novel

1. `full`: fresh Bandit and Semgrep processes each analyze every module of the updated snapshot, retaining all findings.
2. `hash_cache`: retain complete, per-module normalized findings from a prior complete scan only where module *bytes* and active scanner/rule content are unchanged; re-run both scanners over changed modules. This is a known, strong baseline, not an SCM invention.
3. `prism`: select `full` or `hash_cache` independently per scanner based on estimated historical execution cost, setup cost and changed-file fraction. The planner is deterministic, requires no AI and never sees benchmark labels or comparison results before deciding. Merely choosing the strong baseline is NOT SCM superiority.

Unlike Phase 4.3A, **no Semgrep finding is intentionally omitted because Bandit already found something**. The entire pair of normalized scanners' alerts must match fresh full scans, including location, rule, severity/message and multiplicity.

## Frozen input protocol and edits

Benchmark SHA: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`; Linux CI source manifest (raw file bytes + names): `fe0ec67dcc328feb33d592b790563add38c721af4b89abcf839e56bc9e3b9b9d`. The development benchmark's original source files are never modified.

After cold full-corpus cache build, create independent synthetic edited snapshots at three edit volumes: `one` (1/1230 files), `tenth` (123/1230), and `all` (1230/1230). Fixed pseudorandom seeds choose files independent of labels. Most edits append a unique marker comment; one of every eight changed modules additionally receives a non-executed-by-scanners `eval("1 + 1")` call, to test genuinely new alerts. The benchmark labels cease to be meaningful on edited snapshots: they **must not be used for detection scoring**. These edits are *not* an untouched holdout.

Each arm rereads files, creates its edits, hashes all modules, validates rule content, stages unchanged bytes for every scanner invocation, checks process status/JSON/exact scanned inventory, merges cached alerts, cleans temporary directories, and measures elapsed time including these costs. Per tool we also measure scanner subprocess elapsed and child CPU time. Scanner installations/network and final report serialization are excluded, and peak RSS/energy/USD are not yet available (never count as zero).

**Cache assumptions:** the scanner rule content, binary version, flags and selected relative path are pinned. Other implicit environmental inputs or cross-file dependencies may exist. Therefore the cache is an *experimental* module-local hypothesis. Each edited-snapshot result must be paired with a fresh full scan, and ALL normalized findings must match. This empirical equality does not formally prove module independence or safe production caching.

## Preconditions and negative gates

- Abort on missing/extra scanned files, scanner errors, source manifest drift, rule/config drift without invalidation, missing cache record or mutated source bytes reused.
- Abort if a single alert identity is missing, extra, moved or duplicated relative to the full arm on the same edited snapshot.
- No unscanned case is considered negative; unchanged cached observations are conditionally reused, with provenance recorded.
- Fresh full vs fixed-cache and fresh full vs PRISM comparisons are made at the same scenario/repetition, under the same pinned tool inventory and mutation selection.
- Claim only an exploratory development speed signal if the median end-to-end cost is at least 10% below the full arm *and* alert equality holds. Two repetitions on GitHub-hosted hardware are insufficient for stable speedup/p95 confidence intervals.
- Claim **no SCM-specific advantage** unless PRISM beats the competent exact-hash cache baseline at matched full-finding quality with a robust cost reduction, and later survives untouched holdout validation and native incremental/tool optimizations.

The *cold cache build* is reported separately. For repeated workloads, total lifecycle cost must additionally include its amortization: expensive initialization is not free. Run-order, scanner startup, cache-fingerprint computation and baseline-choice overhead count in each update iteration.

## Counterexamples and separate future regimes

If the rules or scanner binaries change, invalidate the entire cache. Tests cover stale-source bytes, stale scanner configuration, missing scanner records, unexpected findings, duplicated alerts and new/removed modules. A later test must cover cross-file imports/dependencies and project-level rules on a separate corpus; until then the safe production fallback for uncertain cross-module analyses is a complete scan.

A meaningful larger SCM gain must emerge from mechanisms distinct from exact hashing: certified dependency-component invalidation, safe query-family elimination, or reuse of expensive intermediate verification with explicit proof boundaries. Those will need strong native caching baselines and independent tasks; results from this study must not be used as proof of general SCM superiority.

## Reproduce

```bash
python -m unittest discover -s tests -p 'test_phase43b_incremental.py' -v
python scripts/measure_phase43b.py \
  --source-dir benchmark/testcode \
  --semgrep-config semgrep-rules/python/lang/security \
  --semgrep-config semgrep-rules/python/flask/security \
  --output reports/phase43b-ci --repeats 2
```

A dedicated GitHub Actions workflow `phase43b-incremental.yml` captures the raw scan JSON and `measurement.json`, reporting alert-preservation checks, per-arm timings and cache construction costs. A new independent holdout remains unopened.
