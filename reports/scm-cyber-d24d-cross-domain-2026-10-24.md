# PRISM / SCM — D2.4D cross-domain cyber results (24 October 2026)

**Engineering PASS. Scientific superiority beyond conventional static slicing: NOT DEMONSTRATED.**

- Successful final [GitHub Actions run 40097924140](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40097924140), tested code commit `91b43fc42b33a3759b74eb32698b2dd54b100e07`.
- Draft PR #30, branched from isolated D2.4C, not merged into main.
- Eight Python adversarial/unit tests passed; 80 correlated seeded finite-model configurations completed. Full JSON and resource evidence archived in the action artifact `d24d-cross-domain-model-reproducible`.
- Deterministic verdict/count SHA-256: `3c3fe7e615262bf72295f6d963a914ae0124444bdde26c50ca59361af6241cea`.

## Comparative model results

| Threat family | Seeded configurations | Full BFS median attempts | Conventional static slicing+BFS | SCM quotient+slice |
|---|---:|---:|---:|---:|
| Web authorization | 16 | 420 | 21 | 21 |
| Untrusted input → sink | 16 | 1,458 | 122.5 | 122.5 |
| DeFi D2.2 finite model | 48 | 305 | 170 | 170 |

Across all 80 model configurations: 40 positive finite-model witnesses and 40 finite-model negative scenarios. All three policies agree with the exhaustive model-level oracle; all positive traces replay in the model. Each scenario is synthetic or preexisting researcher-authored D2.2, NOT an independent real-world vulnerability. Seed permutations are correlated and do not create 80 independent vulnerabilities.

**Critical negative scientific result:** The quotient component has exactly the same median search attempts and state expansion as conventional static slicing on all three families. It has **no observed added search advantage over the competent classical slicing comparator in this experiment**. Reduced attempts versus whole-alphabet BFS are an engineering benefit of known slicing, not evidence of a new scientific algorithm.

## Adversarial validity and corrections

1. A deliberately omitted guard/read dependency makes quotient search miss a witness found by full BFS. Dynamic auditing of writes cannot establish completeness of reads. This false-negative counterexample is retained in unit tests.
2. The measured policy elapsed times now include preparation/slicing overhead. Bounded-depth metadata audits are marked truncated and never mislabeled exhaustive.
3. Any missing effect, malformed state, or exhausted runtime budget is UNKNOWN/fail-closed, not a declaration of safety.
4. No production Solidity, web-app, C/C++, Python or JavaScript semantics are derived by this experiment. The OUSD EVM tests remain the separate D2.4C gate.

## Next critical research gate

Build conservative automatic source/effect frontends for at least two real cyber ecosystems, verify generated witnesses against externally authored runnable programs, and compare with strong existing fuzzing/symbolic and dependency-slicing baselines under equal budgets and independent root-cause labels. No external zero-day, historical SCFuzzBench root cause, or full-domain scientific superiority can currently be claimed. Keep this PR draft; do not merge into `main`.
