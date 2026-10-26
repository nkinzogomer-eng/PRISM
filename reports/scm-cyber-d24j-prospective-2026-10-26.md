# D2.4J — Actual prospective holdout: evidence, negatives, and next corrections

Date: 2026-10-26.

**Methodology gate: PASS. Detection/generalization gate: PARTIAL/INSUFFICIENT.**
There are **zero** newly verified real vulnerabilities and zero demonstrated
new vulnerability classes.

## Provenance and chronology

- Previous candidate generator *published before selecting this corpus*:
  commit `a1ac84271726e8a38870f0670ff54d5992249a09`, immutable Git blob
  `16e303970ad36e63f4126572efa2b6fdad718de5`.
- Three prospective repo/commit/path pairs published without source inspection:
  commit `12ddb220cde4c9619c0588487d773707c3ba20c8`.
- No changes were made to the candidate generator for this experiment.
- Independently rerun in GitHub Actions:
  [40303952197](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40303952197) —
  workflow completed successfully, with the negative results preserved.
- Full machine-readable evidence in `reports/d24j-prospective-result.json`,
  including source SHA-256/Git blob identities and abstentions.

## Preselected unseen source outcomes

| Public source | Source-generated candidates | Observed status |
| --- | ---: | --- |
| Solady ERC-4626 (`Vectorized/solady`) | **6** | Unverified hypotheses (4 preview/transition, 2 conversion round-trip) |
| Morpho Blue (`morpho-org/morpho-blue`) | **0** | `UNKNOWN_NOT_SAFE` — syntax frontend unsupported |
| Uniswap V3 Pool (`Uniswap/v3-core`) | **0** | `NO_CANDIDATES_UNKNOWN` — available source, no grammar match |
| **Total** | **6** | **1 abstention and 1 no-candidate unknown** |

All files were read from fixed public GitHub commit SHAs. The engine was
frozen beforehand, and all three targets remain in the denominator. The
trial is a **real out-of-sample source-generalization check** relative to
this exact frozen proposer; it is NOT an out-of-sample *vulnerability-recall*
test because there are no independently labeled ground-truth vulnerabilities
or dynamic evidence for this new cohort.

## Failure analysis (performed after recording the frozen outputs)

1. **Morpho Blue:** its `Morpho.sol` defines two overloaded `_isHealthy`
   functions. The inherited D2.4C lexical extractor treats duplicate
   function names as ambiguous and rejects the whole file. This is a
   missing frontend capability, **not evidence of absence of flaws**.
2. **Uniswap V3:** this source exposes pool operations such as `swap`,
   `mint`, `burn`, `flash`, and `_updatePosition`, without the syntactic
   preview/action or `get...`/`_update` relationship that the existing
   proposer needs. The proposer therefore emits zero candidates despite
   source availability. This shows a **fundamental coverage gap** in the
   property grammar, not a secure contract verdict.
3. **Solady:** the name/shape-based preview and inverse-conversion grammar
   generalizes to an independently maintained ERC-4626 implementation.
   None of its six candidates has yet received a real-EVM semantic oracle;
   **six hypotheses are not six discovered bugs**.

## Cost and reproducibility

No LLM calls were used. The reported full-source evaluation ran on an
ordinary hosted CPU, with no GPU required; separate CPU/memory benchmarking
and comparison against Slither/Echidna/Medusa remain **not performed**.

The D2.4J prospective CI job passed all **22 D2.4J Python tests**. The full
local PRISM regression suite ran **347 tests; 346 passed and one intentional
expected failure**. Earlier D2.4J native Uniswap V2 testing also passed its
three controls and detected one deliberately introduced temporary sync
mutation; that remains **lab sensitivity only**, not a real-world finding.

## Required design changes — for a NEW experiment, not this holdout

- Frontend: adopt a compiler-derived, overload-aware Solidity function IR
  with explicit modifiers/inheritance/import resolution, or abstain at a
  smaller *function* scope instead of losing an entire program.
- Hypotheses: derive invariants from storage transitions, authorization and
  economic state relationships, not primarily naming conventions such as
  `previewX`/`X` or `getX`/`_update`. Define semantics independently.
- Evidence: capture transaction-level EVM state deltas and cost, apply
  independently authored semantic oracles, and conduct mutation/negative
  controls **without using mutation labels as proposer input**.
- Scientific generalization: freeze the improved engine, then select a
  **different untouched** prospective cohort. Never report a retuned score
  on Morpho Blue/Uniswap V3 as though those same targets remained blind.
- Comparative superiority: execute pinned baseline tools under matched
  time/CPU/memory limits and retain false positives, false negatives and
  unresolved cases; only then evaluate scientific advantage.

**Conclusion:** the scientific procedure correctly exposed a weakness. PRISM
can generate useful candidates on some unseen DeFi sources at low cost, but
it is far from demonstrating comprehensive discovery or novel zero-days.
