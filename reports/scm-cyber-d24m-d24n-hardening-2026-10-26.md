# PRISM D2.4M → D2.4N — Compiler, CFG, native EVM, truly frozen cohort

Date: 2026-10-26. Published only to experimental branch
`research/scm-cyber-d24i-independent-holdout`. **Real novel public-source
vulnerabilities: 0. New vulnerability families proven: 0. Zero-days: 0.**

## 1. Reproducible engineering progress, separate from discovery

- [D2.4M final green](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40327343118)
  (following [initial checksum red](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40326872232)
  and [EVM-fork red](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40327157927)).
- Implementations: `prism/d24m_cfg.py`, `scripts/d24m_compiler_matrix.py`,
  `scripts/d24m_retrospective.py`, and EVM fixture
  `benchmarks/defi/d24m/D24MBranchValue.t.sol`.
- Corrected compiler matrix: 0.8.24 and 0.8.33, checksum verification **on**.
  Foundry 1.3.6 refused the 0.8.31 compiler with a checksum mismatch;
  its upstream issue is https://github.com/foundry-rs/foundry/issues/12911.
  The 0.8.33 compiler successfully compiled new OpenZeppelin code only
  after enabling the **Osaka** compilation target needed for `clz` in Yul.
  No checksum safeguards were bypassed.

### Retrospective — previously seen D2.4L sources

| Public code closure | D2.4L unsupported functions | D2.4M unsupported functions | Improvement |
| --- | ---: | ---: | ---: |
| OpenZeppelin AccessManager | 186 | **130** | −56 (30.1%) |
| Aave V3 Pool and dependencies | 228 | **202** | −26 (11.4%) |
| **Combined** | **414** | **332** | **−82 (19.8%)** |

Both real source closures compiled successfully: 2/2. These targets were
already examined previously, so this is a **retrospective repair
measurement**, NOT unseen-source generalization. **Zero independently
verified new flaws.**

The additional independent native EVM fixture executed 3/3 Solidity tests.
The intentionally flawed conditional bank exposes a one-ETH *local test
value* reentrant capture on the true branch, while the fixed false branch
preserves the benign depositor's funds; an ordinary withdrawal control passes.
The CFG rule must not combine mutually exclusive branches or code after
`return`. These are **known synthetic exploit and negative controls**.

## 2. D2.4M initially unseen source evaluation — negative result

- [GitHub Actions 40327803748](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40327803748).
- Engine & compiler source blobs frozen before target choice. Manifest
  published at commit `04228778cfab927444087d9033423d15cae960c6`.
- Compound Comet target `contracts/Comet.sol` **404** at the pinned commit;
  missing target retained as `UNKNOWN_NOT_SAFE`.
- OpenZeppelin Governor could not pass the older, too-restrictive Solidity
  pragma grammar in an imported dependency; likewise retained UNKNOWN.
- **0/2 compiled; 0 vulnerabilities identified.** Test succeeded as
  an accounting/provenance protocol, not a detector performance gate.

## 3. D2.4N fresh-source repair and genuinely frozen test

New version-range parser supports bounded `^`, `>=`, `<`, `>`, `<=`, `=` and
OR clauses across real semver versions, always from source pragmas, with
negative tests for malformed grammars and conflicts. Target *existence*
was checked using GitHub path-directory **metadata only**, without
inspecting source contents. The new semver policy was published before
selecting the cohort, and the exact target manifest was then separately
published at commit `b3bf813e797d54b0638ff83d98e5d13d54353777`.

- [First published prospective run 40328618617](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40328618617).
- [Diagnostic repeat 40328877710](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40328877710)
  with **unchanged inference engine, compiler-selection policy and targets**;
  only the reporting detail of method names and unsupported pragmas changed.

| New, source-uninspected target file | Compilation | Candidate hypotheses on chosen target | Failure context |
| --- | --- | ---: | --- |
| Compound `CometRewards.sol` | UNKNOWN, not compiled | 0 | Original target and dependency files specify **exact `pragma solidity 0.8.15`**, outside the precommitted binary set `{0.8.24, 0.8.33}`. |
| OpenZeppelin `GovernorTimelockControl.sol` | **Compiled using 0.8.33 + Osaka** | **3 unverified** | 181 partially unsupported functions in source closure; no native target oracle. |

The 3 predeclared-engine candidate method sites are:

1. `GovernorTimelockControl._queueOperations(...)`
2. `GovernorTimelockControl._executeOperations(...)`
3. `GovernorTimelockControl._cancel(...)`

The count is **3 source-derived verification hypotheses**, not 3 flaws.
There is no independent native/EVM exploitation or value-conservation
test for the Governor target, so no vulnerability, severity or novelty
verdict is admissible.

### After-test source inspection: limitations, not posthoc score tuning

Original third-party source:
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/11565e5f6277a320408025e649240056ba6a3919/contracts/governance/extensions/GovernorTimelockControl.sol

- `_queueOperations` contains external **read-only** timelock queries prior
  to some state updates. The current heuristic treats external views and
  mutable external interactions too similarly. A view call followed by
  a write is not itself evidence of exploitable reentrancy.
- `_executeOperations` executes a timelocked action before local cleanup.
  Whether adversarial callbacks can produce a prohibited state depends on
  the real timelock, Governor state machine and role authorization. **UNKNOWN**.
- `_cancel` is explicitly documented in the original OpenZeppelin code as
  being reentry-sensitive under a trust assumption about the
  `TimelockController`. This is an **already-known design assumption**,
  emphatically not an unprecedented vulnerability class uncovered by PRISM.

This exposes the precise next blocker: typed *external effect semantics*
(`view`/`pure`/`STATICCALL`, trusted target, reentrant callback graph,
role restrictions, invariant consequences) must be distinguished before
any independent verification verdict can be credible.

## 4. Verification, cost, and scientific limits

- Whole local Python regression suite: **404 tests**, all normal cases
  pass and one pre-existing explicitly expected failure.
- No model, paid API or GPU calls. GitHub-hosted CPU runners, no real
  blockchain RPC, live contract attack or real funds.
- Unit and native laboratory outcomes are not a wall-clock- or
  CPU-normalized superiority claim over Slither/Medusa/Echidna.
- The D2.4N cohort was **not** processed by classical matched baselines,
  and it was **not** subjected to independent live-state or local-native
  target-specific semantic oracles. Candidate recall and false positives
  against true vulnerability labels are therefore not established.
- A missing or zero-candidate target always remains **UNKNOWN**, never safe.

## 5. The next minimum-sufficient hardening gate

1. Add a **version-pinned 0.8.15** compiler where required by exact pragmas,
   retaining checksum verification; replays on the already seen Compound
   target are strictly retrospective. No after-the-fact blind success.
2. Distinguish compiler-typed `view` / `pure` / static operations and
   external mutating calls. Build minimal interprocedural effect summaries
   and role/state-machine obligations; use path-sensitive, bounded analysis.
3. Independently execute selected public-target hypotheses against a
   pinned native EVM harness with explicit authorization and attacker
   assumptions, counterfactuals, state deltas and artifact hashes.
   Every claim remains UNKNOWN if preconditions are unresolved.
4. Preregister a **different** corpus only once this verifier is frozen,
   and compare matched classical analyzers, real target-specific recall,
   false positives and CPU/memory cost.

**Bottom line:** Compiled code coverage and known-class laboratory
verification substantially improved, and one truly frozen target yielded
three source-specific hypotheses. The central scientific goal —
**independently verified unknown security flaws or zero-days at lower cost**
— remains *unproven*.
