# PRISM — D2.4C source-structural frontier diagnostic (24 October 2026)

## Status: ENGINEERING PASS; ORIGINAL SCIENTIFIC SUPERIORITY NOT DEMONSTRATED

**Direct, reproducible evidence:** [GitHub Actions run 40087105210](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40087105210); tested code commit `a8b15d1b7dc40efdf1054412d3df9a4a20cdf62a`. The full source/ABI/CPU measurements, experiment stdout/stderr and source-frontier JSON are archived in the action's `d24c-real-ousd-multistep-results` artifact.

The previous validated D2.4C run used ordinary fixed ERC20 property templates and Foundry, with no SCM source analysis or genuine new external root-cause discovery. This is an explicitly limited attempt to close **one component gap** while continuing the same independent-EVM regression campaign.

## Pinned third-party target and guardrails

- `scfuzzbench/origin-dollar-scfuzzbench` at `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`.
- Read-only analysis of `contracts/contracts/token/OUSD.sol` from the exact checkout, no mainnet RPC or live asset interaction.
- Two preregistered **researcher-specified** property root/symbol sets: allowance debit (`transferFrom`, `approve`, `allowance`; storage `allowances`), and supply transitions (`transfer`, `transferFrom`, `mint`, `burn`, `changeSupply`; supply/credit symbols).
- A small lexical extractor masks comments/strings, extracts local function bodies, builds a conservative, source-visible direct-call graph, and retains reachable functions. Unresolved member calls, inherited functions, aliases, assembly and nonlinear control flow are **not proven safe**. This is neither a Solidity AST nor sound program slicing.
- An independently known allowance-debit statement serves as a positive control that must remain within the selected allowance frontier. It is NOT a discovered third-party vulnerability or an unseen label.

## Measured run

| Goal | Source-visible local functions | Frontier functions | Excluded by first-stage frontier | Valid scope |
|---|---:|---:|---:|---|
| Allowance accounting | 32 | 11 | 21 (65.625%) | Local function *count*, not audited lines or EVM actions |
| Supply transitions | 32 | 13 | 19 (59.375%) | Local function *count*, not safety proof |

Known allowance mutation witness retained: **True**. Source traversal flagged unresolved member-call semantics; missing or malformed inputs are treated as UNKNOWN/error, not SAFE.

**Regression checks retained:** 18 Python unit/adversarial tests passed; both generated tests succeeded twice on real clean OUSD; both independent matched Foundry tests succeeded twice; native stateful Foundry invariant succeeded twice; the deliberately injected missing-allowance-debit mutation was detected separately by generated, matched, and stateful approaches (3/3), then the original source was restored byte-for-byte.

## What the result DOES and DOES NOT demonstrate

**Does:** demonstrate the engineering ability to narrow an explicitly chosen source-visible function frontier while still retaining one pre-known witness, run adversarial parsing/dependency guards, and rerun the original independent EVM positive-control suite in CI after the change.

**Does not:** demonstrate more vulnerabilities, any new zero-day, a source-to-EVM soundness theorem, a positive recall over the 13 untested historical root causes, lower total CPU or human effort, a faster EVM verifier, or better discovery than a competent conventional slicer/stateful fuzzer. The function reduction is measured against naive whole-file inspection only; this is **not a strong competitive baseline**. Both Foundry-based conventional and generated test paths detected the same deliberate mutation.

The manual goal specification can embed researcher knowledge. This prototype is also file-local and does not resolve effects from imported/inherited Solidity or external system contracts. An end-to-end speed claim or economic-security certification on the reduced code would be incorrect.

## Diagnosed blockers, ordered by scientific causality

1. **Property derivation:** ABI templates do not infer complex economic invariants from external code. The property grammar and its assumptions are still human-authored.
2. **Semantic completeness:** lexical call frontiers do not model storage aliasing, inheritance, cross-contract effects, rebase/share accounting or dynamic dispatch.
3. **Search contribution:** even with a usable property frontier, a genuine SCM search policy has not been pitted against matched best-first, coverage-guided and stateful/symbolic baselines on this real target.
4. **Oracle/validation:** one synthetic mutation is useful for falsification only. No new independently adjudicated real security root cause has been detected by SCM.
5. **Experiment design:** holdout labels public, lack of matched CPU/EVM budgets, and only one external token in this phase preclude generalization or scientific supremacy.

## Higher-cadence experimental protocol

For every single measurable component change, run in the same CI:

1. **Structural measurement** and adversarial negative controls (fail closed, report UNKNOWN).
2. **Positive and safe controls** on immutable real external source, plus temporary synthetic mutants *reported separately*.
3. **Paired baselines** with identical objectives and explicitly accounted EVM transitions/CPU/human-property design.
4. **Automatic ablation and decision gate:** record whether the component improves verified discovery or complete cost. Keep negative results, report regressions, and never automatically promote a proof-of-concept into a superiority claim.

Next actual scientific step is a source-semantic, cross-contract accounting model that yields a falsifiable *previously unspecified* financial hypothesis, followed by independent EVM root-cause verification and a predeclared comparison on withheld third-party protocols. If this fails, the result is an investigated blocker, not a reason to alter scoring definitions after seeing outcomes.

**Release gate: NO-GO for merging D2.4C research branch into main or making scientific superiority claims.**
