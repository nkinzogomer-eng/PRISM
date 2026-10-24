# D2.4C — External DeFi multistep accounting gate, frozen before CI

**Research protocol (23 October 2026). No claim of vulnerability discovery or scientific superiority.**

## Decision and prior falsification

D2.4A compiled real Origin Dollar; D2.4B generated two ordinary one-operation ERC20 checks. Neither searched for the 13 historical SCFuzzBench issues, and neither justified a detection-performance advantage. D2.4C adds a falsifiable *multistep* compatibility gate and independent comparators. It intentionally does **not** relabel successful accounting checks as detected bugs.

## Frozen target and eligibility

- Independent benchmark repository: scfuzzbench/origin-dollar-scfuzzbench at exact `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`.
- No mainnet requests or live assets. Compile the real OUSD ABI with Foundry v1.3.6.
- The generator receives only compiled ABI signatures; it cannot read the upstream issue catalog, historical bug labels, original Echidna property names, or test outcomes.
- **No sealed blind holdout.** This source is public. Both properties are manually authored conventional ERC20 semantics, not discovered novel invariants.
- The only properties eligible for this gate are **ALLOWANCE_SPEND_CONSERVATION** (approve, transferFrom, transferFrom, allowance after each, totalSupply) and **TRANSFER_ROUNDTRIP_SUPPLY** (transfer, return, supply checks). Missing ABI capabilities yield **UNKNOWN**, never SAFE.
- Rebased balance conservation, rounding equivalence and economic-value preservation **are not claimed**. Round-trip checks hold total supply constant without intermediate mint, burn or rebase and do not demand exact user balance equality.

## Controlled EVM comparisons

1. **Generated:** two ABI-activated 2–3 transaction Solidity fuzz methods, 128 fuzz cases per property.
2. **Independent matched reference:** manually written Foundry fuzz methods exercising the **same two properties**, with 128 fuzz cases per property and the same bounded input domains. Same input distribution by specification; not identical seeds or identical execution time. Demonstrates independent oracle cross-check, **not planner superiority**.
3. **Independent stateful:** two behavioral actions in a manually written stateful Foundry handler, 128 campaigns with depth 48, supply invariant and `afterInvariant` checks that the two action families were actually exercised. A stateful campaign has a different trace budget; it is a stronger scope check but **not a cost-matched competitive comparator**.

Repeat each group twice. Archive raw Foundry JSON, stderr, SHA-256, wall and CPU time; compilation/network/setup costs are measured separately or declared excluded. Unrelated runtime/build failures must abort rather than be scored as counterexamples. A verified test failure is **UNADJUDICATED** until an independent root-cause evaluator checks whether it is a real exploitable violation.

## Gates and falsification

- Technical **PASS** only if exact upstream source resolves, compiled ABI is recorded, generator proposes precisely two candidates, independent test inventories are exact, all six test groups are recorded, and source-independent unit/adversarial checks pass.
- Technical **FAIL** if EVM test fails, a property is inapplicable, or data missing; report the failure, not a vulnerability.
- Scientific **NO-GO for discovery superiority** regardless of technical outcome without a sealed external target or truly prospective labeled benchmark, proof of distinct root cause on real external contract, paired equal-opportunity budget comparisons against stateful/symbolic references, and confidence intervals across distinct independent targets. The 13 documented historical cases are still **NOT EVALUATED**, not TP=0 or FN=13.
- Only the baseline-compatible search on genuinely exploitable financial behavior could establish real-world utility; synthetic/mutant fixtures must be reported separately as sensitivity controls.

## Next research fork, D2.4C-root-cause

Develop semantic role extraction from bytecode/source (rebasing shares, vault share-price invariants, caller authorization and time dependence) without issue labels. Lock a property budget and an *external* target split **before** any CI outcome. Compare SCM's structural action planner with standard stateful fuzz and conventional search using a common oracle and equal EVM transitions/CPU budgets. Independently reproduce counterexamples and score distinct root causes. Do not claim superiority unless a predeclared primary metric and uncertainty bound support it.

## Synthetic falsification / sensitivity control (separate from external truth)

After the clean, independently pinned OUSD run, temporarily mutate exactly one
source line in the same local OUSD checkout, replacing
`allowances[_from][msg.sender] = userAllowance - _value;` with
`allowances[_from][msg.sender] = userAllowance;` (no debit on transferFrom).
Run the already frozen generated, matched-reference and stateful checks again.
Require an explicit accounting-property failure in all three; restore the exact
original source bytes in a `finally` block and record both file hashes.
If any of the three misses this obvious artificial fault, the sensitivity
control is **FAIL**, not an opportunity to rewrite the detection budget.
A successful control is **not a third-party vulnerability discovery** and
proves **no advantage over the independent baseline**.

## D2.4C structural dependency-frontier diagnostic (incremental engineering)

D2.4B/C revealed that the purported "PRISM" test engine was only ordinary
Foundry driven by manually coded templates. The next **falsifiable component**
must run before EVM sampling, on the exact independently pinned OUSD source.
A deliberately bounded lexical Solidity function extractor identifies
source-visible call dependencies from frozen property-relevant entrypoints:
allowance approval/transferFrom and token supply transitions. It reports
numbers of relevant vs all locally defined functions, the exact allowed
roots/symbols, unresolved member calls and a known source mutation witness.

**Primary engineering metric:** retained positive-control source witness and
function-count reduction versus inspecting every locally defined function.
Do **not** treat the reduction ratio as CPU improvement, proof of semantic
completeness, recall of real bugs, or superior vulnerability discovery.
The full source is still needed for sound security claims; inherited source,
overloads, external calls and dynamic behavior remain UNKNOWN. Lexical source
slicing is a conventional technique, not inherently novel.

**Test gate:** paired synthetic distractors (comments/strings/unrelated
functions), nested-body calls, missing roots/symbols, unknown external calls,
and mutation of the witnessed allowance decrement must all be handled without
inventing a SAFE verdict. GitHub Actions archives the measured frontier and
its resource costs alongside the real-source EVM campaign.

**Scientific advancement required after this component:** source-semantic
contract models, independent adversarially chosen real root causes, a verified
difference between search policies under equal allowed observations, honest
ablations against conventional program slicing and strong dynamic search.
