# PRISM / SCM — D2.4C, external OUSD multi-transaction test, 23 October 2026

**Technical gate: PASS. Mutation-sensitivity gate: PASS on one synthetic defect. Discovery-superiority gate: NO-GO.**

## Immutable execution evidence

- Successful final scientific execution, [GitHub Actions 39988468931](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39988468931), code commit `677b7dd4cbf882006782d4a0fe39bb9f774a7006`. Failed previous iterations were retained in GitHub history, not erased.
- Experimental PR: [#29](https://github.com/nkinzogomer-eng/PRISM/pull/29), isolated draft branch `research/defi-d24c-accounting-stateful`, based on D2.4B, not merged into main.
- External real-world source: `scfuzzbench/origin-dollar-scfuzzbench`, exact revision `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`. Source file `contracts/contracts/token/OUSD.sol` is unchanged for the clean experiment. ABI is actually compiled with pinned Foundry v1.3.6.
- Raw JSON, stderr, source/ABI SHA-256, CPU/wall and mutation-control evidence: GitHub Actions artifact `d24c-real-ousd-multistep-results`, archived with the above CI run.
- **11/11 local Python/adversarial tests passed.** Clean EVM tests: six successful Foundry process executions (2 generated, 2 independently authored matched, 2 deeper stateful). All tested properties returned Success.
- The source-independent generator activates precisely two frozen, ordinary ERC20 property families: `ALLOWANCE_SPEND_CONSERVATION` and `TRANSFER_ROUNDTRIP_SUPPLY`. It does not read historical issues, and it does not automatically infer full token economic semantics.

## Clean actual external EVM results (seconds, excluding full setup/network/human design)

| Comparator | Two repeat wall times | Outcome |
|---|---:|---|
| ABI-generated 2-to-3 transaction tests | 3.4486; 0.6136 | Both methods pass in each repetition |
| Independently written matched-input Foundry tests | 1.9865; 0.6094 | Both methods pass in each repetition |
| Independent deeper Foundry stateful 128 x 48 campaigns | 2.0631; 2.0601 | Invariant passes in both repetitions, no-vacuity hook enforces both action families exercised |

Both matched-input fuzz campaigns use 128 seeds per property, and the stateful handler uses 128 campaigns with a depth of 48. This is **not** an equivalent full CPU, seed-aligned or human authoring budget, and the stateful campaign is not a speed comparator. Observed times do not support a speed advantage for the generated variant. No observed violations of these narrow properties; this does NOT prove OUSD is safe.

## Synthetic positive control, strictly isolated from real-source results

After clean external EVM tests, on a **temporary local copy only**, exactly one line of OUSD was intentionally changed from `allowances[_from][msg.sender] = userAllowance - _value;` to `allowances[_from][msg.sender] = userAllowance;`. This simulates an ERC20 allowance debit omission. The original source was restored byte-for-byte in a finally block, and both hashes are recorded.

All three frozen references detected the deliberately introduced regression:

1. Generated multi-transaction: `D24C_FIRST_DEBIT` — detected.
2. Independently authored matched Foundry: `D24C_REF_FIRST` — detected.
3. Independent Foundry stateful: `D24C_STATEFUL_DEBIT1` — detected.

**3/3 synthetic controls detect a known artificial fault**. These are not three different vulnerabilities, not a discovered third-party bug, and not evidence of PRISM beating the baselines. The first attempt at this control found a Foundry error-reporting issue (an `assertEq` failure gave an empty JSON reason); the reference was instrumented with explicit `require` failure reasons without changing its accounting property. This is disclosed as an instrumentation correction rather than presented as a new scientific capability.

## Scientific interpretation and blocked claims

**Technical result:** external source -> real ABI -> independent source-free candidate selection -> multi-transaction EVM checks -> independent Foundry comparators -> synthetic negative-to-positive mutation sensitivity -> raw reproducible evidence. That chain is now operational.

**Scientific result:** no independently adjudicated real external vulnerability, no historical benchmark root cause reproduced by a novel detector, and no additional true positive over Foundry. The 13 historical SCFuzzBench issues remain **NOT EVALUATED**; reporting TP=0/FN=13 or a recall figure would be invalid. A public source is not a sealed blind holdout. Although called PRISM-generated, the current test templates are conventional, manually authored and do NOT yet exercise a unique SCM search planner. The experiment therefore provides no evidence for an original scientific discovery advantage.

**Next falsifiable gate:** implement a genuinely structural, source-semantics-informed planner for DeFi roles and sequences (rebasing credits, vault shares, oracle/interest transitions); freeze algorithm/property and resource budget ahead of a held-out set of third-party root causes; compare under equal actionable EVM transitions and CPU with equally informed conventional Foundry stateful and an independent symbolic tool; independently adjudicate distinct real vulnerabilities, report TP/FP/FN/UNKNOWN with uncertainty bounds, and preserve any negative results. Do not merge this branch into main until these criteria are achieved or the risk is explicitly accepted.
