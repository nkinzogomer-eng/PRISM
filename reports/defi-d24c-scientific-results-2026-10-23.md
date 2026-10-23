# PRISM / SCM — D2.4C experimental result (23 October 2026)

**Verdict: technical PASS, mutation-sensitivity PASS, discovery superiority NO-GO.**

## Reproducible evidence

- **Final successful actual-EVM / sandbox-mutation CI:** https://github.com/nkinzogomer-eng/PRISM/actions/runs/39986379929
- **Target:** independently authored `scfuzzbench/origin-dollar-scfuzzbench`, pinned `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`, compiled OUSD ABI with Foundry v1.3.6.
- **Branch:** `research/defi-d24c-economic-stateful`, draft PR #28 based on D2.4B PR #27. Not merged into `main`.
- **Code-level tests:** 19 D2.4C adversarial/unit + 15 D2.4B regression tests passed.
- Full `forge --json` stdout/stderr, proposal provenance, CPU/wall times and synthetic-control attestations archived in the CI artifact. Independent Foundry reference never reads detector property outputs.

## Clean third-party target (never mutated in this phase)

Two manually specified, ABI-triggered multi-transaction economic predicates:

1. Nonrebasing holder balance isolation plus *pro rata* allocation of an externally authorized global rebasing increase, accounting for public `nonRebasingSupply()`.
2. Exact allowance decrement after successful `approve -> transferFrom`.

Both generated Foundry properties and the independently authored matched Foundry tests passed **two 256-run fuzz campaigns per property**. Clean outcomes: generated 4/4 successful tests, reference 4/4 successful tests; zero observed counterexamples on these narrow paths.

Clean EVM wall-time observations (s, cold/warm): generated 2.76555 / 0.49471, reference 1.31464 / 0.50068. These figures do **not** support a speed advantage, especially without identical calldata, setup/human design, and total end-to-end budget equivalence.

## Critical self-falsification: invalid initial economic model

A provisional D2.4C yield oracle incorrectly assumed that the local test holder was the *sole* rebasing recipient. The preexisting external Echidna setup in fact seeds other token holders: it mints to an outsider user and an outsider nonrebasing contract before our test mint. The resulting clean-contract `D24C_REBASING_YIELD_DRIFT` counterexample was independently reproduced by the Foundry reference (run https://github.com/nkinzogomer-eng/PRISM/actions/runs/39985785381). It was a **misspecified property / false alarm**, NOT an OUSD vulnerability.

The generator and independently authored comparator were amended to use the **public** rebasing-eligible denominator `totalSupply - nonRebasingSupply` and fixed predeclared rounding tolerance of 1e9 wei. The corrected control passed on unmodified upstream OUSD (run https://github.com/nkinzogomer-eng/PRISM/actions/runs/39986137824). **Important:** this is post-observation development. OUSD can no longer be considered an unseen holdout for that rule.

## Explicitly synthetic positive mutation controls (NOT security discoveries)

On **isolated temporary working-tree copies only**, the experiment inserted two intentionally wrong lines in real OUSD Solidity:

| Local test control | Generated property | Independent Foundry | Untargeted property |
|---|---|---|---|
| Do not decrement allowance in `transferFrom` | Failure as expected ×2 | Failure as expected ×2 | Passed |
| Calculate rebasing share without subtracting excluded supply | Failure as expected ×2 | Failure as expected ×2 | Passed |

Both methods detected **2/2 manually injected, known synthetic defects**. These are **sensitivity/positive-control results**, not false negative rates on genuine third-party security bugs. The source was restored **byte-for-byte** after each mutant and a `git diff --exit-code` guard passed. No chain fork, no on-chain calls, no real funds, no attacker exploit.

## What has and has not been established

**Established:** reproducible economic multi-step checks on genuine external Solidity; independent matched property tests; explicit false-positive recognition; controlled proof that both checkers reject two defective local variants; fail-closed provenance/ABI checks and raw evidence.

**Not established:** any newly found externally validated root cause, comparative real-vulnerability recall or precision, a blind holdout, a general automatic derivation of financial invariants from implementation semantics, a competitive stateful/symbolic fuzzer comparison, or an SCM-specific structural-planning ablation. **Historical 13 documented SCFuzzBench issues were not evaluated.** Do not report a `0/13` recall, `2/2` discovered real bugs or a broad superiority percentage.

## D2.4C next scientific gate

Keep this experiment as the *development and instrument-validation set*. Freeze the candidate generator before opening independent evaluation examples. Use a separate externally adjudicated, initially unseen protocol family with multiple distinct root causes. Run PRISM, Foundry stateful and a symbolic/other strong baseline under matched budgets and independent confirmations; add SCM planner ablation against dependency-aware greedy, FIFO and randomized ordering. Publish all counterexamples, false positives, misses, cold-start costs, and paired uncertainty estimates; only then test whether any advantage survives. Until then: **NO-GO for scientific discovery superiority and remain a draft.**
