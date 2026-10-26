# PRISM D2.4P — First bounded autonomous ETH-liability search, native EVM

**Date:** 2026-10-26. **Branch:**
`research/scm-cyber-d24p-autonomous-native-lab`.

## What was actually tested

A CPU-only ABI-guided engine (`prism/d24p_probe.py`) constructs a bounded
series of 18 candidate transaction traces from the public ABI of an ETH vault:
honest deposit, attacker deposit, attacker withdrawal with zero/one/two
callback retries, and independent on-chain ETH/liability observations. It
varies honest liquidity and attacker seed capital. Native replay deploys a
**fresh Solidity contract for every trial**. An economic witness requires
both attacker gain **above deposited seed capital** and an uncovered honest
depositor claim. The engine does not receive per-instance ground-truth labels.

The limited interaction grammar works only for `deposit()` payable,
`withdraw()` without arguments and a `balances(address)` observation. All
unsupported ABIs or tests remain **UNKNOWN**, never safe.

### First external CI failure mattered

- [Initial run 40341284120](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40341284120)
  executed 18 Solidity variants, finding 3 positive economic witnesses but
  was scored with 3 apparent false negatives. Investigation revealed that
  **the benchmark labels were wrong**: the test author incorrectly assumed
  that a post-transfer checked `balances[msg.sender] -= amount` enabled
  successful recursive ETH extraction. On modern Solidity 0.8, the nested
  withdrawal reduces the balance first, so the enclosing checked subtraction
  underflows and **reverts the entire transaction**.
- The fix corrected the ground truth, **not the planner's findings**. A new,
  distinct `unchecked { balances[msg.sender] -= amount; }` variant was added
  to establish the missing genuine economic-positive control. The checked
  case is retained as a difficult negative control, along with before-call
  accounting and reentrancy-lock controls.
- [21-case corrected native run 40341604479](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40341604479):
  6/6 true positives, 15/15 true negatives, no false results.

## Hardened independent-seed evaluation

**[Successful final CI run 40341982493](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40341982493)**;
GitHub artifact `d24p-seeded-lab-native-witness-and-controls` stores Solidity
sources, random seeds, manifests, EVM log and JSON verdicts.

| Quantity | Observed |
| --- | ---: |
| Distinct pseudorandom cohort seeds | 3 |
| Generated Solidity contract instances | 63 (21 per round) |
| Distinct intentionally authored semantic templates | **7, not 63** |
| Proposed trace trials per contract | 18 |
| Native fresh-deployment trials | 1,134 |
| EVM economic-positive observations | 18 |
| EVM economic-negative observations | 45 |
| False positives / false negatives on benchmark labels | **0 / 0** |
| New public real-world vulnerabilities | **0** |
| New vulnerability families | **0** |
| Independently established zero-days | **0** |

The source filenames and EVM function names do not disclose per-instance
labels; the scoring script opens the sealed labels **only after** collecting
native Solidity observations. Three seeds: `40341982493`, `40342048030`,
`40342113567`. Each group runs all 18 trials for every case, then scores
positive/negative values against independently measured ETH balances.

**[Original D2.4O Euler proof](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40335609330)**
was a real historical account-health consequence, but human-scripted.
D2.4P instead automatically synthesizes and tests economic witnesses, but on
**generated laboratory instances**. These are different achievements; they
must not be conflated to claim fully autonomous real-protocol discovery.

## Interpretation and limits

The D2.4P result **proves a narrow capacity for autonomous discovery of
financially meaningful value violations in a controlled native-EVM domain**.
It does *not* yet prove new classes, unknown historical bugs, live-contract
bug bounty capability, arbitrary ABI/asset handling, or general DeFi reach.

In particular, all seven program templates and the ETH-liability oracle were
authored by the investigators. Although instance order and seed were held
back from the probe, this is **not an independently designed and unknown
third-party holdout**. Apparent 100% performance is *only* on these seven
templates; it must not be extrapolated to other protocols. A call/fallback
probe cannot infer protocol-specific permissions, token semantics, flash-loan
repayment requirements, oracle transitions or liquidation dependencies.

No matched Slither, Echidna, Medusa or alternative-fuzzer performance was
measured. GitHub CPU-only Foundry execution succeeded without paid AI or GPU;
these data support feasibility on hosted ordinary CPUs, **not** scientifically
established lower cost or speedup versus other engines.

## Next falsification gate before any broader claim

1. Freeze the source-based hypothesis generator, action grammar and verifier
   *before* an independently curated, uninspected corpus of real historical
   third-party DeFi programs. Prevent training-on-test contamination.
2. Add adapters for actual ERC20/share/debt, multi-actor and temporally
   dependent interactions, with a separation between candidate generation,
   witness search and native-EVM financial adjudication.
3. Demand at least one real historical finding with an **automatically
   synthesized** complete native EVM witness and properly matched patched
   control. Otherwise report failure/UNKNOWN openly.
4. Run matched independent baselines and record full CPU wall-time, peak RAM,
   code coverage, verified recall, false discoveries and human adapter effort.

**Verdict: D2.4P bounded laboratory-autonomy gate PASSED. Real public-source
autonomous discovery and any zero-day gate remain OPEN / UNPROVEN.**
