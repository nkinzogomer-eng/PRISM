# PRISM / SCM — D2.4C preregistered real-OUSD economic state-sequence gate

**23 October 2026. Scientific status: experiment in progress, NO superiority claim.**

## Question

Can a source-ABI-triggered, manually specified multi-step economic property
generator execute two nontrivial accounting checks against unchanged, pinned
third-party OUSD Solidity and agree with an independently authored Foundry
reference, without receiving SCFuzzBench bug labels? This question is **not**
whether PRISM finds previously unknown vulnerabilities better than fuzzers.

## Immutable provenance

- External source: `https://github.com/scfuzzbench/origin-dollar-scfuzzbench`
- Exact revision: `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`
- Actual `OUSD` compiled ABI via Foundry 1.3.6, no synthetic ABI in external EVM run
- Target contract unchanged. `D24BAdapter` only exposes the original token deployed
  through upstream `CryticTester`, and is not a model of OUSD.
- Code and test harness reside on a public issue-bearing benchmark. **Not blind.**
- Candidate logic reads only ABI signatures, not `known_bugs.json`,
  upstream vulnerability property names, exploit traces, or canaries.

## Predeclared hypotheses (source input alone never proves behavior)

1. `NONREBASING_HOLDER_ISOLATION`: fund rebasing counterparty, opt out one
   holder, rebase global supply through authorized vault, verify that the
   excluded holder's balance is unchanged, while the sole rebasing
   counterparty receives its pro-rata share of the gain, measured against
   `supplyBefore - nonRebasingSupply`, within 1e9 wei rounding tolerance;
   opt back in and verify accounting continuity. All operations must complete successfully. Fixed initial
   mint: 1000 OUSD; transfer: 400 OUSD; yield increment 1–101 OUSD.
2. `SPENDER_ALLOWANCE_DEBIT`: holder mints, approves a spender, spender uses
   `transferFrom`, and the remaining allowance must equal approved
   minus transferred. Amount in [1,100] OUSD.

These are conventional hand-designed metamorphic hypotheses *triggered by*
available ABI signatures, not learned from source semantic analysis. A missing
ABI method yields UNKNOWN; incompatible test environment yields ERROR. A
revert or unrelated Foundry failure is not counted as a security finding.

## Matched technical controls

Generated Foundry `testFuzz` vs independent test contract: same upstream
deployment, same hypothesis, same amount mapping, 256 fuzz runs per test,
two process repetitions with fixed corresponding fuzz seeds. Full JSON/stderr,
resource use, ABI and generated-file fingerprints are archived. A valid
property counterexample is UNADJUDICATED until independently reproduced and
shown not to be a false hypothesis. State is intentionally multi-transaction
for both checks.

Equal fuzz run settings **do not establish equal search ability**, matching
EVM calldata, total cost, or competitive detection efficacy. Both use
Foundry execution. This test does not yet include full stateful/Echidna/
Medusa/Halmos discovery baselines; these remain mandatory for any superiority
claim. Writing templates and comparator consumed unmeasured human work.

## Critical falsification and advancement gates

- Passing the test means external multi-step compatibility, *not* absence of bugs.
- No root-cause-specific SCFuzzBench known bug is eligible for TP/FP/FN here,
  hence recall/precision remain **NOT EVALUATED**, not zero or 100%.
- If generated and reference checks disagree, investigate ABI, trace, prestate,
  revert and Solidity rounding before treating any result as novel.
- Disallow a zero-success or all-reverted handler from creating a valid
  evidence certificate in subsequent stateful experiments.
- **Next discovery sub-gate:** freeze a task/instance manifest and property
  derivation mechanism *before* a new, developer-unseen, externally
  adjudicated sample; run blind property generation, EVM replay and
  strong matched-budget Foundry stateful plus symbolic or Echidna reference.
  Compare per-distinct-root-cause confirmed findings, human design cost,
  counterexample validity, paired per-instance CPU and observed search cost.
  Use confidence intervals and negative findings; no template retuning on
  evaluation data.
- **SCM-specific ablation:** compare the exact same hypothesis set, oracle,
  executor and action budget with (i) structural dependency/decision frontier,
  (ii) independent conventional dependency-aware greedy, (iii) static/FIFO,
  (iv) randomized search. If no robust advantage over (ii), no novel
  structural computation advantage is supported.

**Promotion:** Keep research branch and PR draft; keep `main` untouched
until replication and honest evidence review.


## Post-observation experimental extension (not part of the frozen clean holdout)

After evaluating the initial two checks, an independent native Foundry
stateful handler was added. It executes rebases, allowance-dependent spending
and reciprocal transfers in a single persistent EVM state, with 128 invariant
runs of depth 48 and two repetitions. A separate mandatory state-changing
fuzz control requires both a successful rebase and a successful delegated
spending action; this protects the instrumentation check from an entirely
vacuous pass. It does **not** establish non-vacuous coverage of every
individual invariant trajectory. Synthetic-mutant sensitivity of the stateful
comparator is evaluated as an instrument check, not an unseen vulnerability
benchmark. Runtime and search budgets remain unmatched to the generated
one-shot tests, so there is still **no fair detection-superiority claim**.

The preceding failed sole-yield-recipient property remains permanently
recorded as a model misspecification. No existing target behavior should
be called a newly discovered vulnerability because a hypothesis was revised
after observing its response.
