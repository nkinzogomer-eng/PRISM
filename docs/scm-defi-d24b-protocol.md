# D2.4B — Reproductible source-independent ERC20 property verification on external Origin Dollar

**Prerecorded experimental protocol, 22 October 2026. Not a claim of new vulnerability discovery or PRISM superiority.**

## Question and test gate

Does a bounded, ordinary generic ABI property compiler produce executable, reproducible local EVM checks against a **real independent protocol**, and how do the observed results compare with an independently authored native stateful Foundry reference under the **same property specification**?

### Independent source, frozen before results

The upstream Origin Dollar SCFuzzBench repository is checked out read-only from `https://github.com/scfuzzbench/origin-dollar-scfuzzbench` at exact commit `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`; Foundry v1.3.6 and actual Solidity ABI compiled with `forge inspect OUSD abi --json`, *not* an ABI artificially created by PRISM. No RPC, mainnet fork, live protocol call, or live assets. The upstream Echidna suite has an existing constructor/deployment environment; a local-only adapter `D24BAdapter is CryticTester` exposes the token address without rewriting protocol code.

No actual historical known-bug labels are supplied to the detector: it reads only compiled ABI signatures. **Important caveat:** the upstream repository is public and contains issue-labeled tests, so this is still **not a blind holdout**. The adapter and fuzzer reference run in an environment that includes publicly known property tests; this is not an external novel-bug benchmark.

### Frozen properties (generic to a large class of tokens)

1. `TRANSFER_SUPPLY_PRESERVED`: if a token implements `totalSupply()`, `balanceOf(address)`, and `transfer(address,uint256)`, a **successful transfer with no intermediate mint/burn/rebase** should not change the reported total supply. The generator mints a starting balance in setup, records supply after the mint and checks the transfer result. It does not assume accounting identity under rebase or across all addresses.
2. `APPROVE_ALLOWANCE_OVERWRITE`: if a token implements `approve(address,uint256)` and `allowance(address,address)`, a successful approve should record the requested allowance. This is conventional ERC20 behavior; unusual token-specific allowance policies may require different specifications.

Both templates are specified before observing CI outcomes, and **are manually coded conventional invariants**, not a discovery of new mathematics or a semantic inference from contract bytecode. Missing or incompatible ABI signatures produce `UNKNOWN`. An identical ABI can mask different behaviors. We also do not use the upstream property names or root-cause labels as a source of candidate properties.

### Real EVM execution and independent baseline

- **Generated PRISM candidate checks:** two `testFuzz` methods built from actual ABI candidates, 256 one-transaction fuzz runs per case. They run against actual third-party token deployed through upstream CryticTester initial state.
- **Native Foundry stateful reference:** independently handwritten handler with `move(uint96,bool)` and `allow(uint96)` selectors operating on the same deployed upstream OUSD; it repeatedly mutates real EVM state with 128 fuzz campaigns, depth 48. It checks the same supply preservation and approval semantics. **Two process repeats** for each method, raw forge JSON retained, resource usage logged.
- On property failure, count a **candidate counterexample** requiring root-cause adjudication, not automatically a security vulnerability. EVM runtime crashes, missing functions, compilation errors, mismatched SHA or exit-status inconsistencies **fail closed**, not counted as findings.
- No direct comparison of wall times or recall is valid yet: separate fuzz methods and stateful handler have differing trace lengths, initial compile costs, custom setup differences, and unequal property search behavior. This first external test is a reproducibility and compatibility milestone, not a budget-matched competitive victory.

### Scientific criteria and next gate

- **Technical PASS:** pinned source compiles, ABI yields inspectable relevant hypotheses, independent external EVM executes at least two completed repetitions per comparator with explicit test inventories, raw traces and costs archived. Failing a property with a verified predicate is recorded without asserting exploitability.
- **Scientific NO-GO:** no extra confirmed distinct historical security vulnerabilities compared to Foundry; no blind withheld labels, no verified root cause, no equal-computation/quality comparison. A 100% success rate on generic safe properties is not a vulnerability recall metric.
- **D2.4C gate:** hold the property derivation algorithm and targets fixed, then add upstream-root-cause-specific behavioral verification (independent adjudicator), unbiased action-distribution sampling, strong real contract stateful/symbolic tools and cost-matched ablation of SCM's planner. Any true discovery claim requires an independent verified root cause not already produced by the baseline, ideally on a non-training external holdout.

## Reproduce

```sh
python -m unittest discover -s tests -p 'test_d24b_*.py' -v
# On a pinned upstream checkout (same SHA as above), after submodule fetch:
forge inspect OUSD abi --json > /tmp/d24b-ousd-abi.json
python -m scripts.d24b_erc20_properties --abi /tmp/d24b-ousd-abi.json --root external/origin-dollar --output reports/d24b-local
cp benchmarks/defi/d24b/D24BReference.t.sol external/origin-dollar/test/recon/D24BReference.t.sol
python -m scripts.d24b_external_evm --root external/origin-dollar --abi /tmp/d24b-ousd-abi.json --properties reports/d24b-local/proposals.json --output reports/d24b-local
```

This document reports **protocol and limitations only**. Results should be added solely after actually inspecting the CI execution and raw output.
