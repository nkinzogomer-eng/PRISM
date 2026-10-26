# PRISM D2.4Q — First preregistered third-party ERC4626 economic EVM witnesses

Date: 2026-10-26. Experiment branch:
`research/scm-cyber-d24q-unseen-solmate-native`.

**Verdict: real-source economic-redistribution witness POSITIVE, new real
vulnerability claim NOT established, new class 0, zero-day 0.**

## Preregistration and independence

Source and candidate grammar were frozen *before inspecting* the chosen
third-party implementation: `benchmarks/defi/d24q/preregistration.json`,
`prism/d24q_asset_share_probe.py`, and `tests/test_d24q_asset_share_probe.py`.
The target was selected using public commit and path *metadata only*, not
source contents.

- Repository: `transmissions11/solmate`.
- Full pinned revision: `89365b880c4f3c786bdd453d4b8e8fe410344a69`.
- Source: `src/tokens/ERC4626.sol`.
- Official Git blob: `0a34ac9855a4ea371319c882e392428432a27ab2`.
- SHA-256 measured on source: `f7febaa5999e4b4255e5c4fb3f898428fe74a7b153110064f44d973e85479276`.
- Frozen enumeration: 27 candidate sequences, 3 possible initial attacker
  seed quantities, 3 unmatched underlying donations, 3 subsequent victim
  deposits.

The threat grammar was authored with knowledge of the *existing public
ERC4626 asset/share inflation attack class*. Only the exact third-party
source was previously uninspected: **this is not a new security class**.

## Independent native EVM proof

**[Green run 40345956053](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40345956053)**.
GitHub artifact `d24q-thirdparty-native-erc4626-evidence` records the pinned
source attestation, actual EVM stdout, JSON candidate plan, and result.

The original third-party abstract ERC4626 library was compiled **without
modifying its source**. The minimum required concrete derived vault used
`totalAssets() == underlying.balanceOf(vault)` and an ordinary mock ERC20;
there was no live chain, governance integration, oracle, or external liquidity.

The program generated real native EVM transactions: attacker seed deposit,
direct underlying transfer to the vault without shares, independent victim
deposit, attacker share redemption, and comparisons of token holdings and
victim's redeemable assets. A **separate no-donation counterfactual** had to
give the victim their full deposited underlying value.

| Observable | D2.4Q first source-blind result |
| --- | ---: |
| Pinned third-party source compilations | 1 success |
| Native economic trial sequences | 27 |
| Native sequences with attacker net underlying gain and victim redeem loss | **8** |
| Trial indices | 5, 9, 13, 14, 17, 22, 23, 26 |
| Native Solidity test suites | 1 pass |
| Python D2.4Q adversarial tests | 5 pass |
| Independently confirmed new public-protocol vulnerabilities | **0** |
| Confirmed previously unknown classes / zero-days | **0 / 0** |

All 19 other trials are **NO_WITNESS_IN_BOUNDED_TRIALS**, not confirmed safe.
Some returned no shares and reverted as required by the real source's
`ZERO_SHARES` prevention. The other valid deposit paths can still transfer
rounding value to earlier shareholders after donation.

### Quantitative *model* explanation, not an additional EVM measurement

The identified trial index 17 corresponds to:
attacker seed 2 minimal token units; direct donation 1,000; victim deposit
1,000. Applying the source's documented floor-division share conversion
to these input quantities yields 1 new victim share, a model-predicted
attacker recovery of 1,334 total units after spending 1,002, and thus
a gain of 332 units against a 332-unit victim loss (33.2% of victim input).
The **EVM independently established the sign of both losses** and the
counterfactual; its run did not independently log these exact numerical
amounts. They are explanatory model calculations, not a separate proof.

## Why this is not yet a protocol bug or a cheap zero-day

1. The original ERC4626 contract is an **abstract vault library** requiring
   an application-specific `totalAssets()` implementation. The test makes a
   minimal reasonable choice; it does **not** prove that every downstream
   protocol with Solmate has this exposure or can be exploited in deployment.
2. The phenomenon is a **known share-price manipulation / rounding risk**.
   See the primary-source OpenZeppelin ERC4626 security documentation:
   https://docs.openzeppelin.com/contracts/4.x/erc4626 . Existing protections
   may include initial liquidity, min-share acceptance, and virtual offsets.
3. The experiment uses **raw minimal token units** and synthetic token supply;
   transaction gas, MEV competition, exchange pricing, slippage limits,
   liquidation feasibility, and profit after fees were not measured. A
   positive raw-unit transfer can be worthless after execution cost.
4. The attacker funded the initial donation. No zero-capital or cost-free
   attacker strategy was demonstrated. The 27 trial choices were human-frozen
   before source inspection, not an adaptive all-class search.
5. There is no matched comparison to Slither, Echidna, Medusa, or an
   independent frontier analyzer, and no demonstrated general speedup.

**Scientific interpretation:** unlike D2.4P's entirely generated laboratory
contracts, D2.4Q reaches untouched real third-party source and constructs
an actual native-EVM economic witness without being told where the target
implements that behavior. It proves a bounded source-to-EVM *economic pattern
discovery* capability. It emphatically does not establish an unknown
reportable vulnerability, deployed loss, superior discovery recall, or
zero-day-capable general intelligence.

## Next adversarial gate

- Test an uninspected **deployed protocol implementation**, pinned before
  incident, with a real asset and all adapter/inheritance logic, while
  independently confirming scope, no existing fix, and viable attacker
  parameters with gas/capital costs.
- Expand the engine beyond one fixed ERC4626 grammar: let it discover
  stateful action relationships and obligations from ABI/source semantics,
  including ERC20 approvals, loans, liquidations, and unrelated classes.
- Score blinded corpora with matched baselines and CPU/RAM/GPU/API budgets;
  reproduce fixes on native EVM and reject false positives.

**D2.4Q narrower autonomy gate: PASSED. New real security flaw and
zero-day gate: NOT YET PROVEN.**
