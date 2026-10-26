# D2.4K — Real-source economic hypothesis: source-first proposal and native EVM verification

Date: 2026-10-26. **Engineering gate PASS. Genuine previously unknown
vulnerability / zero-day gate NOT PASSED.**

## Reproducible artifacts

- Final green native EVM run:
  [GitHub Actions 40315464698](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40315464698).
- One successful preliminary native run before source-to-hypothesis integration:
  [40314184416](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40314184416).
- Source-to-hypothesis integration initially **failed**:
  [40314831279](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40314831279).
- Corrected source-to-hypothesis chain:
  [40315090180](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40315090180).
- Native EVM original contract: pinned Solmate ERC4626,
  `transmissions11/solmate@89365b880c4f3c786bdd453d4b8e8fe410344a69`.
- Implementation: `prism/d24k_structural.py`,
  `scripts/d24k_value_influence.py`,
  `benchmarks/defi/d24j/test/D24JValueInfluence.t.sol`.
- All experimental actions used a local EVM and intentionally funded local
  fixture token. No RPC fork, deployed funds, credentials or mainnet actions.

## The concrete EVM witness

The candidate is generated from code-visible coupling of the vault's
`totalSupply`, abstract `totalAssets`, share conversion and deposit quote.
It is conditional on external assets affecting the exchange rate without
creating shares. The independent Solidity oracle checks the possible
financial consequences in a minimal **unprotected** vault derived from the
unaltered published Solmate base contract.

| Step in isolated economic example | Units / result |
| --- | ---: |
| Attacker deposits first | 1 unit; 1 share |
| Attacker directly donates to vault | 100 units; **no new shares** |
| Victim deposits without minimum-share guard | 199 units; receives 1 share |
| Attacker redeems | 150 units |
| Victim redeems | 150 units |
| Attacker net gain relative to 101 spent | **+49 units** |
| Victim net loss relative to 199 spent | **−49 units** |

Original token issuance and final asset supply are conserved. A separate
control without the donation yields **no victim loss**. A separate guard
requiring a minimum number of shares **rejects** the manipulated deposit and
preserves the user's assets.

The native suite also exercises **15 distinct donation sizes and matching
victim inputs**. Each must preserve the observed value-transfer relationship;
this is not a replay of only the same hard-coded amount.

Final observed test suite:

- **5/5 native Solidity tests passed**, including 15 parameter variants.
- **11/11 D2.4K Python tests passed** (structural and evidence controls).
- **358 whole-project Python tests executed, 357 passed and one intentional
  expected failure**.
- GitHub-hosted EVM compilation/evaluation subprocess recorded about
  **0.3676 seconds**, measured *after fetching pinned sources*, not an
  end-to-end or hardware-normalized performance comparison.
- **0 model/API calls**, GPU not required.

## Failure-driven engineering correction

The first automatic source-to-EVM integration was red because `totalAssets()`
is an **abstract function** in the published ERC4626 base. The initial
source proposer incorrectly required an implemented body in the same file,
so it discarded a legitimate cross-contract semantic dependency. The fix
recognizes the declaration, generates a **conditional** hypothesis and
retains the actual aggregate semantics as UNKNOWN. This was validated with
a separate regression test and a real pinned source read.

The D2.4K syntax extractor now records overloaded functions rather than
immediately rejecting the entire file. It is still lexical rather than a
typed Solidity compiler IR: imports, inheritance, hooks, storage aliasing,
upgradeability and external economic specifications remain unsolved.

## Exact boundary of the claim

The tested manipulation is the **already publicly documented ERC-4626
inflation/donation and rounding pattern**, including in the OpenZeppelin
ERC4626 security documentation:
https://docs.openzeppelin.com/contracts/5.x/erc4626

The downstream effect depends on the integration's initial liquidity,
fee/rounding logic, slippage protection, asset handling and deployment
conditions. This exercise is **not** a security advisory about any deployed
vault, nor a newly identified flaw in Solmate, nor evidence of a zero-day.
The class and test target were known to the researcher when the D2.4K
hypothesis grammar was built. **This is therefore a development/positive
verification control, not a blind unknown-family discovery.**

The concrete advance over D2.4I/D2.4J is that a real third-party contract
exhibited actual balance/share/value changes under a generic conditional
source proposal, and the independent EVM oracle reproduced the economic
effects with undonated and guarded counterfactuals. The advance is in
**semantic verification depth**, not established zero-day recall.

## Blocking goals still to solve

1. Generalize to typed intercontract storage/effect graphs, semantic
   specifications and EVM state traces that cover Morpho-like lending and
   Uniswap V3-style concentrated liquidity, not only ERC4626 ratios.
2. Build tool-independent witness adjudication with low false-positive
   rates and explicit UNKNOWN on insufficient observation.
3. Freeze the **next** generator, then run it on wholly unseen DeFi targets
   selected afterwards; do not recycle these Solmate examples as blind test
   positives.
4. Benchmark actual bug recall, false-positive rate and resource cost
   against pinned classical baselines on identical legal local code.

No result so far justifies claims that PRISM is unbeatable, can find
unprecedented vulnerability classes, or can reliably discover zero-days.
