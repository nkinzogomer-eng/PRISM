# D2.4J — Label-free DeFi source pilot and real EVM sensitivity test

Date: 2026-10-26. **Exploratory source-and-oracle gate: PASS.**
**Novel vulnerability discovery gate: NOT PASSED / NOT YET MEASURED.**

## Evidence

- First independent third-party native EVM observation:
  [GitHub Actions run 40302480551](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40302480551).
- Hardened repeated run, including an ephemeral deliberately broken sync:
  [GitHub Actions run 40302812408](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40302812408).
- Preregistration published **before viewing selected sources**: commit
  `468e00f0ecac91e487160f7ebdba4cb767fbb353`.
- Frozen source references and Git blob digests:
  `benchmarks/defi/d24j/preregistration.json`.
- Raw source-only candidates:
  `reports/d24j-local-evaluation.json`.

## Results

| Fixed upstream source | Source-only relational hypotheses | Independently EVM-observed |
| --- | ---: | --- |
| Solmate ERC-4626 | 6 | Not yet |
| OpenZeppelin ERC-4626 | 6 | Not yet |
| Uniswap V2 Pair | 4 | 1 read-after-write relationship, 3 native test cases |
| **Total** | **16** | **3 tests passed; zero new vulnerabilities** |

The candidate grammar infers preview/execution reconciliation, inverse-unit
round-trip nonexpansion, and read-after-write reconciliation. These are
**families of candidate properties**, NOT new vulnerability families.
Every result is explicitly `UNVERIFIED` until a separate EVM observer checks
its meaning and its concrete traces.

For Uniswap V2, the verifier downloaded original source and its imports at
the pinned commit, compiled it using a local Foundry v1.3.6 setup and an
isolated, fake-token fixture, then checked that `sync()` reconciles reserve
readbacks with actual asset balances. A pre-sync divergence was visibly
detected, so the observer was not merely asserting a tautology.

On the second run, a **separate temporary copy** of the original contract had
the `sync()` state update neutralized. The exact same native test battery
then failed on the primary reconciliation property. PRISM required that
failure; a compiler failure or missing tests would not count as sensitivity.
This is an intentionally injected lab mutation, NOT a newly found Uniswap
vulnerability.

- Native original: **3/3 tests succeeded**.
- Temporary mutation: **detected by original EVM oracle**.
- GitHub CI reported roughly **0.4012 s** for the full native pilot including
  the local mutation, on its hosted runner (not a hardware-normalized metric).
- D2.4J adversarial Python tests: **18 passed**.
- Full local project suite: **343 executed, 342 passed, 1 intentional expected
  failure**.
- Known real-world newly verified security flaws: **0**.
- Classical competitor comparisons performed here: **0**.
- Ciel-produced hypotheses actually verified: **0**; Ciel remains decoupled.
- Model API calls for this experiment: **0**.

## Critical anti-hype distinction

The selected **repositories and commits were frozen before inspection**.
However, the hypothesis grammar was subsequently developed *with knowledge
of these three targets' function surfaces*. Therefore these are an
**exploratory in-sample cohort** for the new grammar: source labels were
hidden, but this is NOT a fully independent, out-of-sample blind holdout.
No sensitivity estimate, novel-class discovery rate, or claim of scientific
superiority may be inferred from the 16 candidate count.

The Solidity lexical extractor also does not resolve complete semantics of
fees, rounding, imported modules, compiler modifiers, inherited methods,
callbacks or adversarial external tokens. Solidity unit tests are external
native observers, but they cover only one selected relation of one target.
The passing witness of a good property is not proof that the entire protocol
is safe.

## Next locked scientific hurdle

1. Freeze the **proposer and verifier** first, then choose new unseen,
   independently maintained DeFi contracts with no post-hoc selection.
2. Run the unchanged engine and report **zero-candidate outcomes**, malformed
   frontends and unknowns as prominently as positive candidates.
3. Verify all feasible proposed properties against independent raw EVM state
   observations; use negative and metamorphic controls and fail closed.
4. Compare cost, recall and false-positive rate against a pinned classical
   tool baseline, on identical legal local source/budgets.
5. Only an independently adjudicated real defect outside training/development
   material may count as new external finding; zero days require much more.

The engineering lesson is positive: PRISM can propose a relation from real
DeFi code without a bug label, check one independently, and demonstrate its
oracle detects a transient mutation. The scientific generalization claim
remains explicitly **unproven**.
