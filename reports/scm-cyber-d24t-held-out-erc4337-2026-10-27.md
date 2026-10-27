# PRISM D2.4T — Held-out ERC-4337 reference-wallet native EVM trial

Date: **2026-10-27**. Private-lab-only security experiment; no mainnet or real funds.

## Verdict: bounded cross-architecture reproduction, not a novel zero-day

The prior PRISM target inventory was searched for `eth-infinitism`, `SimpleAccount`, and `account-abstraction` and contained no matching prior target. The official `eth-infinitism/account-abstraction` **v0.7.0** release was selected and a threat specification [committed](https://github.com/nkinzogomer-eng/PRISM/commit/a453715692365b3cbb0a3fb48f2ea2533ebeeffb) **before its source was read**.

The exact third-party original contracts were then deployed and tested on a native local Foundry EVM. The target `SimpleAccount` is explicitly described upstream as a **sample minimal smart account**, not an independently established deployed treasury.

| Observation | Verified result |
|---|---:|
| Source-derived ABI grammar candidate executions | 18 / 18 confirmed by distinct EVM logs |
| Official factory-initialized account candidates | 9 |
| Unauthorized token outflow with proper factory initialization | **0 / 9** |
| Independently deployed, uninitialized proxy candidates | 9 |
| Uninitialized-proxy attacker token-outflow witnesses | **3 / 9** |
| Positive indices in all 18 cases | **15, 16, 17** |
| Original EVM test functions | 3 passed, 0 failed |
| Local Python suite regression | 445 tests, 1 expected failure |
| Confirmed novel vulnerabilities / new classes / zero-days | **0 / 0 / 0** |

In the three positive cases, a proxy using the original SimpleAccount implementation was created *outside* the project's official factory with empty initialization data, then funded with 1,000,000 mock-token units. An unprivileged caller was able to initialize this **previously ownerless** account in its own name and subsequently make a transfer of **1, 1,000, or 1,000,000 mock-token units**. The final amount represents 100% of the **simulated** funded treasury, and attacker starting asset holdings were zero inside the lab.

This is a **configuration/deployment hazard**, not evidence of a bypass of the owner checks for normally deployed SimpleAccount instances. In the nine official factory-initialized cases, no unauthorized outflow was observed. Transaction gas and any externally borne expenses are not priced: zero initial assets is **not** a demonstration of zero total real cost.

## Scientific separation of known versus unseen

1. **Unseen target selection:** true relative to PRISM's recorded prior benchmarks; a precise repo commit and success criteria were frozen before reviewing the target.
2. **Unseen adaptation:** **not achieved**. The EVM adapter was implemented after reading target code, so some source-specific knowledge was necessarily available to its implementer.
3. **Automated scenario generation:** the bounded ABI-led state/action planner generates 18 actions without vulnerability labels, but it relies on prior categories and a known initialization-versus-noninitialization state axis.
4. **New semantic family discovery:** **not demonstrated**. Initialization takeover under unsafe deployment had already appeared in the preceding Safe experiment.
5. **Zero-day / deployed real-world funds:** **not demonstrated**.

These distinctions are mandatory. The correct scientific conclusion is that PRISM has **reproduced the same permission/deployment failure mode on original code from a second architecture** and avoided reporting it as a flaw of the correct deployment mechanism.

## Source provenance

Pinned target: `eth-infinitism/account-abstraction` release `v0.7.0`, commit `7af70c8993a6f42973f520ae0752386a5032abe7`.

| Original file | Git SHA-1 | SHA-256 |
|---|---|---|
| `contracts/samples/SimpleAccount.sol` | `61af6ca6bfba4a38c7096aa52c48041c55712b31` | `8075e38726cac91e9f80051833bf61c8ad26650795eab75af276c3f71169fc0a` |
| `contracts/samples/SimpleAccountFactory.sol` | `5afa2ce60c17f0a79be2a225037d81daf85693a5` | `9cfaa4a25f583b57cdba51a7084440f4570a414118ab7c38766229a66e3ea3ff` |
| OpenZeppelin `contracts/proxy/ERC1967/ERC1967Proxy.sol`, commit `dbb6104ce834628e473d2173bbc9d47f81a9eec3` | `0fa61b5b3f157b67d9e1e18154a0f1a39c3a78fe` | `ca1c1476f97761f3a5830395576c82756899ad8896489cef9c388afab825ef21` |

CI run with all trials individually logged and source attestation: [GitHub Actions 40528339551](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40528339551).

Native artifacts: [forge logs, generated trial plan, SHA evidence, classification](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40528339551/artifacts/12745660321).

## Scope and negative controls

- Attacker was distinct from official owner and from the fixed entrypoint address.
- No authorized owner signatures, external entrypoint control, mainnet accounts, or real assets were supplied to the attacker.
- Legitimately initialized original account succeeded at an **authorized** owner token transfer, proving the source was not simply incapable of executing transfers.
- An independently authored *intentionally unsafe* wallet acted only as a positive observer check and is excluded from third-party findings.
- There is no source-code modification of either target contract or its pinned OpenZeppelin dependency.
- ERC-4337 `validateUserOp`, entrypoint sponsorship, signature verification, and account-ownership transfer were **not** exhaustively evaluated. The ABI lacks a direct ownership-transfer method compatible with the preregistered grammar, and this family is explicitly listed as uncovered.

## What failed to meet our scientific target

The user-facing goal is to find serious **previously unknown** authorization or economic vulnerabilities on real, authorized targets, preferably with no attacker-owned starting capital and modest computational resources. This trial does not establish that capability. It cannot justify claims of scientific superiority over existing bug finders, a zero-day, guaranteed treasure-draining exploit, or universally safe official wallets.

## Hard gate before claiming autonomous discovery

Build a source-independent semantic property generator and native execution adapter **before selecting or reading the next held-out target**. Freeze the engine and challenge criteria, then test on an unrelated wallet or protocol. Require independent positive/negative controls, full operation traces, real cost-model separation (capital, gas, sponsorship), and source/deployment-state validity. Treat any incomplete authorization or transaction domain as `UNKNOWN`, never `SAFE` or `ZERO_DAY`.
