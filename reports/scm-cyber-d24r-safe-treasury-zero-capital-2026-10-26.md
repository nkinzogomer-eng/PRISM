# PRISM D2.4R/D2.4S — Frozen Safe authorization and exploratory state frontier

Date: **2026-10-26**. Classification: **local, authorized research benchmark**.

## Executive verdict

- The **frozen, pre-registered** authorization search on a correctly initialized, original **Safe v1.4.1** found **0/12 unauthorized treasury transfers**, **0/12 unauthorized role modifications**, and **0 novel vulnerabilities**. This is a bounded negative result, not evidence of global safety.
- The **post-inspection, explicitly nonblind** general state-frontier engine then generated **24 state/action cases**. On the original Safe proxy under an intentionally unsafe **funded-before-initialization** deployment, **3/24** candidates yielded attacker token gains and owner takeover, corresponding to candidate indices **9, 10 and 11**. The amounts were 1, 1,000 and **1,000,000 mock-token units** respectively from a 1,000,000-unit treasury.
- The full-drain witness has **zero pre-owned attacker assets** in the local EVM state and uses no legitimate owner approval. **Real transaction gas, sponsorship, market value, net profit, and actual zero external expense remain unproven.**
- The original Safe source itself warns that calling `setup` on an uninitialized proxy is open to whoever calls it first. This is therefore an **already documented unsafe deployment condition**, **not a novel Safe source-code defect**, **not a new vulnerability family**, and **not a zero-day**.
- The independently authored insecure control was detected. The legitimate two-owner authorization succeeded and its replay was rejected after nonce consumption.

## Source and evidence integrity

Target: official `safe-fndn/safe-smart-account`, release `v1.4.1`, Git commit `bf943f80fec5ac647159d26161446ac5d716a294`.

| Original third-party source | Git blob SHA-1 | SHA-256 |
|---|---|---|
| `contracts/Safe.sol` | `3bd2ed9e9693838db0fb21960d00b78427a63c87` | `efd3301ed5c6bf522fb3a7a43be4a27341e65dff6d1fee04f8567f304a67e365` |
| `contracts/proxies/SafeProxy.sol` | `eb21260363a19f1a35ef34e323761e63cf5600e3` | `a32e2bb41a928cc17ac82a7240571e7ad8b8230555f711c13343584d8a4802bb` |

Preregistration was committed **before source inspection** in
[`benchmarks/defi/d24r/preregistration.json`](../benchmarks/defi/d24r/preregistration.json), commit `bdbe69e0116be0e39cf002590e0dd3fb733ce348`. After inspecting the source, the D2.4S generator was added, labelled nonblind from the outset.

Independent runner proof:

- Frozen/original native EVM CI run: [40413294094](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40413294094) — successful, 3/3 native tests, 7/7 new Python tests, 0/12 frozen witnesses.
- Hardened state-frontier CI run: [40413838243](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40413838243) — successful, **5/5 native EVM tests**, 3/24 exploratory state witnesses, 0/12 frozen witnesses, replay controls passed.
- The latter CI run publishes `forge-output.txt`, `source_attestation.json`, `trial_plan.json`, `state_frontier_plan.json`, and `result.json` as a [downloadable evidence artifact](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40413838243/artifacts/12693638754).
- In the local development workspace, the full existing Python suite was run: **440 tests**, 1 expected failure, no unexpected failures. This local output is not an independent GitHub Actions artifact.

## Exactly what was tested

**Frozen (blinded with respect to original source code):** A proxy was first initialized with two unrelated owners, threshold 2, no modules, and funded with 1,000,000 private-lab tokens. Twelve ABI-led attacker candidates across unauthorized module execution, unsigned direct execution, owner or threshold mutation, and reinitialization were run, with three bounded amounts. No original-owner signatures or attacker starting token holdings were provided. No witness was observed.

**Exploratory D2.4S (NOT blind):** The generator crossed the *same* four candidate families and amounts with two deployment states: properly initialized versus not initialized. It generated 24 cases, without receiving a vulnerability label. In three uninitialized cases, the attempt to call the public one-time initialization procedure with a mock-token reimbursement produced attacker gains and a changed owner set. The known unsafe deployment condition was previously visible to the implementer, so this is a **generalized state-exploration regression**, not evidence that PRISM independently identified a previously unseen threat.

**Independent controls:**

1. Deliberately insecure, *locally authored* account: attacker token transfer succeeds; observer logs a positive witness. **Not a third-party vulnerability**.
2. Properly initialized original Safe: identical unauthorized actions show no transfer and no privilege change in these cases.
3. Original Safe with two explicit owner approvals: owner-authorized transfer succeeds; the old approval cannot be replayed for the next nonce.
4. Known misconfigured original Safe proxy: the initialization boundary is demonstrated on its real native EVM code, with a mock-token treasury.

## Interpretation and constraints

The full-drain witness tests **a misconfiguration, not a bypass of properly configured Safe multi-signature policy**. A Safe wallet is not shown vulnerable merely because an uninitialized proxy can be claimed; the original release warns about this usage contract. The attacker owns zero starting assets inside the test scenario; external deployment costs and blockchain fees are out of scope, so `zero_capital=true` **must not be confused with** `zero_real_cost=true`.

The 24 exploratory combinations overlap with the 12 frozen hypotheses. They are separate results in separate test functions and must not be pooled into a single blinded discovery rate. No proof for never-before-seen vulnerabilities, universal exploit discovery, protocol treasury drainability, or better performance than leading tools follows from these experiments.

The proposer is currently still **ABI-template-limited**; full unanticipated attack-family invention, unbiased code-based semantic state inference, actual deployed-state replay, and financial gas/fees are unimplemented for this target. The preregistered signature-replay *autonomous candidate family* is still uncovered, although a manually constructed legitimate replay control passes.

## Next falsifiable step

Select a **different**, uninspected third-party wallet/DeFi integration. Freeze target commit, real deployment preconditions, independent outcome oracle, and budgets *before reading its source*. Transfer the state-frontier generator without target-specific alterations; measure recall/false positives, actual native effects, execution cost and missing reachable operations. Add library-to-protocol transaction-domain and signature-invariant checks (`ethers.js` and `viem`) only when the native controls remain sound. Do not claim novel critical flaws without independent responsible disclosure review.
