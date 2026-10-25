# PRISM D2.4G — source-only discovery, third current-source trial, and live Ciel bridge

**25 October 2026 — CONCRETE ENGINEERING PASS; NO independently unknown vulnerability discovered.**

## Reproducible code and CI

- PRISM [draft PR #33](https://github.com/nkinzogomer-eng/PRISM/pull/33), tested code `381f392cbd5bf7bd26c7f1135414765fe4f5efb6`, [passing Actions run 40215557334](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40215557334).
- Ciel [draft integration PR #1](https://github.com/nkinzogomer-eng/ciel/pull/1), code `94a72365afae5a6cb0a2aa5f8bf182ccf82fc5a8`, [passing end-to-end Actions run 40215693887](https://github.com/nkinzogomer-eng/ciel/actions/runs/40215693887).
- Neither main branch was changed. PRISM Python unit tests **14/14**, Ciel capability unit tests **7/7**.
- All local source-only JSON, Ciel task envelopes, replay digests, version fingerprints and resource measurements archived by PRISM Action `d24g-local-unlabeled-execution-and-ciel-json`.

## Real behavior observed without feeding source diffs, fixes or CVE labels to the scanner

| External source | Scoped property probes | Locally reproduced behavioral violations | Result |
|---|---:|---:|---|
| Starlette 0.26.1 old, exact upstream commit | 6 | 3 | `LOCAL_PROPERTY_WITNESS` |
| Starlette 0.27.0 fixed, exact upstream commit | 6 | 0 | `NO_WITNESS_NOT_SAFE` |
| Werkzeug 3.1.5 old, exact upstream commit | 17 | 8 | `LOCAL_PROPERTY_WITNESS` |
| Werkzeug 3.1.6 fixed, exact upstream commit | 17 | 0 | `NO_WITNESS_NOT_SAFE` |
| Django main pinned SHA `0e128d524d0a7c55a955570d6e5da983ac6ce6c7` | 7 | 0 | `NO_WITNESS_NOT_SAFE` |

These are **2 real already-published historical root causes**, not 11 independent bugs or new zero-days. The 11 are reproducing inputs for two existing security issues. The researchers CHOSE the Starlette and Werkzeug historical projects with foreknowledge of their known defects. The engine's no-patch mode is only *label-blind at execution time*, **not a sealed objective holdout or a genuinely prospectively discovered vulnerability**.

Django is a separate **current-version source-only exploratory target**, chosen without a specific suspected bug. Seven root boundary probes found no violation; that is strictly **not a proof of safety**, and does not say anything about other Django functionality, Windows behavior or vulnerability classes outside the chosen property.

## New operational capability

- **Source-only probe:** `prism/cyber_discovery.py` records explicit property, source fingerprint, budget, all observations, deterministic replay hash and the shortest local property witness. The scanner may return `LOCAL_PROPERTY_WITNESS`, `NO_WITNESS_NOT_SAFE` or fail closed. No historical patch is mandatory for hypothesis execution.
- **Read-only local adapters:** real upstream Starlette method on real temporary filesystem; real Werkzeug `safe_join` code with a function-local Windows OS facade (not Windows kernel); real current Django `safe_join` extracted unchanged from AST with a stub for an imported exception class. None provides a general framework/HTTP/network exploit assertion.
- **Research integrity:** the probes and semantic adapters are researcher-supplied and tuned to path-containment classes; not an autonomous generalized discovery of arbitrarily complex cyber violations.
- **Ciel evidence boundary:** Python emits `scm.prism.ciel-capability.v1` with correlation IDs and budget. It always marks `ciel_verification_state=UNVERIFIED`, `needs_independent_attestation=true`, `claim_of_new_vulnerability=false`. This is an observation for Ciel to verify, not a certificate of independent attestation.
- **Real Ciel execution:** in its private repo, Ciel's EXTERNAL capability checks `cyber:local-audit` permission, an injected source authorization predicate, SHA-256 and JSON fields, and launches the actual Python PRISM scanner via its injected runner. It executed one historical Starlette mission (3 witnesses) and one current Django mission (0 witnesses). Both completed `COMPLETED_UNVERIFIED`; Ciel did not improperly promote a claim to VERIFIED. `AI_ENABLED=false` was tested in both runs.

## Hard limits — what this is not

1. **No new unknown vulnerability.** Two old selected cases, one current-source negative property trial.
2. Not a universal scanner: no semantic cross-module reasoning, contract storage economics, native memory properties or automatic high-quality property inference across arbitrary APIs.
3. No hardened deployment worker: the GitHub Actions machine was an ephemeral CI environment; production Ciel still needs strict sandboxing, source allowlists, timeouts, network policy and independent replay attestation.
4. No evidence for 29–50× end-to-end speed or 80% lower total cost. These benchmarks do not include meaningful direct comparisons; those ambitions remain unproven.

## Immediate next build gate

Make the Ciel independent replay verifier and secured external worker real; add additional source-derived security property families for web authorization, cryptographic accounting and memory safety; select targets based on project rules and independent distributions **before knowing the relevant vulnerabilities**; then confirm genuinely novel findings privately with maintainers under coordinated disclosure. Retain zero findings as explicit negatives, not unsafe optimism.

**STATUS:** technically usable research prototype in two unmerged PRs; production readiness and scientific supremacy remain NO-GO.
