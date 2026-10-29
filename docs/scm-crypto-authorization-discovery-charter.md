# PRISM — Crypto-authorization discovery charter (D2.5-Crypto)

**Status:** research charter; target selection is in progress, no implementation or superiority claim follows from this document.  
**Created:** 2026-10-29  
**Branch:** `research/scm-crypto-authorization-d25-charter`  
**Parent experiment:** [D2.5 semantic discovery-to-witness gate](scm-cyber-d25-semantic-verifier-gap.md)

## Purpose

Define the smallest credible research path toward discovering previously unknown vulnerabilities affecting cryptocurrency protocols, programmable wallets, and address/transaction authorization. The first domain is **authorization integrity from signed intent to actual asset effect**. This is a research priority, not a claim that this domain is objectively the most dangerous in every ecosystem.

PRISM's core must remain deterministic and usable without an AI model. All testing must use pinned public source and isolated local forks/simulations; never test against live wallets, real keys, real treasuries, or third-party systems without explicit authorization.

## The central research question

Can PRISM derive a justified, contract-specific security property from source and interface structure, turn it into an executable oracle, and discover a reproducible counterexample that competent reference methods miss—or discover it at lower total cost—under a fair, pre-registered budget?

The candidate SCM mechanism to test is **context-distinction preservation**: identify which distinctions in an authorization context are security-relevant (for example signer/account, chain/domain, destination, asset, amount/limits, nonce/expiry/revocation, permission state, and execution effects when applicable), then test whether those distinctions remain correctly bound from authorization through execution. These are candidate dimensions, not a universal checklist; applicability must be justified per target.

This mechanism is a hypothesis, not a demonstrated novelty. Existing static analysis, symbolic execution, fuzzing, property-based testing, and protocol-specific tools may already detect many such defects. D2.5 must measure SCM's incremental contribution.

## Scope: what is in and out

### First target family

A publicly available, previously unstudied EVM programmable-wallet or protocol codebase in which signed or delegated authorization controls a transfer or other asset-affecting operation. The exact target is **not yet selected**.

### In scope for this first experiment

- The relationship between signer/authority, signed operation context, permissions, execution, and asset effects.
- Multi-step and state-dependent behavior, including replay/nonce/expiry/revocation only where relevant to the target's stated semantics.
- Addresses as signed destinations or authorization context; not yet the full human-interface/address-poisoning problem.
- Source-derived candidate properties with explicit assumptions, provenance, falsifiable predicates, and a declared status: justified / plausible / unjustified / not executable.
- Reproducible local witnesses, minimized sequences, and independent adjudication.

### Out of scope for this first experiment

- A general-purpose scanner for every DeFi category.
- Live exploitation, real funds, private-key collection, or testing against production endpoints.
- Declaring a property valid merely because it can be tested.
- Treating a known vulnerability reproduction as a novel discovery.
- Claiming a zero-day or new vulnerability class without independent novelty and root-cause review.

## The four stages — no extra feature roadmap

### Stage 1 — Freeze the threat model and select the target (**current stage**)

1. Define the protected outcome: no asset-affecting operation may exceed the authority justified by the target's documented or independently defensible semantics.
2. Record attacker capabilities and exclusions; distinguish externally controlled inputs from trusted state and privileged actors.
3. Build a short candidate inventory, excluding targets/families already used in D2.4C/D/E/H and preferably the specific Safe/ERC-4337/Solmate experiments already present elsewhere in the project.
4. Screen each candidate for reproducible source/build, compiler/toolchain availability, local-only execution, meaningful stateful authorization, and a way for an independent reviewer to judge properties and findings.
5. Select one target only after the screening evidence is recorded. Pin repository commit, compiler, dependencies, build artifacts and hashes; keep historical issue/fix information hidden from the discovery run.

**Stage-1 exit artifact:** a frozen target-and-threat-model record with the reason for selection, exclusions, build reproducibility, known information leakage risks, and explicit success/failure criteria. Do not implement the discovery engine before this record exists.

### Stage 2 — Build only the semantic bridge

Implement the smallest deterministic path from compiler/source structures to (a) context/authority/effect relations, (b) candidate properties with explicit assumptions and provenance, and (c) executable oracles where justified. Unknown semantics must remain UNKNOWN. No broad adapter framework and no model dependency.

### Stage 3 — Run the frozen comparative experiment

Compare:
- a competent conventional baseline for the selected ecosystem;
- the same underlying tools with fixed/simple orchestration and without SCM's candidate-generation mechanism;
- PRISM with the proposed context-distinction mechanism.

Freeze versions, seeds, hardware, CPU/wall-clock and execution limits before runs. Count preprocessing, property generation, planning, execution, verification, memory and minimization costs. Separate human setup/property-authoring effort from machine runtime. Do not tune PRISM after seeing the held-out target's outcomes.

### Stage 4 — Independently adjudicate and decide go/no-go

Commit outputs before revealing known issues. An independent reviewer must classify each witness as invalid, valid-known, valid-novelty-undetermined, or independently confirmed novel. A larger campaign is justified only if at least one source-derived property is independently justified, an executable oracle produces a reproducible witness, and the baseline comparison shows a meaningful contribution attributable to PRISM. One witness is not proof of general superiority.

## Required status vocabulary

- **Observed:** output produced within a stated budget.
- **Candidate:** possible violation not yet validated.
- **Reproduced:** exact local witness replays.
- **Validated:** independent review confirms the property and violation under stated assumptions.
- **Known:** root cause or materially equivalent issue was already public/known.
- **Novelty-undetermined:** no sufficient evidence either way.
- **Novel confirmed:** independent review establishes prior novelty under a documented search and disclosure process.
- **No witness observed:** no counterexample found within the stated budget; never equivalent to “safe.”

## What counts as a result

A finding must include pinned source/build identifiers, the property and its justification, assumptions, executable oracle, minimal sequence/inputs/actors, state/effect trace, reproduction command, resource accounting, baseline outputs, and limitations. A generated property without independent justification is not a security finding.

Success is not a raw increase in candidates or tests. It is either (a) a valid discovery missed by strong references under comparable limits, or (b) a reproducible improvement in confirmed discovery per total cost, with uncertainty and failures reported. A single success authorizes a larger evaluation, not a claim of universal SCM superiority.

## Current execution record — 2026-10-29

- [x] Charter and four-stage sequence defined.
- [ ] Stage 1: threat model and candidate-selection criteria applied to concrete repositories.
- [ ] Stage 1: candidate selected, pinned, and independently screenable.
- [ ] Stage 2: semantic bridge implemented.
- [ ] Stage 3: frozen comparison completed.
- [ ] Stage 4: independent adjudication and go/no-go decision.

**Current honest status:** Stage 1 has started at the level of criteria, but is not complete. No target has been selected or pinned; no code has been implemented for this charter; no new tests or vulnerability findings have been produced.
