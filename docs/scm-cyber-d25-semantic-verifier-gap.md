# D2.5 — Semantic discovery-to-witness gate

**Opened:** 2026-10-28  
**Branch:** `research/scm-prism-d25-semantic-verifier-gap`  
**Purpose:** resolve the demonstrated bottleneck, not increase test count.  
**Core constraint:** PRISM must remain useful without an AI model. This experiment is restricted to pinned source, isolated local execution, and synthetic/local state; no live systems or real treasuries.

## Decision from the preceding evidence

D2.5 must not start by adding more AST pattern rules. The existing reports establish three specific limitations:

1. D2.4H can emit Solidity candidate labels, but its compiler is lexical: it does not resolve inheritance, modifiers, storage flow, or EVM call semantics. Its OUSD run produced 12 unverified candidates (5 accounting, 7 authorization), no external-call/state-consistency candidate, and no executable oracle for those candidates.
2. D2.4C can execute real Foundry multi-transaction checks, but its two properties (`ALLOWANCE_SPEND_CONSERVATION`, `TRANSFER_ROUNDTRIP_SUPPLY`) are fixed, manually authored ERC20 specifications selected from ABI signatures. They are not inferred from the contract's semantics.
3. D2.4D's SCM quotient tied a conventional static-slicing baseline on search attempts and state expansion in all three measured families. Thus, simply adding another structural filter is not an evidenced scientific advantage.

**Root bottleneck:** the system does not yet connect source-derived semantic relations to a justified property, a runnable oracle, and a minimized counterexample. Candidate generation and verification exist as separate islands. That is more consequential than the latest keyword/alias false negatives.

## One experiment, not a broad test campaign

### Question

Can a deterministic, model-independent source frontend derive at least one *contract-specific, executable* multi-step property from a previously unstudied pinned Solidity project, and can PRISM find a counterexample that a competent baseline misses under matched limits?

### Protocol

1. **Freeze first:** record source commit, compiler version, ABI, engine commit, dependency versions, and SHA-256 hashes before any run. Do not change the engine after seeing target-specific outcomes.
2. **Target selection:** choose one authorized, publicly available Solidity project not used in D2.4C/D/E/H. The engine receives source and build artifacts only; historical issue labels, fixes, audit findings, and CVE/incident descriptions are withheld until all outputs are committed.
3. **Structural input:** use compiler-produced AST/ABI (not regex alone) to recover state variables, function/modifier relationships, external-call sites, and state writes before/after calls. Unknown constructs remain UNKNOWN.
4. **Property derivation:** derive candidate relations from those structures and declared interfaces. Every candidate must identify its state variables, relevant entrypoints, assumptions, and a falsifiable predicate. Do not silently reuse the two D2.4C ERC20 templates unless the target independently satisfies their declared semantics.
5. **Witness search:** generate bounded multi-transaction sequences and execute them only against an isolated local EVM deployment. Minimize any failing sequence and preserve the exact source, calldata/actors, state trace, and oracle output.
6. **Fair baseline:** run the project's available strong Foundry invariant/fuzz setup or an independently authored matched property harness, with the same target, wall-clock/CPU limits, and comparable number of executions. Count setup and property-authoring effort separately; do not pretend human authoring is free.
7. **Reveal and adjudicate:** only after freezing both outputs, reveal known issues/fixes and ask an independent reviewer to classify each witness as real, false positive, known, or novelty-undetermined.

## Single go/no-go gate

**GO to a larger discovery campaign only if** the engine produces at least one reproducible contract-specific witness from source-derived structure, the oracle is independently justified, the baseline comparison is fair, and the result survives independent review.

A known issue reproduced by the engine is useful engineering evidence but **not a novel discovery**. A candidate without an executable oracle is not a finding. A passing search with no witness means only “none observed within this budget,” not “safe.” One witness can establish a concrete capability but cannot prove general SCM superiority.

## Failure diagnosis (mandatory)

If no witness is found, report which stage blocked progress:
- property derivation produced no meaningful contract-specific predicates;
- the predicate could not be mapped to an executable oracle;
- the exploration failed to reach relevant states;
- the oracle was too weak/incorrect;
- the baseline found the same witness;
- or the target's observed behavior did not violate the candidate property.

Do not respond to a failed gate by merely adding more tests or keyword rules. Change the representation or the search mechanism only when the failure evidence identifies that as the bottleneck.

## Existing evidence (not repeated here)

- D2.4C: `reports/defi-d24c-external-multistep-2026-10-23.md`
- D2.4D: `reports/scm-cyber-d24d-cross-domain-2026-10-24.md`
- D2.4E: `reports/scm-cyber-d24e-real-source-2026-10-24.md`
- D2.4H: `reports/scm-cyber-d24h-autonomous-hypotheses-2026-10-26.md`

These reports explicitly state that no novel vulnerability and no general superiority has been demonstrated.
