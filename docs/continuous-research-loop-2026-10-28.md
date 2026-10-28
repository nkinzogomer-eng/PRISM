# PRISM continuous research loop — 2026-10-28

## Purpose

Turn PRISM development into a continuous, evidence-driven loop: observe results, diagnose the highest-impact failure, implement a bounded correction, attack the correction with counterexamples, measure against frozen baselines, and retain only improvements that survive regression tests.

This is a working protocol, not a claim that autonomous novel-vulnerability discovery has been achieved.

## Current evidence boundary

The external review snapshot dated 2026-10-27 remains the baseline for historical claims. It reports no verified new zero-day and no verified novel vulnerability family. Reproducing known bugs, detecting intentionally vulnerable controls, or generating many related traces must not be counted as distinct discoveries.

The latest proposed engineering direction is semantic obligation generation: infer candidate security obligations from program structure and behavior instead of relying only on a list of vulnerability labels. Candidate generation, witness production, confirmation, and novelty assessment are separate stages.

## Loop contract

For each iteration, record:

1. **Observation:** exact target revision, tool versions, command, resource budget, logs, and reproducible result.
2. **Failure class:** false positive, false negative, unsupported semantics, wrong ground truth, weak baseline, budget exhaustion, or inconclusive evidence.
3. **Hypothesis:** one falsifiable explanation for the failure and a predicted observable effect of the proposed fix.
4. **Change:** minimal patch on an experiment branch; do not silently alter `main`.
5. **Countertests:** original failing case, repaired control, adversarial variants, metamorphic variants, and regression suite.
6. **Independent check:** where possible, a separate oracle or tool verifies the behavior. The generator must not be its own sole judge.
7. **Decision:** retain, revise, or revert the patch based on predeclared acceptance criteria.
8. **Ledger:** preserve code commit, inputs, logs, metrics, uncertainty, and the next highest-value experiment.

## Required result labels

- `HYPOTHESIS`: a plausible obligation or suspected issue, not yet witnessed.
- `WITNESS`: a reproducible trace demonstrates the predicted behavior under stated assumptions.
- `CONFIRMED_VIOLATION`: an independent check establishes that the witness violates an explicit or independently justified security obligation.
- `KNOWN_CLASS`: the root cause matches a documented class or previously reported issue.
- `NOVELTY_UNVERIFIED`: no match has yet been found, but novelty has not been independently established.
- `NOVEL_CLASS_CANDIDATE`: a third-party reviewer has confirmed the root cause is not a duplicate of known reports; still not automatically a zero-day claim.
- `UNKNOWN` / `UNSUPPORTED`: semantics or evidence are insufficient. Never silently convert these to `SAFE`.

## Semantic-obligation experiment

### Question

Can PRISM infer a useful obligation for a method that was not explicitly named in a vulnerability rule, using only generic structure and independently observed behavior?

### Development corpus

Use synthetic and public, historically documented vulnerable/fixed pairs. Freeze expected outcomes before testing. Include at least:

- state-mutating method with a missing authorization check;
- equivalent method correctly guarded;
- a guard that occurs after the state-changing effect;
- shared storage with intentionally different legitimate access policies;
- inheritance/modifier/helper-call cases that the current parser cannot soundly resolve;
- proxy and initialization-state variants;
- an unrelated method with superficially similar names but different semantics.

Every unsupported semantic feature must lead to abstention or an explicit coverage gap, not a guessed verdict.

### Holdout protocol

1. Freeze the engine commit, generic adapters, configuration, budgets, and scoring code.
2. Have an independent selector choose target repositories only after the freeze.
3. Keep labels and patch history hidden from the implementer until the run is complete.
4. Do not modify the engine after inspecting a holdout and still call that same target blind; move it to development and select a fresh holdout.
5. Run strong relevant baselines under the same target revision and resource constraints.
6. Count results by distinct root cause, not by trace, function, contract, or generated scenario.

### Metrics

Report at minimum:

- true/false positives and false negatives by root cause;
- number of independently confirmed distinct root causes;
- proportion of candidates reaching a reproducible witness;
- proportion of witnesses independently confirmed;
- abstention and unsupported-coverage rates;
- time to first confirmed issue and total end-to-end time;
- peak RSS, CPU time, compile time, and external/API cost;
- human hours spent preparing adapters, interpreting results, and confirming findings;
- baseline-only findings, PRISM-only findings, and overlap.

No aggregate “superiority” claim is allowed unless target selection, labels, and acceptance criteria were frozen before the holdout run and uncertainty is reported.

## Acceptance gate for a patch

A patch is accepted only if:

- the targeted counterexample is fixed;
- the repaired control remains negative;
- no existing regression test worsens;
- the independent checker agrees or the result is explicitly marked inconclusive;
- cost/coverage trade-offs are reported;
- the change does not make the core depend on an LLM or paid model.

Passing synthetic tests is necessary for engineering confidence but insufficient to establish real-world generalization.

## Safety and scope

All experiments must use public code, local copies, or explicitly authorized targets and isolated test environments. No malicious transactions, production treasury interaction, use of private keys, or unauthorized exploitation. Economic claims must include gas, sponsorship, capital, and other costs rather than assuming them away.

## Next actions

1. Verify whether the semantic-obligation prototype and its tests are present on the public branch; do not assume local changes were published.
2. Re-run focused tests and the full regression suite in a reproducible environment.
3. Add a differential vulnerable/fixed pair where the obligation is not pre-labelled by a vulnerability-specific rule.
4. Audit guard semantics, helper expansion, control-flow order, and unsupported constructs; abstain where the representation is incomplete.
5. Only after the engine and scoring are frozen, launch a truly independent holdout.

## Status

Protocol committed to an experimental branch on 2026-10-28. Implementation status, CI status, and blind-holdout performance remain **unverified** until separate evidence is recorded.
