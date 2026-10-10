# PRISM Validation Step: 2026-10-10

## Work completed in order

1. Added deterministic benchmark generators: sparse relevance, distractors, parity, and intentional misspecification.
2. Added transparent comparison policies: cost-first fixed order, seeded random order, and decision-disagreement greedy selection.
3. Added generator and policy contract tests.
4. Performed a local semantic validation of the reference logic, replay invariant, certificate rejection, duplicate-operation guard, and exact-policy cost recurrence.

## Defect found and corrected

The original sufficiency fixture was wrong. After observing `a=0`, its remaining hypotheses had opposite decisions, but the test expected certification. The test therefore encoded an unsound claim about decision invariance.

The fixture now makes both remaining hypotheses imply `right`, while preserving distinct hypotheses. This is the correct demonstration that decision sufficiency does not require model identification.

## Validation result

The corrected local checks pass:

- initial ambiguity is not certified;
- two compatible hypotheses with one decision are certified;
- a certificate with the wrong decision is rejected;
- duplicate observations fail instead of being silently replayed;
- the exact-policy recurrence selects the cost-1 observation over cost-4;
- deterministic generator behavior is reproducible.

This was a semantic validation script, not yet a full remote CI run. The repository still needs a minimal test runner configuration and a complete benchmark runner before performance claims.

## Important remaining gap

The misspecification generator deliberately keeps the hidden world outside the declared problem. The current finite reference API cannot execute an operation against a hidden world absent from its hypothesis map. This is intentional for now, but the benchmark runner must represent hidden-world execution separately from declared-hypothesis reasoning so that PRISM can be tested for honest abstention rather than failing due to an interface shortcut.

## Gate status

The implementation is not ready for a domain adapter or performance claim. Next required work:

1. add a benchmark runner with separate hidden-world oracle;
2. add a minimal test configuration and run all repository tests;
3. implement policy-vs-optimum evaluation;
4. test empty compatibility and unsupported/malformed outcomes;
5. only then introduce the structural selector.
