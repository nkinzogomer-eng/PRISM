# SCM-PRISM Phase 3: controlled structural-computation experiment

**Status:** proposed implementation; Phase 3 remains unchecked until CI passes and measured results are reviewed.  
**Protocol version:** 1

## Research question

Does one already-verified structural transformation—dominated-observation pruning—preserve decision semantics and never increase exact expected execution cost across favorable, neutral, and adversarial finite regimes, and can we identify the limits of its guarantee?

This is deliberately narrower than H-SCM-1. Phase 3 does not test a general structural planner.

## Fixed transformation and regimes

No transformation code is changed. The existing dominated-observation pruning is tested across five predefined regimes, each with 100 fixed seeds by default:

1. favorable: a richer observation determines a coarser one and costs less;
2. cost reversal: a richer observation determines a coarser one but costs more, so pruning must not remove the cheaper coarse observation;
3. unrelated: observations expose independent bits and no dominance relation exists;
4. equal-cost duplicate: equal-cost equivalent observations test deterministic tie-breaking;
5. chain: a richer observation determines two coarse observations.

Seeds rotate hypothesis identifiers while preserving semantics, testing identifier-order robustness without changing the evaluation target.

## Hard acceptance gates

- 100 fixed-seed instances per regime complete.
- The independent dominance verifier passes every instance.
- Exhaustive decision-set comparisons over all evidence assignments to retained observations pass.
- The exact expected-cost solver finds no increase in expected execution cost for any instance under the declared uniform hypothesis prior.
- Favorable, equal-cost, and chain regimes perform expected removals; cost-reversal and unrelated regimes remove nothing.
- An omitted-world counterexample explicitly demonstrates that declared-class dominance does not establish external-world completeness.
- JSON and Markdown reports contain environment, seeds, per-regime counts, exact costs, timing diagnostics, hard-gate results, and limitations.
- Existing unit tests and Phase 2 benchmarks remain unchanged and pass.
- No production transformation, general planner, or domain adapter is added.

## Cost accounting

Observation execution cost is reported in abstract operation-cost units. Transformation, exact-solver, and elapsed wall times are reported separately in seconds. Unlike units are not silently added. The exact solver is a small-instance oracle relative to the declared class and implicit uniform prior, not an external-truth oracle. Timing comparisons are diagnostics; primary evidence is semantic preservation and exact expected-cost comparison.

## Refutation and failure policy

Any verifier failure, decision-set mismatch, exact expected-cost increase, missing expected positive/negative regime behavior, or CI failure blocks Phase 3. If the transformation only helps when its preconditions are deliberately satisfied, that narrow scope remains explicit. A certificate can remain wrong relative to an omitted external world even when the declared-class verifier passes.

## Phase 3 decision

Passing validates only the tested dominated-observation rule under the stated finite deterministic assumptions. It does not establish general SCM advantage, real-world cybersecurity efficacy, financial-flow analysis, astronomy performance, vulnerability discovery, or incident repair.
