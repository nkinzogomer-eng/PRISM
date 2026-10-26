# PRISM D2.4I — independent-source holdout, safe model checks, resource costs

Date: 2026-10-26. Research-only; no change to Ciel or `main`.

## Preregistered experiment

Before evaluating source, freeze the manifest at
`benchmarks/cyber/d24i/holdout_v1.json`: four exact upstream Git commits and
one broad API module per project (Click, Requests, HTTPX, Pydantic). Selection
is by framework diversity, **not** known vulnerability labels. The pinned
inputs have no verified ground-truth vulnerability labels, so this is a
real-source *coverage and cost pilot*, NOT a precision/recall benchmark or a
scientific confirmation of zero-day discovery. The developers still chose the
programs, so a true independent blind holdout will require an external curator.

## New capability and interpretation

`prism/cyber_flow_model.py` interprets a deliberately tiny, pure AST subset
with harmless canary values. It checks whether a source-derived hypothesis
for command/evaluator execution or secret logging has a *modeled* input-to-sink
path. It does not execute any source code, shell, eval, command, or logger.
Unknown side effects, unsupported syntax and exhausted budgets abstain.
Unknown conditional feasibility is disclosed. A model witness is explicitly
**not** an actual vulnerability or runtime exploit reproduction.

The held-out CLI scans all four sources within a fixed 1 MB/file bound, 128
candidates/file, 256 modeled statements/candidate and 16 paths/candidate, with
zero external LLM calls and no GPU. It measures elapsed and process CPU time,
Linux peak process RSS, hypotheses, modeled witnesses and unknowns. There is
no comparison against human auditors, fuzzers, symbolic analysis or commercial
tools yet; do not claim speedup or lower total economic cost.

## Required engineering gates

1. Adversarial tests pass for a modeled dangerous sink, logging, false-positive
   assignment overwrite, unknown branch feasibility, unsupported side effects,
   resource exhaustion and absolute nonexecution of third-party code.
2. The previous D2.4H test suite remains green.
3. All four pinned source files load, are content-hashed and yield a complete
   JSON record and `time -v` measurements; no result is silently omitted.
4. A zero finding, zero candidate or unknown must never become SAFE. No novel
   issue may be asserted from a source heuristic or AST model witness.
5. Keep work on D2.4I branch/draft PR until independent review.

## Scientific GO beyond this pilot

Add independently curated holdouts with externally verified historical and
unpublished cases, ground truth, reproducible isolated behavior-based oracles,
and explicit per-class recall, precision, TTFW, memory, CPU, and cost
comparisons under identical budgets. Extend executable Solidity multi-contract
economics and stateful sequences. Search novel classes through semantic
counterexample generation, not by mere synonym expansion of these heuristics.
No 80% cost reduction, universal superiority or zero-day capability is claimed.
