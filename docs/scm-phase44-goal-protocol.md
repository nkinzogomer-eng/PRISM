# SCM / PRISM Phase 4.4 — calcul orienté vers un objectif de découverte

**Protocol and result register — 2026-10-21. Research stage, NOT production ready.**

## Why the objective has changed

Earlier Phase 4.3 studied preservation of fixed Bandit/Semgrep decisions at lower resource cost. The stronger research objective is now to *discover and independently verify security-relevant behaviors that a given detection workflow otherwise misses*, within a fixed computational budget. Reproducing an existing scanner's weak decision is not sufficient.

The MSC decision specification is:

\[
 S = (\Phi, Y, P, V, B).
\]

- **\(\Phi\)**: a scoped CWE-22 request-controlled path reaching an operation outside an explicitly allowed filesystem root.
- **\(Y\)**: a set of distinct hypotheses, replay evidence, unresolved paths and refutations. Unknown stays unknown.
- **\(P\)**: source→sink dependency, control flow, sanitizer/guard and concrete reachability distinctions. Severity is a separate property.
- **\(V\)**: a fresh, instrumented and isolated execution using a synthetic request and a synthetic sentinel file. A semantic diagnosis and severity require extra independent adjudication.
- **\(B\)**: wall time, CPU, memory where available, tool calls, number of probes, precision/error budget and a safe sandbox. No external model is required.

**Long-term acceptance target (aspiration, not result):** at least 80% of independently verified target vulnerabilities on *unseen* projects, with no more than a 10% false-positive rate among adjudicated findings, complete accounting of unknowns, and competitive total time/resource cost against strong existing approaches. Unknown prevalence and severity distributions must be shown; tuning against benchmark labels invalidates holdout status.

An illustrative 8/10 or 18/20 claim is only meaningful if 10 or 20 true vulnerabilities were independently established and each PRISM discovery was independently verified. Raw scanner alerts or synthetic witness access do not qualify automatically.

## Research pipeline

1. **Goal compiler:** input specific CWE/attack surface and evidence/precision/budget requirements; refuses unsupported security properties.
2. **Static hypothesis engine** (`prism/goal_discovery.py`): narrowly bounded label-blind AST taint, symbolic branch simplification, exact dictionary keys, small list/config summaries, local helper functions and filesystem operations. Unknown reflection/imports/guards remain explicit. Incomplete and not a sound general Python analyzer.
3. **Goal-directed replay** (`scripts/phase44_replay.py`): in-process local Flask test client, user-controllable synthetic request in cookies/query/form/headers, synthetic sentinel just outside a synthetic allowed directory, everything within a disposable temporary directory. Instrument actual `open`, `codecs.open`, `Path.open`, `Path.exists` and `os.path.exists`. A successful sink operation proves this synthetic path escaped the intended test root; existence-only observations are lower-severity metadata probes. It does not execute shell commands or connect to a network service.
4. **Verification & ledger:** dynamic replay is independent from the AST candidate classifier; all errors and no-observation cases remain unknown for vulnerability absence. Replay also cannot establish whether a real user reaches the route, whether authorization is present or whether the effect would be critical.
5. **Evaluation:** separate scripts read labels only *after* the label-blind discovery and replay artifacts are saved. These labels are not an independent truth oracle and may be disputed.

## Frozen first measurement — pinned development corpus

- [GitHub Actions run 39646760383 (PASS)](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39646760383).
- [Raw discovery, replay, comparison, case-by-case evidence ZIP](https://github.com/nkinzogomer-eng/PRISM/actions/runs/39646760383/artifacts/12367153344).
- 23 tests for Phase 4.4 goal/proof contracts + 15 earlier Phase 4.3C tests passed. All 1,230 source modules examined statically without labels. OWASP Python v0.1 fixed at `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, 168 cases labeled path traversal (65 positive, 103 negative).
- **Static candidates:** 27 CWE-22 candidate cases (24 matching positive labels, 3 matching negative labels); 35 unknown path traversal cases. Among 133 evaluated cases, diagnostic label precision 24/27 = 88.9%, evaluated-label recall 24/53 = 45.3%. These are NOT independently verified bugs and are in-sample developer metrics. The 29 labelled positives not flagged among evaluated are failures of the static engine, not evidence of safety. Unknowns were excluded from the evaluated-label recall denominator and MUST be reported.
- **Targeted local behavioral replay:** source code route-string selection identified 168 cases using the literal `/benchmark/pathtraver-`. Each case received one fixed, safe path-escape probe, not an adaptive exploit search. **54/168 observed an external-to-root sentinel access**. Of these, **42 had a successful file-open operation** and **12 involved only existence/metadata checks**. Each observed case is positive according to development benchmark labels: 54/65 labeled positives captured by this one local probe = 83.1% **benchmark-label capture**, NOT real-world detection recall or critical-severity accuracy. No observed sentinel accesses in 103 labeled-negative cases. 19 cases failed to complete due to runtime exceptions (17 NameError, 1 IsADirectoryError, 1 UnboundLocalError); 95 showed no escape from this one payload. Neither group is certified safe.
- The full replay suite's instrumented execution took ~0.61 s wall time on this GitHub Actions run with runtime loaded, but this omits package installation, CI provisioning, additional proof/severity adjudication and all other costs; it is not a fair full-life-cycle time comparison with static scanners.

## Important adversarial interpretation

**Benchmark-category leakage:** the local replay driver currently selects routes whose URL literally contains `pathtraver`. This means the target weakness category is already supplied by the benchmark structure. The route selector does **NOT** discover that CWE-22 is the relevant property for a previously unseen program. Consequently the 83.1% figure is a *targeted proof harness success rate on a category-known toy suite*, not autonomous vulnerability discovery on an unknown application. A next-stage evaluation must remove this structural hint and infer the target independently.

**Synthetic oracle:** the harness constructs the sentinel outside `TESTFILES_DIR` but still within its own temporary root. A verified `open` is direct evidence that this synthetic path was accessed by the test handler with the supplied request. It is not yet evidence of exploitable access to sensitive production files, lack of authorization, or high/critical CVSS severity. A metadata-only `exists` check must not be counted as a successful arbitrary read/write. Simple single-probe non-observation does not measure true negatives.

**Strong comparison:** earlier development Bandit scans found zero true path traversal cases by coarse label attribution. CodeQL and Semgrep can find other cases. A targeted dynamic test is a different detection modality from a generic SAST scanner, so comparison to Bandit alone cannot establish superiority. Future research must compare to a pinned, competent dynamic/taint tool and state-of-the-art structure-/dependency-aware static engines at matched task scope and budgets, plus an autonomous controller that chooses probes for *unknown targets*.

**External dataset limitations:** OWASP Python v0.1 is preliminary and has contested labels. Report label disagreement and runtime evidence separately, rather than silently treating the CSV as ground truth or discarding disputed cases.

## Gate status and next experiment

- PASS: first purpose-specific working detector and independent runtime verification apparatus, tests passing, data labels separated, positive behavior observed in a reproducible sandbox.
- NOT PASSED: automatic property inference on a previously unseen software project, ground-truth independent full weakness recall, independently confirmed high/critical severity, complete cross-file flow tracking, native dynamic competitor baselines, robust time/memory/full-lifecycle cost, high-quality unknown/error handling, or untouched holdout evaluation.
- **Next: Phase 4.4C** — freeze a blind corpus without vulnerability-category names in code paths; let PRISM infer likely sink classes, resolve inter-function/import dependencies, rank unknowns by expected information gain and select bounded witness probes. Independently adjudicate read/write vs metadata/guard, compare to strong dynamic tools and native scanners, report failure counts and cost. Do not silently use labels or developer route names in target inference.
- Keep the PR a **draft**, do not merge or deploy and do not announce bug bounty/zero-day success based on this benchmark.

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_phase44_*.py' -v
python scripts/phase44_discover.py --source-dir benchmark/testcode \
    --output reports/phase44-goal-ci/discovery.json
python scripts/phase44_evaluate.py \
    --discovery reports/phase44-goal-ci/discovery.json \
    --labels benchmark/expectedresults-0.1.csv \
    --output reports/phase44-goal-ci/development-evaluation.json
python scripts/phase44_replay.py --source-dir benchmark/testcode \
    --output reports/phase44-goal-ci/replay-full.json
python scripts/phase44_replay_evaluate.py \
    --replay reports/phase44-goal-ci/replay-full.json \
    --labels benchmark/expectedresults-0.1.csv \
    --output reports/phase44-goal-ci/replay-development-evaluation.json
```

The first phase provides **verified sandbox behaviors** in a *known category*, not verified critical vulnerabilities in unknown software.
