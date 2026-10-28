# D2.4H — keyword-argument and dynamic-shell regression, 2026-10-28

## Question

Does the source-first Python hypothesis compiler miss untrusted-execution candidates when command data is passed by keyword, or when the `shell` mode is computed dynamically?

## Observed defect and patch

The original taint heuristic examined only positional call arguments. A source pattern such as `subprocess.run(args=user_data, shell=True)` therefore failed to produce an `untrusted_execution` candidate. A second gap was that a non-literal `shell` flag was not treated as uncertain; simply ignoring that case could hide a path whose runtime mode enables shell parsing.

The patch now:
- examines keyword argument values for command-data dependence;
- excludes the `shell` option itself from command-data taint, avoiding a false candidate merely because the shell-mode flag is a function parameter;
- preserves an unverified candidate when tainted command data reaches a subprocess call whose shell mode is dynamic;
- keeps a constant command with only a dynamic shell flag negative in this heuristic test.

## Evidence

- Test-first commit `b1418146b88ca38d66d4c536f41359c34315517d`: the new keyword-argument regression test failed in CI, confirming the pre-patch false negative. Run: [40663651942](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40663651942).
- Fix commit `09be759843dfdfe3be099c053a3b655f50dee904`: **29/29 targeted D2.4H tests passed**, including the keyword-argument case. Run: [40663669903](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40663669903).
- Adversarial extension commit `0f912bb15fd9b88952e161f55834b974e9fdd21e`: the new dynamic-mode tests failed before the corresponding fix. Run: [40663776637](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40663776637).
- Final dynamic-mode code commit `a7e2b36dc9da13931b85b5d02d0185b1dc55d42e`: **31/31 targeted D2.4H tests passed**. Run: [40663816999](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40663816999).
- Import-alias test-first commit `0d0bf89ea931d062cfb7f294c4c5b3c3a007e319`: the new aliased-call test failed before the corresponding fix. Run: [40663940306](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40663940306).
- Current code commit `3877a2fc27d2b006b46cb5637fd84afcb3e461fa`: **32/32 targeted D2.4H tests passed**, including `import subprocess as sp`. Run: [40663967694](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40663967694).

The test-first failures are intentional evidence of a pre-existing blind spot, not failed final validation. The passing workflow also reran the existing bounded source-analysis checks and preserved the explicit outcome `verified_novel_issues = 0`. The full repository regression workflow was then enabled on this research branch and passed **285/285 Python tests**, plus the synthetic policy comparison and decision-equivalence benchmark: [run 40664135766](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40664135766).

## Scope and scientific interpretation

This is a narrow, demonstrated reduction in three syntactic false-negative/uncertainty cases: keyword command arguments, dynamic shell mode, and a simple module-level import alias. It is **not** a sound taint analysis, interprocedural analysis, exploit, real-world vulnerability, new vulnerability class, zero-day, or evidence of scientific superiority. The compiler remains heuristic and function-local; local aliases of command data, function-local imports, dynamic dispatch, branch-sensitive values, cross-module data flow, and unrecognized APIs can still be missed or misclassified.

The existing historical Starlette/Werkzeug experiments remain researcher-selected, not blind. No novelty or generalization claim follows from this patch.

## Next highest-value work

1. Add conservative local-data-alias and branch-sensitive data-flow tests, while explicitly abstaining where semantics cannot be resolved.
2. Compare candidate generation with a strong baseline (at minimum Semgrep rules and a simple AST/data-flow baseline) on the same frozen inputs and resource budget.
3. Freeze engine and scoring before an independent selector supplies fresh holdouts; keep labels and patch history hidden until the run finishes.
4. Record all false negatives and false positives by root cause. Do not equate a candidate with a violation or a passing test suite with a confirmed vulnerability.
