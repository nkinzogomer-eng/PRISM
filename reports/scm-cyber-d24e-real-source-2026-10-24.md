# SCM / PRISM D2.4E — real-source cyber analysis across Python and Solidity

**Executed 24 October 2026. Engineering PASS. Prospective/independent discovery superiority: NOT DEMONSTRATED.**

## Immutable, direct evidence

- [Final successful GitHub Actions run 40108846917](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40108846917), tested code commit `a98cd01c862eb0cdf3cbdfe03b52b1f53edbb18a`.
- Draft [PR #31](https://github.com/nkinzogomer-eng/PRISM/pull/31), based on the D2.4D experimental branch; no edits or merges into main.
- External source A: `pallets/werkzeug` commit `6c4c680f5392342a68065114987f39160388064c`, real Python module `src/werkzeug/security.py`.
- External source B: `scfuzzbench/origin-dollar-scfuzzbench` commit `299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4`, real Solidity OUSD source and pinned Foundry v1.3.6.
- Both checkouts assert exactly the pinned 40-character SHA. The full JSON includes actual source SHA-256 and CPU/wall evidence. Archive: workflow artifact `d24e-two-independent-real-source-verification`.
- 19 adversarial/unit Python tests pass, including a separately implemented *cached classical AST callgraph* baseline. All source-extraction comparisons against that baseline pass.

## Measured scope

| Source and security task | Actual local functions | Source-dependent frontier | Excluded (count, not safely pruned semantics) |
|---|---:|---:|---:|
| Werkzeug Python path handling | 4 | 1 | 3 |
| Werkzeug Python password verification | 4 | 2 | 2 |
| OUSD Solidity delegated transfer/allowances | 32 | 11 | 21 |
| OUSD Solidity token supply operations | 32 | 12 | 20 |

Only direct local syntactic dependencies are extracted. Unresolved imported/method/dynamic calls retain explicit UNKNOWN status. This is NOT a sound source slice or a cross-contract security proof. Counts are not vulnerability recall or wall-time savings.

## Runtime and falsification evidence

- Real third-party Werkzeug `safe_join` executed (without a server) for seven safe/path-boundary inputs; all 7 outcomes agreed with an independent POSIX lexical containment oracle. This oracle deliberately excludes symlinks, filesystem authorization, Windows details, and realistic web-layer encoding.
- A *deliberate memory-only source mutation* removing an ordinary parent-directory guard resulted in unsafe lexical outcomes for **three predetermined control inputs**. The real source file was not edited. This is ONE artificially introduced defect, NOT three third-party vulnerabilities.
- Following initial real-source execution, an exploratory additional AST frontend extracted **two** literal startswith conditions from the independently pinned source, supplying candidate verification inputs. The results are explicitly **post-preflight exploratory**, not a sealed discovery or preregistered blind experiment; this use is known traditional AST pattern matching.
- Actual unchanged OUSD compiled; the **six** D2.4C real EVM test executions succeeded again, including matched independent Foundry fuzz properties and deeper stateful invariants. The same deliberately introduced missing allowance-debit mutation was detected by the generated test, the independently authored Foundry test, and the stateful Foundry handler (**3/3 comparators**). No distinct real protocol vulnerability was discovered.
- Programmatic property candidates remain conventional manual ERC20 rules for Solidity. The Python generator does not invent complete new security invariants; it only extracts obvious lexical rejection-guard seeds.

## Independent competitor and negative scientific result

Unlike comparing against a deliberately expensive full-file scan, D2.4E includes a classical reference Python analyzer that parses the real source **once**, caches local-call edges and does conventional BFS for every target root. The PRISM frontend's closures **match** that properly configured baseline on real Werkzeug code. No distinctive source-selection or semantic capability is measured beyond conventional AST callgraph traversal.

Even if the Python selector reports 1 of 4 functions, or the Solidity selector 11 of 32, it is incorrect to describe that as *SCM superior to state-of-the-art*. No independent new root cause has been confirmed and no real-scale matched-time competitor suite exists. D2.4D also previously found the SCM state quotient tied conventional slicing; negative results remain public.

## Remaining causal bottlenecks and precise next requirements

1. Real cross-file and language-semantic modeling (storage aliasing, heap side effects, decorators, inheritance, delegatecalls, EVM call context, exception paths and dynamic dispatch) that can fail closed.
2. Derive **behavioral security properties** from third-party source/specifications without encoding specific known bug labels; preserve distinctions between fact, hypothesis, observed runtime witness and confirmed root cause.
3. Combine SCM's decision frontier and proof constraints with genuinely novel selection/ranking under an equal full-cost budget, **ablate the contribution against well-configured classical program slicing, coverage-guided fuzzing and symbolic/concolic tools**.
4. Predeclare independent target holdout and root-cause evaluation, expose TP/FP/FN/UNKNOWN where eligible, proof replay, median/dispersion, human authoring cost, and time-to-confirmation. Never claim universal speed or 80%-90% bug discovery without these results.

**Decision: GO to develop conservative source-to-effects verification; NO-GO to scientific-superiority announcement or main-branch merge.**
