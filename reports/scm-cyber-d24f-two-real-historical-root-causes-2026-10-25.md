# SCM / PRISM D2.4F — two genuine historical third-party root-cause proofs

**25 October 2026. Engineering result: PASS. 2 independently published historical root causes reproduced; NO new vulnerability independently discovered; NO scientific general superiority established.**

## Immutable execution evidence

- [Successful final GitHub Actions run 40199373166](https://github.com/nkinzogomer-eng/PRISM/actions/runs/40199373166), tested **code commit `d7ed3c6979cb4a2f54fee4401256c0d5ea3d42e9`**.
- [Draft PR #32](https://github.com/nkinzogomer-eng/PRISM/pull/32) on isolated branch `research/scm-cyber-d24f-real-regression-proof`, targeting previous experimental D2.4E branch; `main` not changed.
- All **18** adversarial/unit tests passed. CI checked out **four real third-party commits at pinned SHAs**.
- CI artifact `d24f-historical-real-werkzeug-proof` includes full before/after observed outcomes for both projects, immutable upstream source SHA-256, two deterministic replay SHA-256 digests, historical regression witnesses, minimal inputs, timing/resource traces, and **`delivery-summary.json`**.
- Consolidated proof digest `146d46fa5346bfe4c207ff8a9e743ceb6b1cd9d47c653644c9767f5c89bc4f53`.

## Two real security regression root causes (publicly known; not new discovery)

| Project | Historical cause | Before source | Patched source | Executed inputs | Confirmed before/after witness inputs | Minimum witness |
|---|---|---|---|---:|---:|---|
| Werkzeug | CVE-2026-27199: multi-segment Windows device names | 3.1.5 `e3d06f4b1f7ff40a63eba78f81d9cda18f805d6d` | 3.1.6 `04da1b5221b7a7b57e82246e4b5741d37a6b2e56` | 17 | 8 | `docs/AUX` |
| Starlette | CVE-2023-29159: textual sibling directory prefix treated as permitted path | 0.26.1 `8965f8849977b5752e415722a83aa00049f80ff3` | 0.27.0 `0c4b68ac4e179a788e38bac28f299dcad0f36e99` | 6 | 3 | `../public2.txt` |

**Counts:** exactly **2 distinct historical root causes across 2 separate external projects**, 23 behavioral inputs, 11 source-revision witnesses. Those 11 do **not** mean 11 distinct flaws. They come from source-derived input family expansions for two previously disclosed vulnerabilities.

### Werkzeug proof

- Executed actual upstream `safe_join` functions from both full Python module sources in separate loaded namespaces. Only the function-local globals emulate the Windows environment (`ntpath`, `os.name`, alt separators), never process-global `os.name`.
- Candidate generation takes device symbols from the genuine older source and combines them with generic nested path templates, plus benign and ordinary `../` controls. Labels and patch differences are **not generator inputs**.
- Eight nested device-name strings were accepted in 3.1.5 and rejected in 3.1.6. Both versions agreed on benign paths and direct device or ordinary traversal controls.
- **Limit:** This establishes an actual third-party Python method's behavior under Windows-like globals on Linux. It does not open an OS device, reproduce a Windows hang, or prove network exploitability on a real Windows host.

### Starlette proof

- Extracted the original AST of `StaticFiles.lookup_path` from each independently pinned upstream file. The exact method body executes against actual isolated temporary directories/files, including existing sibling files with names sharing a textual directory prefix.
- Three such sibling inputs returned existing neighboring files before the fix, and were rejected by the corrected method. Ordinary files in the allowed directory remain accessible. No HTTP server was started, and no unrelated files were accessed.
- **Limit:** The experiment executes the security-critical original method, not a deployed Starlette web stack; network behavior, middleware and request decoding are out of scope.

## Actual delivered software capability

1. `prism/cyber_proof.py`: reusable property-specific behavioral before/after verification, exact observations, deterministic replay SHA, witness ordering, no default SAFE/novelty inference.
2. `scripts/d24f_historical_real_regression.py`: source-derived Windows device-name input generator and real-module method adapter.
3. `scripts/d24f_starlette_real_regression.py`: real filesystem invariant with original upstream Python AST body and temporary-file witness replay.
4. `scripts/d24f_delivery.py`: fail-closed consolidated machine-readable `delivery-summary.json` that counts distinct root causes, refuses missing proofs and explicitly records `novel_cves_discovered: 0`.
5. GitHub Actions pinned four third-party source commits, verifies both fixes, retains auditable raw provenance and resources. No paid APIs or external language model required.

## Scientific and production limits

- The projects and historical vulnerabilities were selected **with the publicly known security issue in mind**. The generator does not access the vulnerability label, but this is **not a sealed prospective holdout**.
- Result is a real historical **behavioral regression reproduction**, not an autonomously discovered unknown vulnerability, not 2 zero-days, and not a general web app or DeFi exploit engine.
- Scope is two Python library security components; the same proof kernel is domain-neutral, but EVM/native adapters have not yet been validated against a historical independent cause. D2.4C/D2.4E real OUSD EVM tests remain separately green.
- The very short measured Python verification times (~0.04s Werkzeug and ~0.0039s Starlette for the last workflow), exclude checkout/setup/human property design and have no matched competing baseline. They cannot substantiate a 29–50× acceleration or 80% reduction in total cost.
- The fixed revisions were the adjudication oracle. A historical witness is not evidence that a current project has a vulnerability.

## Next high-value build target

**Do not add another synthetic breadth benchmark.** Integrate independent historical Solidity accounting flaws and native/web auth regressions as real execution adapters to the proof core. Then add cross-module source semantics and generate candidates without issue-specific labels. Freeze a holdout of independently authored source revisions, verify candidate root causes with the revised program, prioritize first true external findings, and measure end-to-end compute/verification cost once repeatable. The scientific requirement remains an additional observed gain on novel third-party cases, not another green self-test.

**Decision:** KEEP D2.4F as a reproducible product-building milestone; keep PR #32 draft and `main` untouched pending integration review.
