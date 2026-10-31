# PRISM D2.5 — Stage 1 target validation report

**Date:** 2026-10-30
**Track:** D2.5, Stage 1 (target validation only)
**Charter:** [PRISM D2.5 validation charter](../docs/d25-charter.md)
**Target:** Alchemy Modular Account `v2.0.0`, commit `bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482`

**Verdict: the target is validated. Rhinestone is not needed as a replacement.**

This report holds the measured record. The charter holds the definitions, the
gate criteria, and the error analysis; this file holds what was actually
observed.

## 1. Target identity (verified, not assumed)

```text
repository      https://github.com/alchemyplatform/modular-account
requested rev   bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482
git rev-parse    bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482
git rev-parse^{tree} 30281664d0cf68eef171ebe5c7d230afe6ef70c8
git describe --tags --exact-match  v2.0.0
commit date     2024-12-20T15:59:17Z
commit subject  feat: add v2.0.0 deployments (#327)
worktree state  git status --porcelain -> empty
```

The requested commit **is** the `v2.0.0` tag. `v2.0.1` and `v2.0.2` contain it,
so the revision is stable and not a moving branch head.

## 2. Environment and pinned toolchain

| Item | Observed value |
| --- | --- |
| OS / arch | Debian GNU/Linux 12 (bookworm), x86_64 |
| CPU / RAM / disk | 2 vCPU / 3.9 GiB / 20 GiB free |
| `forge` | 1.7.1, commit `4072e48705af9d93e3c0f6e29e93b5e9a40caed8`, built 2026-05-08 |
| `solc` | `0.8.26+commit.8a97fa7a.Linux.g++` (native) |
| `solc` SHA-256 | `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef` (matches `ethereum/solc-bin/linux-amd64/list.json`) |
| `pnpm` | 9.15.0 |
| `node` / `npm` | v22.22.3 / 10.9.8 |
| `git` | 2.39.5 |
| Python (PRISM regression only) | 3.11.2 |

Compiler resolution: `foundry.toml` sets `solc = '0.8.26'` with
`auto_detect_solc = false`; the native binary was placed at
`~/.svm/0.8.26/solc-0.8.26`, so no download happens at build time.

## 3. Dependency locking

```text
git submodule update --init --recursive --depth 1   -> 0 uninitialised submodules
pnpm install --frozen-lockfile                      -> "Lockfile is up to date, resolution step is skipped"
                                                      469 packages, node_modules = 361 MB
```

Direct submodule pins: `forge-std 1eea5bae`, `light-account dd4187d1`,
`openzeppelin-contracts dbb6104c`, `webauthn-sol 619f20ab` (with nested
`FreshCryptoLib 76f3f135`, `openzeppelin-contracts 5705e820`).

GitHub-resolved Node dependencies, exact commits from `pnpm-lock.yaml`:
`account-abstraction d99245dd`, `solady eb227ea1`,
`@erc6900/reference-implementation c9b256cf`.

Full lists and file digests: charter §6.

## 4. Compilation

| Run | Command | Files | Time | Exit | Errors | Warnings |
| --- | --- | --- | --- | --- | --- | --- |
| C1 | `forge clean && forge build` | 228 | 31.72 s | 0 | 0 | 0 |
| C2 | `forge clean && forge build` | 228 | 47 s | 0 | 0 | 0 |
| C3 | `forge clean && forge build` | 228 | 48 s | 0 | 0 | 0 |

C2 and C3 ran while a separate profiling job was using the CPU, which explains
the longer wall times; wall times here are diagnostics only.

**Determinism check (same checkout path).** The artifact manifests of C2 and C3
are identical:

```text
232 artifacts | manifest sha256 24b189ed4e24886dffbd03c78dca85de07d9ff5e6295bfd11244a4d245dc1325 (both runs)
manifest committed at reports/d25-step1/artifacts.sha256
```

With `bytecode_hash = "none"`, artifact bytes are metadata-free, so identity at
byte level is a genuine reproducibility signal and not a formatting artefact.

**Determinism check (different checkout path).** `scripts/d25/validate_target.sh`
was then executed end-to-end in a second, freshly cloned work directory. Result:
13/13 gates passed (228 files ×2 builds, 292/292 tests ×2), and **231 of 232
artifacts are byte-identical** to the first location. The single difference is
`out/build-info/<id>.json`, whose only varying field is the path-derived `id`
(and its filename); source inputs and settings inside it are identical.

Practical rule for later stages: compare artifact hashes within a checkout path;
when comparing across machines, exclude `build-info`.

Advisory output: 148 `forge-lint` notes (`unsafe-typecast` and similar). These
come from Foundry 1.7.1's linter, which postdates the target; they are notes, not
compiler warnings, and the default profile does not fail on them.

## 5. Reference test suite

| Run | Command | Suites | Tests | Passed | Failed | Skipped | Time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| T1 | `forge test` | 46 | 292 | 292 | 0 | 0 | 18.53 s |
| T2 | `FOUNDRY_FUZZ_SEED=20261030 forge test` | 46 | 292 | 292 | 0 | 0 | 20.14 s |

Budgets are the target's own: `[fuzz] runs = 500`, `[invariant] runs = 500,
depth = 10`. Observed fuzz runs per property: 500 for all 36 fuzz properties.

No environment variable was required to run the suite; the only environment read
in the target's `src/` and `test/` is `vm.envOr("FOUNDRY_PROFILE", "default")` in
`test/utils/OptimizedTest.sol`.

## 6. Target's second CI job (optimized / via-IR)

| Step | Command | Observed |
| --- | --- | --- |
| Build, as configured | `FOUNDRY_PROFILE=optimized-build forge build` | `Compiling 118 files`; `Solc 0.8.26 finished in 58.62 s`; `Compiler run successful!`; then `Error: Lint failed — aborting due to 45 linter warning(s)`, exit 1 |
| Build, lint gate disabled | `FOUNDRY_PROFILE=optimized-build forge build -D never` | exit 0, 118 files, 58.62 s, `Compiler run successful!` |
| Deep test | `FOUNDRY_PROFILE=optimized-test-deep forge test -D never` | exit 0 — 46 suites, 292/292 passed, 0 failed, 428.82 s (460 s wall incl. compilation) |

Cause: `deny_warnings = true` in the `optimized-build` profile. Foundry 1.7.1
maps that setting onto its built-in linter, which did not exist in the nightly
the target used in December 2024. Compilation is unaffected — only the
post-compile diagnostic gate. This is toolchain drift, not a target defect, and
it is documented so later stages do not misread it as a failing build.

Deep profile result (fuzz 10 000, invariant 5 000 × depth 32): **all 292 tests
pass**, 428.82 s of test time (812.82 s CPU time) and 460 s wall including the
via-IR compilation. The suite therefore survives a 20× fuzz budget and a 10×
invariant depth on 2 vCPUs.

## 7. Integrity and no-chain confirmation

```text
git status --porcelain   -> empty (before and after all runs)
git diff --stat          -> empty
```

Created outputs only: `out/` (25 MB), `cache/`, `out-optimized/`,
`cache-optimized/`, `node_modules/`, submodule checkouts — all covered by the
target's `.gitignore`.

No `--fork-url`, no `--rpc-url`, no `--broadcast`, no key material, no network
call to any chain. Deployment records under `broadcast/` and
`deployments/v2/Deployments.md` were read as static data only.

## 8. Overlap with earlier PRISM work

* No match anywhere in the PRISM repository for `alchemy`, `rhinestone`,
  `solidity`, `foundry`, `4337`, `ERC-6900`, `modular account` or `D2.5` before
  this work.
* PRISM core suite re-run after all target work:
  `python3 -m unittest discover -s tests` → `Ran 53 tests … OK (expected failures=1)`.
  Unchanged from the Phase 3 baseline in `docs/scm-phase-status.md`.
* No CI, dependency, or artefact overlap: the target lives in
  `~/.cache/prism-d25/` and never enters the PRISM repository or workflow.

Detailed risk discussion: charter §10.

## 9. Supplementary runs and their status

| Item | Status |
| --- | --- |
| Deep profile tests (fuzz 10 000, invariant 5 000 × depth 32) | executed — 292/292 passed, 46 suites, 428.82 s (460 s wall incl. compile) |
| Target's `gas` profile / gas snapshots | not run (requires `ffi = true`; irrelevant to Stage 1 gates) |
| Target's lint step (`pnpm lint`) | not run (Node-side linting; not a Stage 1 gate) |
| Coverage | not run (not a Stage 1 gate) |

These are deliberately excluded: Stage 1 asks whether the target compiles and
passes its reference suite reproducibly, not whether every auxiliary developer
command is green.

## 10. Deviations from the target's own CI, and why

| Deviation | Reason | Effect on results |
| --- | --- | --- |
| Foundry 1.7.1 instead of `nightly` | target CI is unpinned; release binaries are not reachable | none on compilation or tests; adds linter notes |
| Native solc 0.8.26 fetched via `ethereum/solc-bin` git instead of svm download | `binaries.soliditylang.org` unreachable | none; SHA-256 verified against the official manifest |
| pnpm in place of the target's CI pnpm 8 | target `package.json` pins `pnpm ^9.15.0`, lockfile is v9 | none; frozen lockfile respected |
| `-D never` for the optimized profiles only | Foundry 1.7.1 linter vs `deny_warnings` | compilation settings unchanged |
| `NODE_EXTRA_CA_CERTS` and `git insteadOf` rewrites | sandbox TLS interception and blocked SSH | dependency content unchanged |

## 11. What this report does not establish

* No claim about PRISM's hypotheses, gains, or cost model.
* No claim that the target's 2024-era CI produces the same bytes as Foundry
  1.7.1 here; only internal determinism and test correctness are shown.
* No security assessment of the target. The four audit reports present at this
  commit were not read for correctness and are not relied upon.
* No statement about target adequacy for PRISM's research question; that is a
  later stage's decision, made against the baselines locked here.
