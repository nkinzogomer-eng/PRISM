# PRISM D2.5 — Validation charter

**Track:** D2.5 (domain target: modular smart-contract accounts)
**Charter version:** 1.0
**Opened:** 2026-10-30
**Stage covered by this document:** Stage 1 — target validation only
**Status:** Stage 1 complete for the primary candidate. Verdict recorded in
[§11](#11-stage-1-exit-gates-and-verdict).

> This charter governs validation work. It is **not** a result in the PRISM
> scientific sense. Passing Stage 1 means "this target can be built, tested and
> studied reproducibly". It says nothing about whether PRISM's hypotheses hold on
> the target.

## 1. Purpose

D2.5 asks whether a real, audited, modular smart-contract account can serve as a
concrete domain target for PRISM's decision-sufficiency machinery: a system where
hidden distinctions, expensive observations, and abstention decisions are
genuine rather than synthetic.

Before any mechanism is designed, the target itself must be proven to be a usable
laboratory: exact identity, pinned toolchain, locked dependencies, clean
compilation, passing reference tests, and no entanglement with earlier PRISM
work.

This document is the controlling record for that validation. It contains every
command, version, error, and result produced during Stage 1.

## 2. Stage 1 scope and prohibitions

In scope:

1. obtain the target at one exact commit;
2. verify the Foundry/Solidity environment;
3. install and lock dependencies;
4. perform a clean compilation;
5. execute the reference test suite;
6. check for problematic overlap with earlier PRISM experiments;
7. record everything in this charter.

Out of scope and explicitly prohibited during Stage 1:

| Prohibition | Meaning in practice |
| --- | --- |
| No source modification | The target checkout is read-only in intent. No file under `src/`, `test/`, `script/`, `gas/`, `foundry.toml`, or any library is edited. Only build outputs (`out/`, `cache/`), generated lock/state directories, and data under `node_modules/`, `lib/` (git submodules) are produced. |
| No new mechanism | No PRISM adapter, hypothesis encoding, harness, or experiment is written in Stage 1. |
| No real chain | No RPC endpoint, no fork URL, no key, no transaction, no signature against a live network. All execution is local against the in-process EVM used by Foundry tests. |
| No claim inflation | Test success is not evidence for H-SCM-1 or any PRISM scientific claim. |

The target repository is checked out **outside** the PRISM repository, at
`~/.cache/prism-d25/target/target`, and is never vendored, committed, or
submoduled into PRISM.

## 3. Target identity

| Field | Value |
| --- | --- |
| Repository | `https://github.com/alchemyplatform/modular-account` |
| Requested revision | `bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482` |
| Resolved `HEAD` | `bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482` (identical) |
| Tree object | `30281664d0cf68eef171ebe5c7d230afe6ef70c8` |
| Exact tag | `v2.0.0` (`git describe --tags --exact-match` → `v2.0.0`) |
| Commit date | 2024-12-20T15:59:17Z |
| Commit subject | `feat: add v2.0.0 deployments (#327)` |
| Commit author | Adam Egyed |
| Standards | ERC-4337 and ERC-6900 compatible smart account |
| Audits present at this commit | Spearbit (2024-01-31, `0e3fd1e`), Quantstamp (2024-02-19, `0e3fd1e`), ChainLight (2024-12-03, `14afcd8`), Quantstamp (2024-12-11, `14afcd8`) |
| Source scale | 31 `.sol` files in `src/`, 74 in `test/`, 5 in `script/`, plus `gas/` |

**Identity finding:** the requested commit is exactly the commit tagged `v2.0.0`.
The repository `README` still carries a "branch under development" warning, so
the tag — not the branch head — is the valid identity anchor. Later tags
(`v2.0.1`, `v2.0.2`) also contain this commit, which confirms it is an ancestor
of them and therefore not a moving target.

Verification command:

```bash
git clone https://github.com/alchemyplatform/modular-account.git target
cd target
git checkout bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482
git rev-parse HEAD            # bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482
git rev-parse HEAD^{tree}     # 30281664d0cf68eef171ebe5c7d230afe6ef70c8
git describe --tags --exact-match
git submodule update --init --recursive --depth 1
```

## 4. Environment profile

| Property | Value |
| --- | --- |
| OS | Debian GNU/Linux 12 (bookworm), x86_64 |
| CPU | 2 vCPU |
| RAM | 3.9 GiB total |
| Disk | 20 GiB available on `/` |
| GPU | none |
| Network | outbound HTTPS to `github.com`, `codeload.github.com`, `api.github.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org` only; SSH (port 22) and `binaries.soliditylang.org` unreachable |

This profile respects the Phase 0 "ordinary hardware" constraint: the target
builds and tests on a 2-vCPU, 4-GiB machine with no GPU.

## 5. Toolchain pinning

The target pins its compiler (`solc = '0.8.26'`, `auto_detect_solc = false`) but
its own CI does **not** pin Foundry: `.github/workflows/setup-ci/action.yml`
uses `foundry-rs/foundry-toolchain@v1` with `version: nightly`. That is a
reproducibility gap inherited from the target and is recorded here as such.

Stage 1 pins every tool explicitly:

| Tool | Version | Source | Rationale |
| --- | --- | --- | --- |
| forge | 1.7.1 (commit `4072e48705af9d93e3c0f6e29e93b5e9a40caed8`) | npm `@foundry-rs/forge@1.7.1` | GitHub release assets are blocked in this sandbox; the npm distribution ships the same binary toolchain. |
| solc | 0.8.26+commit.8a97fa7a (native Linux x86-64) | `ethereum/solc-bin` git repository, `linux-amd64/solc-linux-amd64-v0.8.26+commit.8a97fa7a` | Exact compiler required by `foundry.toml`. SHA-256 verified against the repository's own `list.json` manifest. |
| solc SHA-256 | `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef` | `linux-amd64/list.json` | Manifest and computed digest agree. |
| pnpm | 9.15.0 | npm | Matches the target's `devDependencies` (`pnpm ^9.15.0`) and `lockfileVersion: '9.0'`. |
| node | v22.22.3 | sandbox image | Sufficient for pnpm 9 and the repo scripts. |
| npm | 10.9.8 | sandbox image | Used only to bootstrap forge, solc and pnpm. |
| git | 2.39.5 | sandbox image | Clone, submodule pinning, identity checks. |
| python | 3.11.2 | sandbox image | PRISM-side regression check only. |

Installation commands actually executed:

```bash
# forge (binary distribution via npm)
npm install --no-audit --no-fund --prefix ~/.cache/prism-d25/tools/foundry @foundry-rs/forge@1.7.1
ln -sf ~/.cache/prism-d25/tools/foundry/node_modules/@foundry-rs/forge-linux-amd64/bin/forge \
       ~/.cache/prism-d25/bin/forge
forge --version    # forge 1.7.1, commit 4072e48705af9d93e3c0f6e29e93b5e9a40caed8

# pnpm (lockfile-compatible)
npm install -g --prefix ~/.npm-global pnpm@9.15.0
pnpm --version     # 9.15.0

# solc 0.8.26 (native binary, checksum-verified)
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/ethereum/solc-bin.git solc-bin
cd solc-bin && git sparse-checkout init --cone && git sparse-checkout set linux-amd64 && git checkout
sha256sum linux-amd64/solc-linux-amd64-v0.8.26+commit.8a97fa7a
mkdir -p ~/.svm/0.8.26
cp linux-amd64/solc-linux-amd64-v0.8.26+commit.8a97fa7a ~/.svm/0.8.26/solc-0.8.26
chmod +x ~/.svm/0.8.26/solc-0.8.26
~/.svm/0.8.26/solc-0.8.26 --version   # 0.8.26+commit.8a97fa7a.Linux.g++
```

`~/.svm/0.8.26/solc-0.8.26` is the path forge/svm uses for compiler version
0.8.26; installing an exact-version binary there prevents any network download
at build time.

## 6. Dependency locking

### 6.1 Git submodules (Foundry libraries)

Pinned by the target's own gitlinks; `git submodule update --init --recursive`
converges to these commits:

| Path | Commit |
| --- | --- |
| `lib/forge-std` | `1eea5bae12ae557d589f9f0f0edae2faa47cb262` |
| `lib/light-account` | `dd4187d1d50751cd2b7a6d6079d87c3114b32f98` |
| `lib/openzeppelin-contracts` | `dbb6104ce834628e473d2173bbc9d47f81a9eec3` |
| `lib/webauthn-sol` | `619f20ab0f074fef41066ee4ab24849a913263b2` (`v1.0.0`) |
| `lib/webauthn-sol/lib/FreshCryptoLib` | `76f3f135b7b27d2aa519f265b56bfc49a2573ab5` |
| `lib/webauthn-sol/lib/openzeppelin-contracts` | `5705e8208bc92cd82c7bcdfeac8dbc7377767d96` |

**Structural finding:** the submodule graph is *cyclic and self-recursing*:
`lib/light-account` pins `lib/modular-account`, which pins `lib/light-account`
again, and so on. Deep recursion produces duplicated nested copies. Two
recursive passes with `--depth 1` converge to zero uninitialised submodules and
are sufficient for compilation; no attempt is made to follow the cycle to
infinity. This is a property of the target, not a defect introduced here.

### 6.2 Node dependencies

Installed with the target's committed lockfile, frozen:

```bash
cd target
pnpm install --frozen-lockfile        # "Lockfile is up to date, resolution step is skipped"
```

* 469 packages installed, `node_modules` 361 MB.
* GitHub-resolved dependencies (exact commits taken from `pnpm-lock.yaml`):
  * `account-abstraction` `github:eth-infinitism/account-abstraction#v0.7.0` → `d99245ddb2d7bde4d2132757c4394818f1d11da0`
  * `solady` `github:Vectorized/solady#v0.0.237` → `eb227ea1c5eaa56296e7dd713eb165d5d75891dd`
  * `@erc6900/reference-implementation` `github:erc6900/reference-implementation#v0.8.0` → `c9b256cfd963a655179fa3cd9ea3f92c73cbfcdd`
* File digests recorded for later re-verification:

| File | SHA-256 |
| --- | --- |
| `foundry.toml` | `68d45ac69adbefc48b650d2c9e6aa6d3e8881f9ba0bb536ab46b134b25ba900e` |
| `remappings.txt` | `896261b0f2cd10e56e6730e5e649b14f51671dbfc05ff13d92441bde11f1fcc9` |
| `package.json` | `348b4762c7a1bc0bee80db60671417b7301dd78a7d32c7ae0b4a70f81bfdd509` |
| `pnpm-lock.yaml` | `341034de48548df888d9531662c21e8eda958fb6c4ed7259ad55d4b5accc0bd0` |
| `.gitmodules` | `0b5d79018b2d9da1ccdf09dcf132f84c5a9cdaf2d37dec324682ef1acf3e036f` |

Environment-level deviations required to make these locks resolvable (recorded
as environment, not target, issues):

* `git config --global url."https://github.com/".insteadOf` for
  `ssh://git@github.com/`, `git@github.com:` and `git://github.com/` — the
  lockfile records git-protocol specs and SSH egress is blocked in the sandbox.
* `NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt` — Node's bundled
  trust store does not include the sandbox TLS interception CA, so tarball
  fetches from `codeload.github.com` failed with
  `UNABLE_TO_VERIFY_LEAF_SIGNATURE`.

Neither change alters dependency content; both were required for the *same*
pinned resolutions to be fetched.

## 7. Stage 1 protocol (commands in execution order)

```bash
# 0. toolchain (see §5) then:
cd ~/.cache/prism-d25/target/target

# 1. identity
git rev-parse HEAD && git rev-parse HEAD^{tree} && git describe --tags --exact-match
git status --porcelain            # must be empty

# 2. dependencies
git submodule update --init --recursive --depth 1
pnpm install --frozen-lockfile

# 3. clean compile (target's default profile, the CI "Build project" step)
forge clean
forge build

# 4. reproducibility of compilation (twice, from clean)
forge clean && forge build
forge clean && forge build
( cd out && find . -name '*.json' | sort | xargs sha256sum ) > manifest-<n>.txt

# 5. reference test suite (CI "Run tests" step, default profile)
forge test

# 6. second run with a fixed fuzz seed (flakiness check)
FOUNDRY_FUZZ_SEED=20261030 forge test

# 7. target's second CI job (via-IR / deep profile)
FOUNDRY_PROFILE=optimized-build forge build
FOUNDRY_PROFILE=optimized-test-deep forge test

# 8. PRISM-side regression (unchanged baseline)
cd /home/user/PRISM && python3 -m unittest discover -s tests
```

Verbosity is left at the target CI's default (`forge test`, and `-vvv` is not
needed to decide pass/fail). All runs are local: no `--fork-url`, no
`--rpc-url`, no `--broadcast`.

## 8. Stage 1 results

### 8.1 Clean compilation — default profile

| Metric | Value |
| --- | --- |
| Command | `forge clean && forge build` |
| Files compiled | 228 (31 `src/`, 74 `test/`, 5 `script/`, plus dependencies) |
| Compiler | solc 0.8.26+commit.8a97fa7a |
| Wall time | 31.72 s (first clean run) / 47 s and 48 s in the two-run determinism check under CPU contention |
| Exit status | 0 |
| Solidity errors | 0 |
| Solidity warnings | 0 |
| `forge-lint` advisory notes | 148 (newer Foundry linter; informational in the default profile) |
| Artifacts produced | 232 JSON files, 25 MB |

### 8.2 Compilation determinism

Two consecutive clean builds **in the same checkout path** produced
byte-identical artifact sets:

* 232 artifacts each;
* identical `sha256sum` manifest digest in both runs
  (`24b189ed4e24886dffbd03c78dca85de07d9ff5e6295bfd11244a4d245dc1325`);
* full manifest stored in [`reports/d25-step1/artifacts.sha256`](../reports/d25-step1/artifacts.sha256).

`bytecode_hash = "none"` in `foundry.toml` keeps metadata out of the bytecode,
which is what makes this byte-level comparison meaningful.

**Path sensitivity (measured, not assumed).** The validation script was then run
end-to-end in a *second* work directory. There, 231 of the 232 artifacts are
byte-identical to the first location, including every contract artifact. The only
difference is `out/build-info/<id>.json`, whose sole varying field is its `id`
(and therefore its filename): the build id is derived from the build context
(paths), not from compiled output. Consequence for later stages: artifact hashes
are comparable **within a path**, and cross-machine comparisons must exclude —
or normalise — `build-info`.

### 8.3 Reference test suite — default profile

| Run | Command | Suites | Tests | Passed | Failed | Skipped | Time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A | `forge test` | 46 | 292 | 292 | 0 | 0 | 18.53 s |
| B | `FOUNDRY_FUZZ_SEED=20261030 forge test` | 46 | 292 | 292 | 0 | 0 | 20.14 s |

Fuzz and invariant budgets are the target's own (`[fuzz] runs = 500`,
`[invariant] runs = 500, depth = 10`). Observed fuzz runs per property: 500.

### 8.4 Target's second CI job (optimized / via-IR)

| Step | Command | Result |
| --- | --- | --- |
| Build | `FOUNDRY_PROFILE=optimized-build forge build` | **Fails at the lint gate**, not at compilation: `Compiling 118 files`, `Solc 0.8.26 finished in 58.62 s`, `Compiler run successful!`, then `Error: Lint failed — aborting due to 45 linter warning(s)` |
| Build (with narrow override) | `FOUNDRY_PROFILE=optimized-build forge build -D never` | Exit 0, 118 files, 58.62 s, `Compiler run successful!` |
| Deep test | `FOUNDRY_PROFILE=optimized-test-deep forge test -D never` | Exit 0: 46 suites, 292 tests passed, 0 failed, 0 skipped, 428.82 s of test time (460 s including compilation) |

The failure is caused by **Foundry version drift**, not by the target: the
profile sets `deny_warnings = true`, which in Foundry 1.7.1 also arms the
built-in linter (a component that did not exist in the nightly used by the
target's CI in December 2024). `-D never` disables only that diagnostic gate; it
does not change compilation settings (`via_ir`, `optimizer_runs = 50000`),
sources, or bytecode.

### 8.5 Deep profile test (fuzz 10 000, invariant 5 000 × depth 32)

| Metric | Value |
| --- | --- |
| Command | `FOUNDRY_PROFILE=optimized-test-deep forge test -D never` |
| Suites / tests | 46 / 292 |
| Passed / failed / skipped | 292 / 0 / 0 |
| Test time | 428.82 s (812.82 s CPU time) |
| Total wall time including via-IR compilation | 460 s |
| Exit status | 0 |

This profile is *supplementary*: it is the target's own stress profile, not the
reference suite used to decide Stage 1. It confirms that the 292-test suite also
passes with 20× the fuzz budget and 10× the invariant depth, on 2 vCPUs, within
about eight minutes.

### 8.6 Target integrity after the run

```text
git status --porcelain   -> empty
git diff --stat          -> empty
```

No tracked file in the target changes during Stage 1. Only `out/`, `cache/`,
`out-optimized/`, `cache-optimized/`, `node_modules/` and submodule checkouts are
created, all of which the target's `.gitignore` already covers.

### 8.7 No-chain confirmation

* `foundry.toml` contains no `rpc_endpoints`/fork configuration.
* No test or script reads an RPC URL or a private key: the only environment
  variable read anywhere in `test/`/`src/` is `vm.envOr("FOUNDRY_PROFILE", ...)`
  in `test/utils/OptimizedTest.sol`.
* Every command ran with default (non-fork) execution.
* The `broadcast/` directory contains historical deployment broadcast records
  that were read as data only; nothing was broadcast.

## 9. Error and incident log

Each entry: symptom → root cause → resolution → classification.

| # | Symptom | Root cause | Resolution | Class |
| --- | --- | --- | --- | --- |
| E1 | `curl` to `release-assets.githubusercontent.com` and `binaries.soliditylang.org` fails (`SSL_ERROR_SYSCALL`, connection refused) | Sandbox egress allowlist excludes GitHub release assets and Solidy's binary host | Install forge from npm; obtain solc from the `ethereum/solc-bin` git repository over HTTPS | Environment |
| E2 | `pnpm install` fails: `git clone git@github.com:...` → `Connection closed by remote host port 22` | Lockfile records git specs that pnpm rewrites to SSH; SSH egress blocked | `git config --global url."https://github.com/".insteadOf` for the three git URL forms | Environment |
| E3 | `pnpm install` warns `UNABLE_TO_VERIFY_LEAF_SIGNATURE` on `codeload.github.com` | Node's bundled CA store lacks the sandbox interception CA (`curl`, which uses the system store, succeeded) | `NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt` | Environment |
| E4 | First solc attempt: `Error: Broken pipe (os error 32)` | `forge` passes `--allow-paths <csv>`; the Emscripten CLI (`solcjs`) rejects that flag and exits before reading stdin | Wrapper of §5 that drops `--allow-paths` and its value (the flag only affects the import callback, unused because forge embeds all sources) | Environment |
| E5 | `solcjs` standard-JSON output unparseable | `solcjs` prints `>>> Cannot retry compilation with SMT ...` to **stdout** before the JSON body | Strip `^>>> ` lines from stdout in the wrapper | Environment |
| E6 | `Error: EAGAIN: resource temporarily unavailable, read` in `solcjs` | forge hands the compiler a non-blocking stdin pipe; `solcjs` performs a synchronous `read(2)` and dies | Spool stdin to a regular file before invoking `solcjs` | Environment |
| E7 | `RuntimeError: memory access out of bounds` from `solcjs` on large payloads (first observed at ~136 sources; deterministic for the full 228-file payload; each file compiles alone) | Emscripten build instability on large standard-JSON payloads in this sandbox; not reproducible with the native compiler | Abandon `solcjs` as final path; install the **native** solc 0.8.26 from `ethereum/solc-bin` with SHA-256 verification. Full build then succeeds with zero errors | Environment |
| E8 | `FOUNDRY_PROFILE=optimized-build forge build` → `Error: Lint failed — 45 linter warning(s)` | Foundry 1.7.1 folds `deny_warnings = true` into its new linter; target CI in Dec 2024 used a nightly without a linter | Re-run with `-D never` (documented above); compilation itself succeeded in both cases | Environment / toolchain drift |
| E9 | `forge` submodule recursion reports `fatal: failed to recurse into submodule` on the first pass | Cyclic submodule graph (`light-account` ↔ `modular-account`) | Second recursive pass converges; documented as a target property | Target property |

No incident was caused by a defect in the target's own source code, and no
incident required modifying the target.

## 10. Overlap analysis with earlier PRISM work

Earlier PRISM work (Phases 0–3) is a Python 3.12 standard-library codebase
(`prism/`, `scripts/`, `tests/`, ~53 tests) that studies named synthetic causal
models. A full-text search of the repository for `alchemy`, `rhinestone`,
`solidity`, `foundry`, `4337`, `ERC-6900`, `modular account`, `D2.5` returns
**zero** matches outside this charter. Concretely:

| Dimension | Earlier PRISM work | D2.5 Stage 1 | Overlap |
| --- | --- | --- | --- |
| Language / runtime | Python 3.12, stdlib only | Solidity 0.8.26, Node 22, pnpm, Rust-built `forge` | None |
| Dependencies | none outside the standard library | 469 npm packages + 4 recursive git submodules | None |
| Repository footprint | `prism/`, `scripts/`, `tests/`, `docs/`, `reports/` | target kept outside the repository in `~/.cache/prism-d25/` | None by construction |
| CI | `.github/workflows/tests.yml`: Python unittest + two synthetic benchmarks | none added; no new CI job, no new Python dependency | None |
| Data / artefacts | synthetic finite models, seeded seeds 0–99 | compiled bytecode, artifact hashes, test logs | None |
| Scientific claim | H-SCM-1 (unproven) | none: Stage 1 makes no scientific claim | None |

Residual risks that *are* real, and how they are contained:

1. **Evidence conflation.** A passing Solidity test suite is a strong baseline,
   not a PRISM gain. Stage 1 therefore records no PRISM metric. Any later claim
   must compare against this suite as a *baseline*, never as a PRISM result.
2. **Toolchain weight.** D2.5 introduces ~1.3 GB of tooling and a 700 MB target
   checkout. This stays outside the repository and outside CI, preserving the
   Phase 0 "ordinary hardware" and "no required external service" constraints
   for the PRISM core.
3. **Scope creep into Phase 4.** PRISM Phase 4 is authorized red/blue cyber
   testing. D2.5 is *not* that: it is a smart-contract domain target for
   decision-sufficiency experiments. Stage 1 does not perform any offensive or
   defensive security testing, and the phase register remains unchanged.
4. **Version drift of the target.** The tag pins the target, but the target's own
   CI uses an unpinned Foundry nightly; findings must therefore always cite the
   toolchain of §5, not "the target's CI".
5. **Private-key / RPC contamination.** none possible: no key material, no RPC
   configuration, no fork mode was used or created.

**Conclusion for Stage 1 gate 6:** no problematic overlap. The D2.5 track is
additive and isolated; the existing PRISM test suite still passes unchanged
(53 tests, `OK (expected failures=1)`).

## 11. Stage 1 exit gates and verdict

| # | Gate | Requirement | Result |
| --- | --- | --- | --- |
| G1 | Exact revision | HEAD equals the requested commit | **Pass** — `bd75c9e…`, tree `3028166…`, tag `v2.0.0` |
| G2 | Environment verified | Compiler and Foundry versions known, pinned, checksum-verified | **Pass** — solc 0.8.26 native, SHA-256 `d5f234…`; forge 1.7.1 |
| G3 | Dependencies locked | Submodules and Node packages resolved to exact commits | **Pass** — frozen lockfile, 469 packages, all SHAs recorded |
| G4 | Clean compilation | Full build from clean, zero errors | **Pass** — 228 files, 31.72 s, 0 errors, 0 warnings; artifacts byte-identical across two clean builds in the same path |
| G5 | Reference tests | Target's reference suite passes | **Pass** — 292/292 tests, 46 suites, twice (default and fixed-seed) |
| G6 | No harmful overlap | No code, dependency, CI or claim collision with earlier PRISM work | **Pass** — zero references; PRISM suite unchanged (53 tests OK) |
| G7 | No source modification | Target tree unmodified | **Pass** — `git status` and `git diff` empty |
| G8 | No real chain | No network interaction | **Pass** — no RPC/fork/broadcast anywhere |
| G9 | Documentation | Commands, versions, errors, results recorded | **Pass** — this charter + Stage 1 report |

### Verdict

**The target is VALIDATED for Stage 1.**

Alchemy Modular Account `v2.0.0`
(`bd75c9eca7ff5a66aaebc3cf2dab43ddc4622482`) builds cleanly and reproducibly on
ordinary hardware, with a pinned and checksum-verified toolchain, fully locked
dependencies, and a reference suite of 292 tests passing twice. The target can
therefore serve as the D2.5 domain target.

**Rhinestone is not required as a replacement target.** The fallback is recorded
as unnecessary, with two conditions attached:

1. All later D2.5 stages must cite the toolchain of §5 and the artifact manifest
   of §8.2, not "the target's CI", because the target's CI is unpinned.
2. If a later stage needs the target's *optimized* profile as a reference, the
   `-D never` override of §8.4 must be applied and documented, since Foundry
   1.7.1's linter would otherwise reject the target's own `deny_warnings = true`
   setting.

## 12. Reproduction

A faithful re-run, from an empty cache, is scripted in
[`scripts/d25/validate_target.sh`](../scripts/d25/validate_target.sh). It:

1. installs forge 1.7.1 (npm), pnpm 9.15.0 (npm) and the checksum-verified native
   solc 0.8.26 (`ethereum/solc-bin` git repository);
2. clones the target at the exact commit and initialises submodules;
3. verifies commit, tree, tag, and an empty working tree;
4. runs `pnpm install --frozen-lockfile`;
5. runs `forge build` twice from clean and compares artifact manifests;
6. runs `forge test` twice (default and fixed seed);
7. re-verifies that the target tree is still unmodified.

The script refuses to run against a dirty target and refuses to touch the PRISM
working tree.

## 13. Limits and open risks

* **Timing numbers are sandbox timings**, measured on 2 vCPUs with `forge test`
  run concurrently with other profiling in one case. They are diagnostics, not
  benchmark results, and must not be compared to other machines.
* **Foundry 1.7.1 postdates the target.** Compilation is byte-identical to
  itself across runs, but no byte-for-byte comparison against the target's
  2024-era CI artifacts was possible (that toolchain cannot be installed here).
  Differences in artifact *content* versus December 2024 are therefore not
  excluded; only correctness (all tests pass) and internal determinism are
  established.
* **The Emscripten compiler path (E7) is documented but not used.** Any future
  stage that cannot fetch `solc-bin` over git must expect the large-payload
  `solcjs` crash and plan for chunked compilation.
* **Stage 1 does not evaluate target adequacy** for PRISM's research question
  (observability, cost structure, hidden distinctions). That is a later stage's
  decision, and this charter does not pre-commit it.
* **Audit coverage** was noted (four reports at this commit) but not read for
  correctness; nothing here relies on them.

## 14. Change control

* Gate definitions in §11 may not be relaxed after results are known. If a gate
  must change, record the change and the reason in the research log first.
* Any new deviation from the target's own CI (extra flags, different compiler,
  different Foundry) must be added to §5/§9 with its justification before the
  affected result is quoted.
* Stage 2 (mechanism design) must not begin before the Stage 1 verdict above is
  reviewed by the project owner.
