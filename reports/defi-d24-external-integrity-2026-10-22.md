# D2.4 — External corpus preflight (2026-10-22)

**Engineering PASS; scientific superiority NOT established.**

The CI run https://github.com/nkinzogomer-eng/PRISM/actions/runs/39851259299 completed successfully, with 11 adversarial Python tests passed.

Three independent Solidity training samples from `SunWeb3Sec/DeFiVulnLabs` were retrieved read-only from pinned commit `f61f6ee5c3f89eb7685030647f8df19997596f8b`. Exact Git blob integrity checks succeeded for `first-deposit.sol`, `Price_manipulation.sol`, and `Oracle-stale.sol`. Raw acquisition report: https://github.com/nkinzogomer-eng/PRISM/actions/runs/39851259299/artifacts/12456433966

The three files have potential instructional label exposure in comments (1, 1, 3 lexical signals respectively), as well as descriptive filenames. These training fixtures are PUBLIC; they do not constitute a blind independent benchmark. A successful match on these examples must not be counted as discovering an unknown vulnerability.

**No detector was run on these files. No independent EVM witness was executed and no vulnerability precision/recall result is available.** The only verified result is data provenance and identification of contamination risk.

Next requirements: preserve a separate label-free input view; establish independently adjudicated and executable cases, with pinned dependencies and comparable Foundry stateful and other baselines; score distinct confirmed violations, FP and FN plus full resource usage. Hidden truth must remain inaccessible to all detector paths. Public exercise content may be used for development only, not held-out proof. Leave main unchanged and the PR in draft.
