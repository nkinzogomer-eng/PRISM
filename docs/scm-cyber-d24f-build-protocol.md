# PRISM / SCM — D2.4F: verified historical third-party regression

25 October 2026. BUILD-FIRST, scientific honesty required.

## Executable delivery

A generic domain-independent proof core (`prism/cyber_proof.py`) runs immutable test obligations against two source revisions, records acceptance/rejection, verifies the invariant under an independent adapter, minimizes an observed violation to the shortest candidate, and emits deterministic SHA-256 evidence. The first adapter targets a **genuine, externally authored, publicly known, already fixed vulnerability**, not an injected local mutation.

Target: `pallets/werkzeug` v3.1.5 commit `e3d06f4b1f7ff40a63eba78f81d9cda18f805d6d` (before correction), and v3.1.6 commit `04da1b5221b7a7b57e82246e4b5741d37a6b2e56` (corrected). Relevant disclosure is CVE-2026-27199 / GHSA corresponding to Windows device names after path separators in `safe_join`. Labels are for historical evaluation only; no claim of prospectively discovering the CVE.

Property under test: when joining an untrusted URL path under a trusted directory in Windows-like conditions, reject special Windows device names at ANY path segment, without unnecessarily rejecting ordinary paths. Synthetic-free experiment: the unchanged upstream Python sources are loaded in isolated namespaces. Only the function's namespace is configured with `os.name="nt"`, `ntpath`, and the Windows alternate separator. No process-wide OS alteration, no Windows kernel operation, no opening NUL/CON, no server, no exploitation of live targets. **We reproduce the branch behavior, not a genuine Windows file read or device hang.**

Candidate generation enumerates device symbols read from the real v3.1.5 Python module, independently combined with two generic path-prefix templates, plus ordinary paths and parent-traversal control inputs. Both versions receive the same frozen inputs; source file hashes and paired outputs are retained.

## Mandatory delivery gates

- All unit adversarial tests pass (missing provenance, invalid observation, duplicate IDs, no phantom witness, deterministic digest, missing candidate symbols).
- Assert exact SHA-1 Git commits for both independent checkouts.
- Automatically synthesize multiple depth-two candidates; on upstream v3.1.5 observe acceptance of some nested device names, and on upstream v3.1.6 their rejection. Verify ordinary path acceptance and direct device/parent path rejection on BOTH revisions.
- Publish original source SHA-256, all candidates/outputs, replay SHA-256, minimal witness, execution time and resource usage as GitHub Actions artifact.
- Guardrails: any failed patched-property or diverging benign control aborts; no mutation of upstream bytes; "historical confirmed behavioral regression" is distinct from "newly discovered vulnerability" and "live exploit".

## What is new relative to D2.4E?

D2.4E tested **only synthetic** mutation controls on a correctly patched release. D2.4F verifies a **real historical third-party security regression** in its actual original and patched releases. The generic proof core can accept EVM, native binary or API adapters later; the first adapter is Python/Windows lexical path validation.

This does not yet establish superiority, multi-domain breadth, or independent root-cause discovery. It is concrete proof of a working third-party regression pipeline. Next high-value expansion: import independent historical fixes in Solidity, native C and web authentication; generate properties and candidate sequences from code without reading vulnerability labels, then execute patched-vs-vulnerable truth pairs, minimizing proofs and auditing uncertainty.