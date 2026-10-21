# Phase 4.3C — property-specific sufficient computation with conservative fallback

**Frozen protocol, 2026-10-21. Status: exploratory development; no result until CI succeeds.**
Branch stacks on PR #16. PR #15, PR #14 and `main` are not changed.

## The exact property and candidate

The target is ONLY **Bandit v1.8.6 rule B307** (direct calls to `eval`), run with `-t B307` and a pinned, unchanged Python benchmark. This is a single narrowly scoped rule, **not all Bandit/Semgrep alerts**. The rule is a Python AST / call blacklist test, and Bandit honors `# nosec` suppressions. It is not a proof of actual code safety or an exploitability assessment.

Hypothesis H43C: for a previously successfully scanned file ending in a newline, if a new revision consists of **exactly the former source bytes followed by exactly one specifically allowed, standalone no-op comment** (`# SCM43C-INERT-{digits}\n`), it is sufficient to reuse the earlier B307 alert inventory, keeping existing AST nodes and line locations unchanged. Everything else goes to a fresh scanner process.

The suffix proof consists of exact byte-prefix equality, terminal-newline check and a strictly anchored marker regex. It is **not** the generic AST selector rejected by Phase 4.2. Since source bytes are unchanged and the new appended comment has no scanner directive text, no old B307 call or suppression line is changed within this restricted input class. It is nevertheless verified by an independent full scanner on every edited snapshot: no universal soundness claim about arbitrary scanner configuration, old parser failure, custom plugins, or future versions.

This is a **restricted known edit family**, not arbitrary Python changes. Do not claim novel computation: a conventional diff/incremental editor or a purpose-built prefix cache can implement the same rule. The scientific result can at most establish a bounded reduction with the cost of the justification included.

## Four fair comparison arms

1. **Full B307 scan:** reanalyze all 1,230 files after each update.
2. **Exact-byte cache:** reuse only unchanged source bytes; reanalyze every changed file. This is a strong baseline.
3. **Conventional AST + scanner-directive cache:** reanalyze changed files unless the full AST including node locations and the line/contents of scanner-sensitive comments are unchanged. Cost of AST/tokenization counts in full update time.
4. **SCM restricted suffix certificate:** check exact-prefix and known inert comment extension; if not proven, scan whole file. Count checking every file, all I/O, staging, invocation, validation and merging.

An ordinary edit-aware suffix detector should be expected to match arm 4. We will not market arm 4's advantage over arm 2 or 3 as a new principle without a genuine stronger native comparator.

## Benchmark controls and adversarial changes

Sources: OWASP Benchmark Python v0.1, SHA-locked checkout `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, pinned Linux byte manifest verified before start by the 4.3B loader. Synthetic edits are applied only to temporary *copies*, are selected by fixed seeds and are not informed by labels or previous scanner findings.

Four predeclared workloads:
- **inert_all:** all 1,230 files have a benign trailing comment added; exact byte cache invalidates all, while suffix certificate can reuse only eligible files ending with newline.
- **mixed:** 90% benign trailing comment additions and 10% appended `eval("1 + 1")` calls (genuine B307 rule targets). Code additions must trigger fresh scans.
- **adversarial:** 80% benign trailing comments, 10% appended unsuppressed `eval` calls and 10% appended `eval` with `# nosec B307` suppression. Both code-change cases must force scanner execution.
- **line_shift:** prepend a newline to a fixed set of 123 source files; a certificate that silently reuses old rule locations must fail.

If source lacks a terminal newline or a scanner/parsing precondition is not established, the narrow certificate must decline and reanalyze. Test invalid and partial scanner output, altered code, suppression directives, shifted lines, arbitrary extra comments, stale cache records and counterexamples.

Every mode is measured twice in rotated order. Cold B307 cache creation is separately recorded and never called free. A fresh B307 process evaluates the same edited snapshot as the comparator. Preserve **all normalized B307 alert identities and multiplicities**: module, rule ID, line, column, message, severity, confidence. A missed/extra/moved alert or scanner failure is **NO-GO**.

## Measurement and falsification

Wall time includes reading the 1,230 originals, constructing the edit in memory, inspecting/checking every module (including the proof), source staging, launching real Bandit when necessary, parsing/verifying full coverage, merging normalized results, and cleanup. Report selected/scanned files, certified reuse, evidence hashes, scanner seconds and total time. Does not include installation/network or serialization of the full JSON report; unmeasured RSS/energy/money are not zero.

A >10% total-cost improvement over the full scan is merely an engineering signal. A >10% improvement over the strong AST-reference cache at equal alerts, replicated on independent realistic edits and compared to native incremental scanners, would justify deeper investigation. On this synthetic workload, even that is not enough to claim state-of-the-art superiority. We must publish negative results and leave the holdout unopened.

Reference evidence: pinned Bandit call blacklist B307 and `# nosec` behavior in Bandit upstream. No findings from the development synthetic corpus count as verified zero-days.

## Code and reproduction

```bash
python -m unittest discover -s tests -p 'test_phase43c_property_certificate.py' -v
python scripts/measure_phase43c.py --source-dir benchmark/testcode \
  --output reports/phase43c-ci --repeats 2
```

Protocol verdict remains **NOT VALIDATED** until CI evidence is reviewed, new scanner findings on edited modules are counted, and all exact-identity preservation gates pass.
