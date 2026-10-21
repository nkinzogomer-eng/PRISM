# Phase 4.2: bounded dependency experiment

Starting point: PR #13, commit `9e84b533f834b88f5957d00df0705dfa14422d42`, and the 21 October audit. No existing detector or normalization behavior is changed.

The graph is a module-local, flow-insensitive **may-depend** graph of statement lines: every candidate store of a loaded name is retained, including later stores and stores in other scopes. Lexical statement containment supplies control edges. This deliberately over-approximates scope and order. It is neither taint analysis nor an executable slice. Line nodes can coincide; this graph is evidence only.

Imports, calls (including sanitizers), attributes, subscriptions, functions, dynamic dispatch and every construct outside a tiny inert grammar remain unresolved. No constant-branch pruning, alias resolution, sanitization inference, or interprocedural proof is attempted. Every unresolved file is scanned whole, preserving original source bytes. Only modules containing exclusively constants, expression wrappers and `pass` may be omitted; even these receive `skipped`, never a successful negative or safety certificate. The graph always returns `certifies_safety=false`. Parse errors select the original file and scanner errors invalidate the run.

Three frozen policies: full module inventory; lexical whole-file selection on `open|Path|execute|executemany|raw`; structural selection with the above fallback. The simple comparator is deliberately weak and is not a deployable recommendation. Selection receives no labels, categories, scanner findings or previous results. Labels enter after scanner execution for offline scoring only. Graph construction cost is part of selection. The PRISM name denotes this experimental structural selector, not the existing SCM optimal-policy algorithm or a proof of its guarantees.

Measure three rotated-order repetitions. Each arm rereads sources, selects, stages unchanged files, launches a fresh Bandit 1.8.6 process, checks exit/errors/file inventory, scores and cleans up. Report individual preparation, selection, staging, analysis, verification and total durations. Installation/network, CPU, memory and agent costs are unavailable, not zero; serialization is outside totals. Local scans use the all-rules default configuration, with no source import or application execution. Exact finding identities retain file, rule, line, column and message. Compare lost and extra identities against the full arm of each repetition, independently of labels. Skipped modules remain unknown in quality scores. Finding retention is not semantic recall or proof that an alert concerns the labeled weakness.

Primary interest: path traversal and SQLi. If the real scanner has inadequate family detections, retain family results but broaden the diagnostic comparison to all development modules without claiming family validation. No CodeQL or Semgrep time may be inferred from Bandit or archived outputs. No independent holdout is opened.

Go requires both zero lost findings and a lower measured total cost than full analysis, without converting unknowns to negatives. Failure to select fewer files, measurable overhead, or insufficient family coverage means no-go for deployment. Three local repetitions support a short engineering decision, not a statistical superiority claim.

Reproduce with Bandit installed:

```text
python -m unittest discover -s tests -v
python scripts/measure_phase42.py --source-dir benchmark/testcode --labels benchmark/expectedresults-0.1.csv --output reports/phase42-local --repeats 3
```

The benchmark must remain pinned to `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (development-only OWASP Python v0.1). CI repeats this experiment separately; its results must not be mixed with local timing.
