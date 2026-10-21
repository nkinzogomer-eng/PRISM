# Phase 4 decision log — 2026-10-16

## Decision 4.1: begin with a bounded defensive benchmark

**Decision:** Start Phase 4 with offline, labeled software-security triage using pinned public benchmark cases and existing static analyzers. Keep remediation as a separate sub-study. Do not begin with live-network activity, autonomous offensive execution, or claims about unknown vulnerabilities.

**Reasoning:** PRISM currently has a finite decision-sufficiency core, not a validated cyber adapter. A labeled, reproducible benchmark provides ground truth for a first falsifiable evaluation while limiting operational risk.

**Candidate datasets:** OWASP Benchmark for Python v0.1 is the pilot candidate because it fits the existing Python prototype; its preliminary status, GPL-3.0 license, and known label concern are recorded in the feasibility note. OWASP Benchmark for Java v1.2 and NIST SARD/Juliet remain separate replication candidates. No dataset is accepted until commit/checksum, labels, and tool compatibility are pinned.

**Comparisons required:** individual tools; fixed-order/all-tools orchestration; a simple cost-aware policy; PRISM using the same operations and visible inputs; and an exact oracle only where tractable.

**Frozen principle:** All preprocessing, planning, execution, normalization, and verification costs count. Hidden labels are never available to the controller. Results must be reported by category and on held-out source/template families. A faster policy that misses more labeled findings does not pass.

**Current evidence:** None yet for Phase 4. The Phase 2/3 synthetic findings do not count as cyber evidence.

**Next action:** pin the Python benchmark commit/checksum, audit labels and license, test the normalized-output scorer, identify compatible static analyzers, and establish individual-tool baselines before connecting PRISM to the task.

**Revisit only if:** the candidate dataset is unavailable, its labels are unsuitable, its license blocks the intended evaluation, or no compatible static analyzer can produce reproducible machine-readable outputs. Any replacement dataset and reason must be logged before held-out evaluation.
