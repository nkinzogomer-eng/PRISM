# Phase 4 evidence review — 2026-10-21

This is an exploratory development iteration, not a preregistration. Full push CodeQL artifacts were recovered and checked: both suites extracted all 1,230 labeled modules and produced identical case predictions. See the [evidence audit](../reports/phase-4-evidence-audit-2026-10-21.md) and its raw-input hashes.

Fix completion/coverage accounting before attempting detector tuning. Preserve unknowns on partial analysis. Exact-CWE filtering is an ablation, not the deployed decision policy: it reduces F1 in this replay. The structural prototype selects explanatory context only; it does not suppress findings or claim certified reachability/taint reasoning. Do not promote it to a safety gate without independent verification.

OWASP Python v0.1 remains development-only. No independent dataset was inspected; no final holdout has been designated or consumed. Phase 4 remains open. Full cost accounting is incomplete where telemetry/billing are unavailable and those costs must not be treated as zero.
