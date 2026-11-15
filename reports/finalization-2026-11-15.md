# PRISM/SCM finalization report

## Scope and verdict

This delivery covers the finite, deterministic, offline PRISM reference kernel.
The honest verdict is **technically usable under a bounded scope; general SCM
superiority and external-world correctness remain unproven**. Cyber and DeFi
research claims are not promoted to core guarantees.

## Repository preservation

- Repository: `nkinzogomer-eng/PRISM`
- Initial `main`: `da6980ae9e9b499795fdbf31f137e5a6a0dd5840`
- Finalization branch: `finalization/prism-complete`
- `main`: not modified and not merged
- Initial working tree: clean
- Existing PRs reviewed: #36 (cyber-range/D2.5 laboratory branch) and #38
  (SCM core audit and certificate hardening)
- Open issue reviewed: #37 (finalization mandate)

## Changes made

1. Selectively integrated the verified certificate hardening from PR #38:
   malformed certificate objects, duplicate hypothesis IDs, duplicate/unknown
   evidence keys, unsupported values, and unsupported scopes are rejected.
2. Added offline packaging in `pyproject.toml` with a `prism` console entry
   point and `python -m prism` support.
3. Added a minimal JSON CLI for `run` and independent
   `verify-certificate` operations. It returns structured JSON and non-zero
   status on abstention, invalid certificates, or input errors.
4. Added `.gitignore` rules for generated Python/build artifacts.
5. Updated README installation, CLI usage, and bounded readiness claims.
6. Added `docs/scm-conformance-matrix.md` and this report.
7. Clarified that `docs/architecture.md` describes an executable finite
   reference architecture rather than a fully general adapter framework.
8. Added the required CLI/API guide and security/threat-model document.
9. Added adversarial CLI tests and a CI installation/CLI smoke test.
10. Replaced the external build dependency with a local PEP 517 backend so a
    clean venv can install the package without setuptools or network access.

## Commands actually executed

```text
git clone https://github.com/nkinzogomer-eng/PRISM.git PRISM
git switch -c finalization/prism-complete
git fetch origin pull/38/head:refs/remotes/origin/pr-38
git cherry-pick c4c98f2 7f643c4
python3 -m unittest discover -s tests -v
python3 -m venv /tmp/prism-venv
/tmp/prism-venv/bin/python -m pip install --no-deps .
/tmp/prism-venv/bin/python -m prism run /tmp/prism-cli/problem.json --evidence '{"a":"0"}'
/tmp/prism-venv/bin/prism verify-certificate /tmp/prism-cli/problem.json /tmp/prism-cli/certificate.json
python3 scripts/run_phase2_reference.py --runs 100 --outdir /tmp/prism-phase2-final
python3 scripts/run_phase3_controlled.py --runs 100 --outdir /tmp/prism-phase3-final
```

## Test and benchmark results

The baseline on the original `main` ran 53 tests: 52 passed and one explicitly
expected failure for the known omitted-world misspecification case. After the
hardening, CLI, and adversarial test changes, the suite ran **60 tests: 59
passed and one expected failure**. No unexpected failure occurred.

An initial clean-venv validation exposed that the first packaging draft
implicitly required `setuptools`. That was treated as a real defect, not
hidden: the build configuration was corrected with a local dependency-free
PEP 517 backend, and the clean-venv install was then rerun successfully.

The existing Phase 2 and Phase 3 suites passed their hard gates. They cover
finite deterministic synthetic instances, independent checks for the two
implemented transformations, decision-set preservation, exact abstract-cost
preservation, parity/negative controls, and an omitted-world counterexample.
Their reports explicitly state that wall-clock values are diagnostics and that
no general speedup or real-world cyber/DeFi efficacy is demonstrated.

The clean virtual-environment install and CLI smoke path produced:

- `CERTIFIED_DECISION` for a declared finite example;
- `VERIFIED` for the generated certificate;
- structured JSON output;
- no network or model dependency.

The 100-run Phase 2 reference benchmark and 100-run-per-regime Phase 3
controlled benchmark both returned `PASS`, including their independent
verifier and preservation hard gates.

## Remaining gaps and risks

The implementation is not a general SCM engine. General structural dependency
graphs, decision-oriented slicing, transformation composition, cache
invalidation, checkpoint/resume, probabilistic/adversarial semantics, and
external-world validators remain partial or absent. Memory, communication,
energy, and financial cost are reported as unknown unless an adapter measures
them. The finite certificate is only relative to the declared hypothesis
class, and can be wrong about an omitted true world; the expected-failure test
keeps this limitation visible.

The existing cyber-range PR #36 was not merged or incorporated: it is outside
the bounded core work and contains claims requiring its own execution and
isolation audit. No offensive test was run against a real target. No new
vulnerability claim is made.

## Proposed pull request and next steps

Open a draft PR from `finalization/prism-complete` to `main` after reviewing the
working-tree diff. Do not merge automatically. The next engineering milestone
should define a versioned trace/checkpoint format and a transformation contract
with explicit invalidation, then add one independent non-synthetic benchmark.
Only after those gates should cyber or DeFi adapters be considered.
