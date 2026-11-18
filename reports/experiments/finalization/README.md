# Finalization experiment artifacts

These files are raw, committed evidence for the finalization run. They are not
claims of general SCM superiority.

The artifacts contain the exact command, stdout, JSON result, Markdown result,
environment metadata, commit SHA, Python version, platform, seeds and run
counts. Phase 2 uses seeds 0–99 for each seeded family (with its fixed parity
control). Phase 3 uses seeds 0–99 in each of its five declared regimes.

## Reproduction

From the repository root:

```bash
python3 -m pip install --no-index --no-deps --no-build-isolation .
python3 scripts/run_phase2_reference.py --runs 100 --outdir reports/experiments/finalization/phase2
python3 scripts/run_phase3_controlled.py --runs 100 --outdir reports/experiments/finalization/phase3
```

The raw JSON and Markdown results must be interpreted together with their
negative controls and limitations. In particular, abstract execution-cost
units, wall-clock diagnostics, representation reduction, and total cost are
separate quantities. The experiments are finite synthetic deterministic
experiments and do not establish real-world cyber, DeFi, or universal SCM
advantage.

The manual GitHub Actions workflow `.github/workflows/experiments.yml` runs the
same two commands and uploads the resulting directory as a recoverable CI
artifact.
