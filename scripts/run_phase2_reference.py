"""Run the Phase 2 reference suite and emit auditable CI artifacts."""
from __future__ import annotations
import argparse, json, platform, sys
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from run_comparison import build_report, markdown as comparison_markdown
from benchmark_transformation import run as benchmark_quotient
from benchmark_transformation import benchmark_dominated_pruning

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--outdir", default="phase2-artifacts")
    args = parser.parse_args()
    if not 20 <= args.runs <= 200:
        parser.error("--runs must be between 20 and 200")
    started = perf_counter()
    comparison = build_report(args.runs)
    quotient = benchmark_quotient(args.runs)
    pruning = benchmark_dominated_pruning(args.runs)
    assert quotient["runs"] == args.runs
    assert quotient["all_independent_checks_passed"], "quotient verifier failure"
    assert pruning["runs"] == args.runs
    assert pruning["all_independent_checks_passed"], "pruning verifier failure"
    assert pruning["optimal_expected_cost_preserved"], "dominated pruning changed exact optimum"
    assert pruning["uniform_hypothesis_prior_preserved"]
    assert comparison["runs_per_seeded_family"] == args.runs
    assert comparison["families"]["sparse_binary"]["fixed_cost"]["runs"] == args.runs
    assert comparison["families"]["misspecified"]["adaptive_greedy"]["runs"] == args.runs
    result = {
        "suite": "SCM-PRISM Phase 2 reference benchmark",
        "protocol_version": 1,
        "runs_per_seeded_family": args.runs,
        "seed_policy": f"integer seeds 0..{args.runs - 1}; deterministic finite generators",
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine()},
        "elapsed_suite_seconds_diagnostic_only": perf_counter() - started,
        "policy_comparison": comparison,
        "decision_equivalence_quotient": quotient,
        "dominated_observation_pruning": pruning,
        "hard_gates": {
            "quotient_independent_checks": quotient["all_independent_checks_passed"],
            "pruning_independent_checks": pruning["all_independent_checks_passed"],
            "pruning_exact_optimum_preserved": pruning["optimal_expected_cost_preserved"],
            "uniform_prior_preserved_by_pruning": pruning["uniform_hypothesis_prior_preserved"],
        },
        "limitations": [
            "Synthetic finite deterministic instances only; no real-world cyber, finance, or astronomy efficacy claim.",
            "Execution costs are abstract operation-cost units and cannot be added to seconds without an explicit calibration.",
            "Wall-clock values are runner-dependent diagnostics, not portable speedup claims.",
            "The exact solver is a small-instance reference relative to the declared model and its implicit uniform prior.",
            "The quotient preserves decision sets but not necessarily the uniform prior over hypothesis IDs.",
            "The dominated-observation result applies only where its finite deterministic dominance witness is valid.",
            "A certificate over an incomplete declared hypothesis class can still disagree with hidden truth.",
        ],
    }
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "phase-2-reference-benchmark.json"
    md_path = outdir / "phase-2-reference-benchmark.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    q = quotient
    p = pruning
    sections = [
        "# SCM-PRISM Phase 2 reference benchmark", "",
        f"- Protocol version: {result['protocol_version']}",
        f"- Runs per seeded family: {args.runs}",
        f"- Python: {result['environment']['python']}",
        f"- Platform: {result['environment']['platform']}",
        "- Scope: finite synthetic deterministic instances only.", "",
        "## Policy comparison", "", comparison_markdown(comparison), "",
        "## Decision-equivalence quotient", "",
        "| Metric | Result |", "|---|---:|",
        f"| Runs | {q['runs']} |",
        f"| Mean hypotheses before -> after | {q['mean_original_hypotheses']:.3f} -> {q['mean_quotient_hypotheses']:.3f} |",
        f"| Mean reduction fraction | {q['mean_hypothesis_reduction_fraction']:.3%} |",
        f"| Independent checks all passed | {q['all_independent_checks_passed']} |",
        f"| Mean transformation time (seconds; diagnostic) | {q['mean_transform_runtime_seconds']:.9f} |", "",
        "Execution-cost results before and after are in the JSON artifact under decision_equivalence_quotient.before and .after.",
        "The quotient preserves decision sets but does not preserve a uniform prior over hypothesis IDs in general.", "",
        "## Dominated-observation pruning", "",
        "| Metric | Result |", "|---|---:|",
        f"| Runs | {p['runs']} |",
        f"| Mean observations before -> after | {p['mean_original_observations']:.3f} -> {p['mean_retained_observations']:.3f} |",
        f"| Mean reduction fraction | {p['mean_observation_reduction_fraction']:.3%} |",
        f"| Independent checks all passed | {p['all_independent_checks_passed']} |",
        f"| Exact expected cost before -> after | {p['mean_exact_expected_cost_before']:.6f} -> {p['mean_exact_expected_cost_after']:.6f} abstract units |",
        f"| Exact optimum preserved in every run | {p['optimal_expected_cost_preserved']} |",
        f"| Mean transformation time (seconds; diagnostic) | {p['mean_transform_runtime_seconds']:.9f} |",
        "", "## Hard gates", "",
    ]
    sections.extend(f"- {key}: **{value}**" for key, value in result["hard_gates"].items())
    sections += ["", "## Interpretation limits", ""]
    sections.extend(f"- {item}" for item in result["limitations"])
    md_path.write_text("\n".join(sections) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS", "runs_per_seeded_family": args.runs,
        "hard_gates": result["hard_gates"],
        "suite_elapsed_seconds_diagnostic_only": result["elapsed_suite_seconds_diagnostic_only"],
        "artifacts": [str(json_path), str(md_path)],
    }, indent=2, sort_keys=True))
    print("\n--- PHASE 2 REPORT ---\n")
    print(md_path.read_text(encoding="utf-8"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
