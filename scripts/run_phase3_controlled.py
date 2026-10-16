"""Phase 3: controlled stress test of one verified structural transformation."""
from __future__ import annotations
import argparse, itertools, json, platform, sys
from pathlib import Path
from statistics import mean
from time import perf_counter
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from prism.optimal import solve_expected
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.transformations import prune_dominated_observations, verify_dominated_observation_pruning
MODES = ("favorable", "cost_reversal", "unrelated", "equal_cost_duplicate", "chain")

def make_problem(mode, seed):
    rotate = seed % 3
    hypotheses = []
    for raw in range(8):
        b0, b1, b2 = ((raw >> i) & 1 for i in range(3))
        values = {
            "favorable": {"rich": f"{b0}{b1}", "coarse": str(b0), "independent": str(b2)},
            "cost_reversal": {"rich": f"{b0}{b1}", "coarse": str(b0), "independent": str(b2)},
            "unrelated": {"a": str(b0), "b": str(b1), "c": str(b2)},
            "equal_cost_duplicate": {"a": str(b0), "b": str(b0), "c": str(b1), "d": str(b2)},
            "chain": {"rich": f"{b0}{b1}", "medium": str(b0), "coarse": str(b0), "independent": str(b2)},
        }[mode]
        decision = str(b1 ^ b2) if mode in ("favorable", "cost_reversal", "chain") else str(b0 ^ b1 ^ b2)
        hypotheses.append(Hypothesis(f"h{(raw + rotate) % 8:03d}", values, decision))
    costs = {
        "favorable": {"rich": 1.0, "coarse": 2.0, "independent": 1.5},
        "cost_reversal": {"rich": 3.0, "coarse": 1.0, "independent": 1.5},
        "unrelated": {"a": 1.0, "b": 1.2, "c": 1.4},
        "equal_cost_duplicate": {"a": 1.0, "b": 1.0, "c": 1.2, "d": 1.4},
        "chain": {"rich": 1.0, "medium": 2.0, "coarse": 3.0, "independent": 1.5},
    }[mode]
    return FiniteProblem(hypotheses, [Observation(k, v) for k, v in costs.items()])

def decision_sets_equal(original, transformed):
    ids = sorted(transformed.observations)
    for count in range(len(ids) + 1):
        for subset in itertools.combinations(ids, count):
            domains = [sorted({h.observations[oid] for h in transformed.hypotheses.values()}) for oid in subset]
            for values in itertools.product(*domains):
                evidence = dict(zip(subset, values))
                def decisions(problem):
                    return {h.decision for h in problem.hypotheses.values() if all(h.observations[k] == v for k, v in evidence.items())}
                if decisions(original) != decisions(transformed):
                    return False
    return True

def run_mode(mode, runs):
    rows = []
    for seed in range(runs):
        original = make_problem(mode, seed)
        t = perf_counter(); before = solve_expected(original); before_seconds = perf_counter() - t
        t = perf_counter(); result = prune_dominated_observations(original); transform_seconds = perf_counter() - t
        t = perf_counter(); after = solve_expected(result.problem); after_seconds = perf_counter() - t
        rows.append({
            "seed": seed, "observations_before": len(original.observations), "observations_after": len(result.problem.observations),
            "removed": result.removed_observation_count, "before_expected_cost_units": before.expected_cost,
            "after_expected_cost_units": after.expected_cost, "expected_cost_delta_units": after.expected_cost - before.expected_cost,
            "verifier_passed": verify_dominated_observation_pruning(original, result),
            "decision_sets_preserved": decision_sets_equal(original, result.problem),
            "exact_expected_cost_not_increased": after.expected_cost <= before.expected_cost + 1e-12,
            "transform_runtime_seconds_reported": result.transform_runtime_seconds,
            "transform_wall_seconds_diagnostic": transform_seconds,
            "exact_solver_before_seconds_diagnostic": before_seconds, "exact_solver_after_seconds_diagnostic": after_seconds,
        })
    return {
        "runs": runs, "mean_observations_before": mean(r["observations_before"] for r in rows),
        "mean_observations_after": mean(r["observations_after"] for r in rows),
        "mean_observations_removed": mean(r["removed"] for r in rows),
        "runs_with_any_removal": sum(r["removed"] > 0 for r in rows),
        "mean_expected_cost_before_units": mean(r["before_expected_cost_units"] for r in rows),
        "mean_expected_cost_after_units": mean(r["after_expected_cost_units"] for r in rows),
        "mean_expected_cost_delta_units": mean(r["expected_cost_delta_units"] for r in rows),
        "all_independent_verifiers_passed": all(r["verifier_passed"] for r in rows),
        "all_decision_sets_preserved": all(r["decision_sets_preserved"] for r in rows),
        "exact_expected_cost_never_increased": all(r["exact_expected_cost_not_increased"] for r in rows),
        "mean_transform_wall_seconds_diagnostic": mean(r["transform_wall_seconds_diagnostic"] for r in rows),
        "mean_exact_solver_before_seconds_diagnostic": mean(r["exact_solver_before_seconds_diagnostic"] for r in rows),
        "mean_exact_solver_after_seconds_diagnostic": mean(r["exact_solver_after_seconds_diagnostic"] for r in rows),
        "mean_pipeline_wall_seconds_before_diagnostic": mean(r["exact_solver_before_seconds_diagnostic"] for r in rows),
        "mean_pipeline_wall_seconds_after_diagnostic": mean(r["transform_wall_seconds_diagnostic"] + r["exact_solver_after_seconds_diagnostic"] for r in rows),
        "mean_pipeline_wall_delta_seconds_diagnostic": mean(r["transform_wall_seconds_diagnostic"] + r["exact_solver_after_seconds_diagnostic"] - r["exact_solver_before_seconds_diagnostic"] for r in rows),
        "per_seed": rows,
    }

def omitted_world_counterexample():
    declared = FiniteProblem([
        Hypothesis("h00", {"rich": "00", "coarse": "0", "decision_obs": "safe"}, "safe"),
        Hypothesis("h01", {"rich": "01", "coarse": "0", "decision_obs": "unsafe"}, "unsafe"),
        Hypothesis("h10", {"rich": "10", "coarse": "1", "decision_obs": "safe"}, "safe"),
        Hypothesis("h11", {"rich": "11", "coarse": "1", "decision_obs": "unsafe"}, "unsafe"),
    ], [Observation("rich", 1.0), Observation("coarse", 2.0), Observation("decision_obs", 1.0)])
    transformed = prune_dominated_observations(declared)
    omitted = {"rich": "00", "coarse": "1", "decision_obs": "safe"}
    violation = any(h.observations["rich"] == omitted["rich"] and h.observations["coarse"] != omitted["coarse"] for h in declared.hypotheses.values())
    return {"declared_class_verifier_passed": verify_dominated_observation_pruning(declared, transformed),
            "omitted_world_exists": True, "omitted_world_violates_declared_dominance_relation": violation,
            "interpretation": "The rewrite is valid relative to the declared class only; this does not establish external-world completeness."}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--outdir", default="phase3-artifacts")
    args = parser.parse_args()
    if not 20 <= args.runs <= 200: parser.error("--runs must be between 20 and 200")
    started = perf_counter()
    modes = {mode: run_mode(mode, args.runs) for mode in MODES}
    external = omitted_world_counterexample()
    gates = {
        "all_independent_verifiers_passed": all(x["all_independent_verifiers_passed"] for x in modes.values()),
        "all_decision_sets_preserved": all(x["all_decision_sets_preserved"] for x in modes.values()),
        "exact_expected_cost_never_increased": all(x["exact_expected_cost_never_increased"] for x in modes.values()),
        "counterexample_exposes_model_relative_scope": external["declared_class_verifier_passed"] and external["omitted_world_violates_declared_dominance_relation"],
        "positive_and_negative_regimes_present": modes["favorable"]["runs_with_any_removal"] == args.runs and modes["cost_reversal"]["runs_with_any_removal"] == 0 and modes["unrelated"]["runs_with_any_removal"] == 0,
        "equal_cost_tie_break_is_safe": modes["equal_cost_duplicate"]["runs_with_any_removal"] == args.runs,
        "chain_dominance_reduces_multiple_observations": modes["chain"]["mean_observations_removed"] >= 2,
    }
    result = {"suite": "SCM-PRISM Phase 3 controlled dominated-observation experiment", "protocol_version": 1,
        "runs_per_regime": args.runs, "seed_policy": f"integer seeds 0..{args.runs - 1}; deterministic finite generators; IDs rotated by seed",
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine()},
        "elapsed_suite_seconds_diagnostic_only": perf_counter() - started, "regimes": modes,
        "omitted_world_counterexample": external, "hard_gates": gates,
        "interpretation_limits": [
            "Only one existing transformation is studied: dominated-observation pruning.",
            "Decision and exact-cost claims are relative to finite deterministic declared hypothesis classes.",
            "Abstract operation-cost units and wall-clock seconds are separate dimensions and are not added together.",
            "Solver wall time is diagnostic and reflects the exact reference solver, not a deployed policy.",
            "Favorable families are deliberately structured to satisfy transformation preconditions.",
            "No real-world cybersecurity, finance, astronomy, repair, or zero-day efficacy was measured."]}
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    jp, mp = outdir / "phase-3-controlled-dominance.json", outdir / "phase-3-controlled-dominance.md"
    jp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# SCM-PRISM Phase 3: controlled structural-computation experiment", "",
        f"- Protocol version: 1", f"- Runs per regime: {args.runs}", f"- Seeds: 0–{args.runs - 1}",
        f"- Python: {result['environment']['python']}", f"- Platform: {result['environment']['platform']}",
        "- Synthetic finite deterministic experiments only.", "", "## Regime results", "",
        "| Regime | Runs | Mean observations before → after | Mean removed | Runs with removal | Mean exact cost before → after | Mean delta | Verifier | Decision sets | Cost never increased |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, s in modes.items():
        lines.append(f"| {name} | {s['runs']} | {s['mean_observations_before']:.2f} → {s['mean_observations_after']:.2f} | {s['mean_observations_removed']:.2f} | {s['runs_with_any_removal']} | {s['mean_expected_cost_before_units']:.4f} → {s['mean_expected_cost_after_units']:.4f} | {s['mean_expected_cost_delta_units']:.6f} | {s['all_independent_verifiers_passed']} | {s['all_decision_sets_preserved']} | {s['exact_expected_cost_never_increased']} |")
    lines += ["", "## Wall-clock diagnostics", "", "Pipeline wall time is estimated as transform time + transformed exact-solver time and compared with the untransformed exact-solver time. All values are runner-dependent diagnostics; abstract operation-cost units are not added to seconds.", "",
        "| Regime | Transform (s) | Solver before (s) | Solver after (s) | Pipeline before (s) | Pipeline after (s) | Paired delta (s) |", "|---|---:|---:|---:|---:|---:|---:|"]
    for name, s in modes.items():
        lines.append(f"| {name} | {s['mean_transform_wall_seconds_diagnostic']:.9f} | {s['mean_exact_solver_before_seconds_diagnostic']:.9f} | {s['mean_exact_solver_after_seconds_diagnostic']:.9f} | {s['mean_pipeline_wall_seconds_before_diagnostic']:.9f} | {s['mean_pipeline_wall_seconds_after_diagnostic']:.9f} | {s['mean_pipeline_wall_delta_seconds_diagnostic']:.9f} |")
    lines += ["", "## Omitted-world counterexample", "", f"- Declared-class verifier passed: **{external['declared_class_verifier_passed']}**",
        f"- Omitted world violates declared dominance: **{external['omitted_world_violates_declared_dominance_relation']}**",
        f"- Interpretation: {external['interpretation']}", "", "## Hard gates", ""]
    lines.extend(f"- {k}: **{v}**" for k, v in gates.items())
    lines += ["", "## Limits", ""]; lines.extend(f"- {x}" for x in result["interpretation_limits"])
    mp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS" if all(gates.values()) else "FAIL", "runs_per_regime": args.runs, "hard_gates": gates, "artifacts": [str(jp), str(mp)]}, indent=2, sort_keys=True))
    print("\n--- PHASE 3 REPORT ---\n" + mp.read_text(encoding="utf-8"))
    return 0 if all(gates.values()) else 1
if __name__ == "__main__":
    raise SystemExit(main())
