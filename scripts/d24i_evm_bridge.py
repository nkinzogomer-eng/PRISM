"""D2.4I bounded real-EVM evidence bridge for pre-labelled LOCAL lab mutants.

Foundry executes the actual Solidity D2.2 code and independently authored
stateful invariants. PRISM only checks observed verdict traces and integrity.
This is an integration/negative-control gate, never a zero-day benchmark.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import subprocess
from time import perf_counter

from prism.hypothesis_contract import (SCHEMA, ciel_hypothesis_capability_result,
                                       verify_hypothesis)


CASE_CONTRACTS = {
    "oracle_bug":"D22OracleBugStatefulTest",
    "withdraw_bug":"D22WithdrawBugStatefulTest",
    "repay_bug":"D22RepayBugStatefulTest",
    "safe":"D22AllSafeStatefulTest",
}
PROPERTIES = {
    "oracle":"invariant_OracleOwnerOnly()",
    "solvency":"invariant_CollateralSolvent()",
    "repayment":"invariant_RepaymentFunded()",
}
REASONS = {
    "oracle":"D22_ORACLE_AUTH_WITNESS",
    "solvency":"D22_WITHDRAW_SOLVENCY_WITNESS",
    "repayment":"D22_UNFUNDED_REPAY_WITNESS",
}
EXPECTED_CASE = {"oracle":"oracle_bug","solvency":"withdraw_bug",
                 "repayment":"repay_bug"}
INVENTORY = set(PROPERTIES.values()) | {"invariant_TokenConservation()"}


def parse_native_evm(raw: str, *, case: str, returncode: int) -> dict:
    """Check the FULL source-independent native test inventory and failure reasons.

    An arbitrary compiler failure, skipped test or failing token conservation
    is an UNKNOWN harness failure, not a property counterexample.
    """
    if case not in CASE_CONTRACTS:
        raise ValueError("unregistered case")
    try:
        decoded=json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Foundry did not return valid JSON") from exc
    if type(decoded) is not dict:
        raise ValueError("invalid Foundry root")
    rows={}
    for suite in decoded.values():
        if type(suite) is not dict:
            continue
        tests=suite.get("test_results",{})
        if type(tests) is not dict:
            raise ValueError("invalid Foundry test suite")
        for name,value in tests.items():
            if name in rows or type(value) is not dict:
                raise ValueError("duplicated or malformed native result")
            rows[name]=value
    if set(rows)!=INVENTORY:
        raise ValueError("native EVM property inventory not complete")
    if rows["invariant_TokenConservation()"].get("status")!="Success":
        raise ValueError("token conservation or harness failed")
    observations={}
    for family,name in PROPERTIES.items():
        status=rows[name].get("status")
        reason=str(rows[name].get("reason") or "")
        if status not in ("Success","Failure"):
            raise ValueError("unknown EVM test outcome")
        if status=="Failure" and REASONS[family] not in reason:
            raise ValueError("wrong reason for observed property failure")
        observations[family]={
            "property_holds":status=="Success",
            "status":status,
            "reason":reason[:220] if status=="Failure" else "",
            "gas_used":rows[name].get("gas_used"),
        }
    if returncode == 0 and any(not x["property_holds"] for x in observations.values()):
        raise ValueError("EVM process falsely exited success")
    if returncode != 0 and all(x["property_holds"] for x in observations.values()):
        raise ValueError("EVM process failed without verified property counterexample")
    if case=="safe" and (returncode!=0 or any(not x["property_holds"] for x in observations.values())):
        raise ValueError("negative control failed")
    return {"case":case,"stdout_sha256":sha256(raw.encode()).hexdigest(),
            "properties":observations}


def verify_native_matrix(cases: dict[str,dict], source: Path) -> dict:
    """Feed immutable Foundry results to generic Ciel hypothesis checker.

    The oracle is *preauthorized host code*, not a Ciel-supplied witness.
    """
    if set(cases)!=set(CASE_CONTRACTS):
        raise ValueError("missing case in EVM evidence matrix")
    digest=sha256(source.read_bytes()).hexdigest()
    results={}
    for family in PROPERTIES:
        request={
            "schema":SCHEMA,"mission_id":"lab:d24i","task_id":"evm:matrix",
            "hypothesis_id":"hypothesis:"+family,
            "proposer":{"kind":"CIEL","id":"ciel.simulated.proposer"},
            "source":{"path":source.name,"sha256":digest,"language":"solidity"},
            "property":{"kind":"FINITE_TRACE_INVARIANT","family":family,
                        "predicate":{"op":"eq","left":{"var":"property_holds"},
                                     "right":{"const":True}}},
            "budget":{"max_observations":4},
            "execution_policy":"LOCAL_READ_ONLY",
        }

        def independent_observer(ctx, family=family):
            return {"observer_id":"foundry.native.stateful.observer",
                    "source_sha256":ctx["source_sha256"],
                    "observations":[
                        {"event_id":case,"values":{"property_holds":cases[case]["properties"][family]["property_holds"]}}
                        for case in CASE_CONTRACTS]}

        report=verify_hypothesis(request,authorized_root=source.parent,
                                 authorized_local=True,
                                 independent_observer=independent_observer)
        results[family]=ciel_hypothesis_capability_result(report)
    return {
        "schema":"scm.prism.d24i.real-evm-lab-bridge.v1",
        "source_sha256":digest,
        "native_stdout_sha256_by_case":{key:x["stdout_sha256"] for key,x in cases.items()},
        "hypotheses":results,
        "property_matrix":{family:{case:cases[case]["properties"][family]["property_holds"]
                                   for case in CASE_CONTRACTS} for family in PROPERTIES},
        "expected_mutant_for_property":EXPECTED_CASE,
        "discovery_blind":False,
        "known_mutants_prelabelled":True,
        "new_vulnerabilities_confirmed":0,
        "ciel_really_generated_hypotheses":False,
        "source_execution_isolation_provided_by":"FOUNDRY_LOCAL_CI_LAB",
        "independent_semantic_specification":False,
        "limitations":[
            "Prelabelled lab variants; known stateful invariants, not actual protocol zero-days",
            "Boolean Foundry invariant outcomes are a bridge, not full EVM state traces",
            "Forge stdout digests document bytes but do not cryptographically attest an EVM",
            "Fuzzing may miss a known mutation at a given budget; retain false negatives",
        ],
    }


def score_native_matrix(cases: dict[str,dict]) -> dict:
    if set(cases)!=set(CASE_CONTRACTS):
        raise ValueError("incomplete EVM matrix")
    misses=[family for family,case in EXPECTED_CASE.items()
            if cases[case]["properties"][family]["property_holds"]]
    spurious=[(family,case) for family in PROPERTIES for case in CASE_CONTRACTS
              if case!=EXPECTED_CASE[family]
              and not cases[case]["properties"][family]["property_holds"]]
    return {"missed_known_mutants":misses,"spurious_counterexamples":spurious,
            "known_mutants_detected":len(EXPECTED_CASE)-len(misses),
            "known_mutant_total":len(EXPECTED_CASE)}


def _run_forge(root: Path, output: Path, case: str, *, runs: int, depth: int,
               seed: int | None = None) -> dict:
    if case not in CASE_CONTRACTS or not 1 <= runs <= 1024 or not 1 <= depth <= 128:
        raise ValueError("unbounded or unknown local EVM workload")
    if seed is not None and (type(seed) is not int or not 1 <= seed <= 65535):
        raise ValueError("invalid reproducible Foundry seed")
    env=dict(os.environ)
    env.update(FOUNDRY_INVARIANT_RUNS=str(runs),FOUNDRY_INVARIANT_DEPTH=str(depth),
               FOUNDRY_INVARIANT_FAIL_ON_REVERT="false")
    if seed is not None:
        env["FOUNDRY_FUZZ_SEED"]=hex(seed)
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    t=perf_counter()
    process=subprocess.run(["forge","test","--match-contract",CASE_CONTRACTS[case],
                            "--json"],cwd=root,env=env,capture_output=True,text=True,
                           timeout=180,check=False)
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stem=f"{case}-{runs}x{depth}"+(f"-seed{seed}" if seed is not None else "")
    (output/f"{stem}.stdout.json").write_text(process.stdout,encoding="utf-8")
    (output/f"{stem}.stderr.txt").write_text(process.stderr,encoding="utf-8")
    result=parse_native_evm(process.stdout,case=case,returncode=process.returncode)
    result["budget"]={"runs":runs,"depth":depth}
    result["wall_seconds"]=perf_counter()-t
    result["child_cpu_seconds"]=(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime)
    result["returncode"]=process.returncode
    result["seed"]=seed
    return result


def run_evm_campaign(root: Path, output: Path) -> dict:
    """Two escalating budgets; test known mutants and preserve all misses."""
    output.mkdir(parents=True,exist_ok=True)
    source=root/"src"/"MultiRisk.sol"
    if not source.is_file():
        raise FileNotFoundError("approved isolated D22 fixture is required")
    attempts=[]
    chosen=None
    for runs,depth in ((64,32),(256,64)):
        cases={key:_run_forge(root,output,key,runs=runs,depth=depth)
               for key in CASE_CONTRACTS}
        result=verify_native_matrix(cases,source)
        scored=score_native_matrix(cases)
        attempts.append({"budget":{"runs":runs,"depth":depth},
                         **scored,
                         "native":cases,"proof_bridge":result})
        if not scored["missed_known_mutants"] and not scored["spurious_counterexamples"]:
            chosen=attempts[-1]
            break
    output_data={
        "schema":"scm.prism.d24i.real-evm-adversarial-campaign.v1",
        "status":"ENGINEERING_GATE_PASS" if chosen else "KNOWN_MUTANT_RECALL_GATE_FAILED",
        "attempts":attempts,
        "all_known_mutants_observed":chosen is not None,
        "blind_holdout":False,
        "actual_independent_vulnerabilities_confirmed":0,
    }
    (output/"evm-evaluation.json").write_text(json.dumps(output_data,indent=2,sort_keys=True)+"\n")
    return output_data


def run_seeded_stress(root: Path, output: Path, *, seeds: tuple[int,...] = tuple(range(1,9))) -> dict:
    """Pre-fixed low-budget adversity across many genuine EVM fuzz seeds.

    Every initial miss is preserved even if a later budget rescues it. This
    is a labelled development control; it is not a blind vulnerability trial.
    """
    if not 1 <= len(seeds) <= 16 or len(seeds)!=len(set(seeds)):
        raise ValueError("fixed non-duplicated seed inventory required")
    output.mkdir(parents=True,exist_ok=True)
    report={"schema":"scm.prism.d24i.seeded-evm-adversarial.v1",
            "seed_inventory":list(seeds),"profiles":[
                {"runs":32,"depth":16},{"runs":64,"depth":32},
                {"runs":256,"depth":64}],
            "results":[],"known_mutants_per_seed":3,"blind":False}
    for seed in seeds:
        if type(seed) is not int or not 1 <= seed <= 65535:
            raise ValueError("unsupported immutable seed")
        record={"seed":seed,"attempts":[],"recovered_all":False}
        for runs,depth in ((32,16),(64,32),(256,64)):
            cases={case:_run_forge(root,output,case,runs=runs,depth=depth,seed=seed)
                   for case in CASE_CONTRACTS}
            scored=score_native_matrix(cases)
            record["attempts"].append({"budget":{"runs":runs,"depth":depth},
                                      **scored,
                                      "source_hashes":{case:value["stdout_sha256"]
                                                       for case,value in cases.items()},
                                      "total_wall_seconds":sum(v["wall_seconds"] for v in cases.values()),
                                      "total_child_cpu_seconds":sum(v["child_cpu_seconds"] for v in cases.values())})
            if not scored["missed_known_mutants"] and not scored["spurious_counterexamples"]:
                record["recovered_all"]=True
                break
        report["results"].append(record)
        # Do not lose partial observations when a later seed cannot run.
        (output/"seeded-stress.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    report["status"]=("ENGINEERING_SEED_GATE_PASS" if all(r["recovered_all"] for r in report["results"])
                      else "KNOWN_MUTANT_SEED_RECALL_NOT_COMPLETE")
    report["seeds_recovered"] = sum(r["recovered_all"] for r in report["results"])
    report["initial_profile_full_detection"] = sum(
        not r["attempts"][0]["missed_known_mutants"] and
        not r["attempts"][0]["spurious_counterexamples"]
        for r in report["results"])
    (output/"seeded-stress.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--stress-seeds",type=int,default=0)
    args=p.parse_args()
    result=run_evm_campaign(args.root.resolve(),args.out.resolve())
    print("D24I_EVM_ADVERSARIAL",json.dumps({
        "status":result["status"],"attempts":len(result["attempts"]),
        "missed":result["attempts"][-1]["missed_known_mutants"],
        "spurious":result["attempts"][-1]["spurious_counterexamples"],
    },sort_keys=True))
    if not result["all_known_mutants_observed"]:
        raise SystemExit(1)
    if args.stress_seeds:
        if not 1 <= args.stress_seeds <= 16:
            raise ValueError("invalid requested stress seed count")
        stress=run_seeded_stress(args.root.resolve(),args.out.resolve(),
                                 seeds=tuple(range(1,args.stress_seeds+1)))
        print("D24I_EVM_SEEDED_STRESS",json.dumps({
            "status":stress["status"],"seed_count":args.stress_seeds,
            "seed_recovered":stress["seeds_recovered"],
            "low_budget_full_detection":stress["initial_profile_full_detection"],
            "recovery_budget_profiles":{
                str(r["seed"]):r["attempts"][-1]["budget"] for r in stress["results"]},
        },sort_keys=True))
        if stress["status"]!="ENGINEERING_SEED_GATE_PASS":
            raise SystemExit(1)
