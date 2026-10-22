"""D2.2 execute and score independently generated Foundry stateful sequences.

Do not reinterpret model predictions as EVM discoveries; report *both* raw
candidate and native fuzz results, including failures and cost. A genuine
native stateful benchmark must run with targetContracts handler, not with a
fixed analyst-authored action sequence.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import subprocess
import time

CASES = {
    "oracle_bug": "D22OracleBugStatefulTest",
    "withdraw_bug": "D22WithdrawBugStatefulTest",
    "repay_bug": "D22RepayBugStatefulTest",
    "safe": "D22AllSafeStatefulTest",
}
PROPERTIES = {
    "invariant_OracleOwnerOnly()": "D22_ORACLE_AUTH_WITNESS",
    "invariant_CollateralSolvent()": "D22_WITHDRAW_SOLVENCY_WITNESS",
    "invariant_RepaymentFunded()": "D22_UNFUNDED_REPAY_WITNESS",
}
TRUTH = {"oracle_bug": "invariant_OracleOwnerOnly()",
         "withdraw_bug": "invariant_CollateralSolvent()",
         "repay_bug": "invariant_RepaymentFunded()"}


def run_forge(root: Path, out: Path, ident: str, contract: str) -> dict:
    argv = ["forge", "test", "--match-contract", contract, "--json"]
    t = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    proc = subprocess.run(argv, cwd=root, capture_output=True, text=True,
                          timeout=210)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    wall = time.perf_counter()-t
    (out / f"{ident}.json").write_text(proc.stdout, encoding="utf-8")
    (out / f"{ident}.stderr.txt").write_text(proc.stderr, encoding="utf-8")
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"forge {ident} did not return JSON; exit {proc.returncode}") from exc
    rows = {}
    for group in raw.values():
        if not isinstance(group,dict):
            continue
        for key, item in group.get("test_results", {}).items():
            if key in rows:
                raise ValueError(f"duplicate native EVM test: {key}")
            rows[key] = {"status": item.get("status"),
                         "reason": str(item.get("reason") or ""),
                         "gas_used": item.get("gas_used")}
    if not rows:
        raise RuntimeError(f"no native test executed for {ident}")
    return {
        "contract": contract, "exit_code": proc.returncode,
        "wall_seconds": wall,
        "child_cpu_seconds": (after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
        "raw_sha256": sha256(proc.stdout.encode()).hexdigest(),
        "rows": rows,
    }


def evaluate(root: Path, out: Path, candidate_file: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    candidate = json.loads(candidate_file.read_text(encoding="utf-8"))
    if candidate.get("phase") != "DeFi D2.2":
        raise ValueError("wrong candidate ledger")
    model = {(r["case_id"],r["property_id"]): r for r in candidate["cross_product"]}
    if len(model) != 12:
        raise ValueError("not all model cases evaluated")
    results = {"phase":"DeFi D2.2", "status":"INCOMPLETE",
               "hypothesis":"Higher property-level confirmed coverage at equal total budget",
               "native_runs": {}, "comparisons": [],
               "model_candidates_sha256":sha256(candidate_file.read_bytes()).hexdigest(),
               "limits":[
                   "Synthetic publicly labelled vulnerabilities, NOT blind holdout",
                   "No source-to-property or source-to-model inference in PRISM",
                   "Foundry handler invariants are independently coded but predeclared",
                   "Native fuzz is stochastic with 256 runs/64 steps; no universal assurance",
                   "No installation/network, human property design, or bytecode inference timing",
                   "Main initial compilation borne by first forge call; not directly policy comparable",
                   "Process wall and CPU times differ from bare Python model search costs",
               ]}
    try:
        generated = run_forge(root,out,"generated","D22GeneratedWitnessTest")
        results["native_runs"]["generated"] = generated
        wanted={f"testGenerated{n}{suffix}()" for n in ("Oracle","Withdraw","Repay")
                for suffix in ("BugWitness","SafeControl")}
        if set(generated["rows"]) != wanted or generated["exit_code"] != 0:
            raise RuntimeError("wrong generated EVM test inventory or failure")
        if any(v["status"]!="Success" for v in generated["rows"].values()):
            raise RuntimeError("generated candidate/patched control fails EVM")

        for case, contract in CASES.items():
            evm = run_forge(root,out,case,contract)
            results["native_runs"][case] = evm
            wanted_tests=set(PROPERTIES)|{"invariant_TokenConservation()"}
            if set(evm["rows"]) != wanted_tests:
                raise RuntimeError("missing/extra native stateful property: " + case)
            if evm["rows"]["invariant_TokenConservation()"]["status"] != "Success":
                raise RuntimeError("asset conservation violation or harness failure: " + case)
            expected = TRUTH.get(case)
            for prop_name, reason in PROPERTIES.items():
                item = evm["rows"][prop_name]
                failure = item["status"] == "Failure"
                if failure and reason not in item["reason"]:
                    raise RuntimeError(f"{case}/{prop_name} failed for WRONG reason: {item['reason']}")
                if item["status"] not in ("Success","Failure"):
                    raise RuntimeError("ambiguous foundry outcome")
                prediction = model[(case,{"invariant_OracleOwnerOnly()":"unauthorized_oracle_write",
                    "invariant_CollateralSolvent()":"unsafe_collateral_withdrawal",
                    "invariant_RepaymentFunded()":"unfunded_debt_repayment"}[prop_name])]
                results["comparisons"].append({
                    "case":case, "property":prop_name,
                    "positive_truth": expected == prop_name,
                    "model_bfs_found":prediction["baseline"]["found"],
                    "model_guided_found":prediction["goal_first"]["found"],
                    "model_bfs_expanded":prediction["baseline"]["expanded"],
                    "model_guided_expanded":prediction["goal_first"]["expanded"],
                    "native_stateful_found":failure,
                    "native_foundry_status":item["status"],
                    "native_reason":item["reason"],
                })
            expected_failures=1 if expected else 0
            actual_failures=sum(x["status"]=="Failure" for x in evm["rows"].values())
            # Native fuzz is a comparator: missed positives are recorded, not
            # quietly erased, nor is a failure to find by budget an API error.
            if actual_failures > expected_failures:
                raise RuntimeError("spurious negative-case baseline failure: " + case)
            if case=="safe" and (actual_failures != 0 or evm["exit_code"] != 0):
                raise RuntimeError("safe control wrongly failed")
        results["metrics"] = {}
        for name, field in (("native_stateful","native_stateful_found"),
                            ("prism_model_bfs","model_bfs_found"),
                            ("prism_model_goal","model_guided_found")):
            tp=sum(r["positive_truth"] and r[field] for r in results["comparisons"])
            fp=sum(not r["positive_truth"] and r[field] for r in results["comparisons"])
            fn=sum(r["positive_truth"] and not r[field] for r in results["comparisons"])
            tn=sum(not r["positive_truth"] and not r[field] for r in results["comparisons"])
            results["metrics"][name]={
                "tp":tp,"fp":fp,"fn":fn,"tn":tn,
                "precision":tp/(tp+fp) if tp+fp else None,
                "recall":tp/(tp+fn) if tp+fn else None,
            }
        results["status"]="PASS: comparable local development EVM evidence measured"
    finally:
        (out/"evaluation.json").write_text(
            json.dumps(results,indent=2,sort_keys=True)+"\n", encoding="utf-8")
    return results


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--candidate",type=Path,required=True)
    args=p.parse_args()
    a=evaluate(args.root.resolve(),args.output.resolve(),args.candidate.resolve())
    print("D22_STATUS",a["status"])
    print("D22_METRICS",json.dumps(a["metrics"],sort_keys=True))
    for name,r in a["native_runs"].items():
        print("D22_RUN",name,"wall",round(r["wall_seconds"],4),
              "child_cpu",round(r["child_cpu_seconds"],4),
              "code",r["exit_code"],
              "tests",[(x,v["status"]) for x,v in r["rows"].items()])


if __name__=="__main__":
    main()
