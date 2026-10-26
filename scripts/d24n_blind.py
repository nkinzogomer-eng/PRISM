"""D2.4N prospectively selected existing target files, no posthoc tuning.

This is a source-only generalization trial. Neither candidate counts nor
successful compilation establish a vulnerability or zero-day.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from time import perf_counter

from prism.d24m_cfg import cfg_hypotheses
from scripts.d24n_compiler_matrix import choose, PINNED, permits, _PRAGMA
from scripts.d24m_retrospective import _project
from scripts.d24l_prospective import retrieve_closure
from scripts.d24j_label_free_trial import git_blob_digest
from scripts.d24c_structural_frontier import mask_noncode


FROZEN_TARGETS=(
    ("N1","compound-finance/comet","f766f51583c23acc33b2a7824654ef2029a96804",
     "contracts/CometRewards.sol"),
    ("N2","OpenZeppelin/openzeppelin-contracts","11565e5f6277a320408025e649240056ba6a3919",
     "contracts/governance/extensions/GovernorTimelockControl.sol"),
)


def validate(reg:dict,graph_source:bytes,semver_source:bytes) -> None:
    if reg.get("schema")!="scm.prism.d24n.v1-untouched-verified-path-cohort":
        raise ValueError("wrong frozen scientific protocol")
    if git_blob_digest(graph_source)!=reg.get("frozen_cfg_blob"):
        raise ValueError("FROZEN_CFG_ENGINE_MISMATCH")
    if git_blob_digest(semver_source)!=reg.get("frozen_semver_blob"):
        raise ValueError("FROZEN_COMPILER_POLICY_MISMATCH")
    if tuple((r.get("id"),r.get("repository"),r.get("commit"),r.get("path"))
             for r in reg.get("cohort",[]))!=FROZEN_TARGETS:
        raise ValueError("FROZEN_TARGETS_CHANGED")
    if (reg.get("max_source_files")!=60 or reg.get("max_source_bytes")!=1_000_000 or
        reg.get("max_cfg_paths_per_function")!=64 or reg.get("max_candidates")!=64 or
        reg.get("allowed_solc")!=["0.8.24","0.8.33"]):
        raise ValueError("frozen compute budgets altered")


def evaluate(reg:dict,graph_source:bytes,semver_source:bytes,*,
             fetch=retrieve_closure,compile_source=_project) -> dict:
    validate(reg,graph_source,semver_source)
    cases=[]
    for target in reg["cohort"]:
        begin=perf_counter()
        files=None
        row={"id":target["id"],"repository":target["repository"],
             "commit":target["commit"],"path":target["path"],
             "status":"UNKNOWN_NOT_SAFE","target_candidates":0,
             "dependency_candidates":0,"new_flaws_verified":0}
        try:
            files=fetch(target)
            row["source_count"]=len(files)
            row["target_blob_sha1"]=git_blob_digest(files[target["path"]])
            policy=choose(files)
            row["compiler_version"]=policy["compiler"]
            ast=compile_source(files,target["path"],policy["compiler"])
            graph=cfg_hypotheses(ast,max_candidates=64,max_paths_per_function=64)
        except (ValueError,OSError,UnicodeError,subprocess.SubprocessError,KeyError) as exc:
            row.update(reason=str(exc)[:600],error_type=type(exc).__name__)
            if str(exc)=="NO_PINNED_COMPILER_CAN_SATISFY_CLOSURE" and files is not None:
                # Post-result DIAGNOSTIC only; never use it to retune frozen
                # candidate logic or to silently discard this cohort member.
                details=[]
                for file,raw in sorted(files.items()):
                    pragmas=_PRAGMA.findall(mask_noncode(raw.decode("utf-8")))
                    if len(pragmas)!=1:
                        continue
                    spec=pragmas[0].strip()
                    if not any(permits(spec,v) for v in PINNED):
                        details.append({"path":file,"pragma":spec})
                row["out_of_matrix_source_pragmas"]=details[:8]
        else:
            target_signals=[x for x in graph["candidates"] if x["source"]==target["path"]]
            dependencies=[x for x in graph["candidates"] if x["source"]!=target["path"]]
            row.update(status="TARGET_HYPOTHESES_UNVERIFIED" if target_signals
                       else ("DEPENDENCY_ONLY_TARGET_UNKNOWN" if dependencies
                             else "NO_TARGET_CANDIDATE_UNKNOWN"),
                       contracts=graph["contract_count"],
                       functions=graph["function_count"],
                       d24l_unsupported=graph["baseline_unsupported_functions"],
                       cfg_unsupported=graph["cfg_unsupported_functions"],
                       target_candidates=len(target_signals),
                       dependency_candidates=len(dependencies),
                       candidate_methods=[c["contract"]+"."+c["signature"]
                                          for c in target_signals],
                       verification="NO_EVM_ORACLE_ON_THIS_PUBLIC_TARGET")
        row["wall_seconds"]=perf_counter()-begin
        cases.append(row)
    return {"schema":"scm.prism.d24n.prospective-hypothesis-coverage-results.v1",
            "cohort_size":2,"targets":cases,
            "compiled_targets":sum("contracts" in x for x in cases),
            "abstentions":sum(x["status"]=="UNKNOWN_NOT_SAFE" for x in cases),
            "unverified_target_hypotheses":sum(x["target_candidates"] for x in cases),
            "unverified_dependency_hypotheses":sum(x["dependency_candidates"] for x in cases),
            "real_public_target_EVM_oracles":0,
            "new_vulnerabilities_confirmed":0,"zero_days_confirmed":0,
            "AI_API_calls":0,"new_classes_confirmed":0,
            "baseline_comparison_on_blind_targets":False,
            "frozen_engine_policy":"UNCHANGED_POST_SELECTION",
            "interpretation":"TRUE_UNSEEN_SOURCE_GENERALIZATION_NOT_BUG_RECALL"}


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--registry",required=True,type=Path)
    parser.add_argument("--graph",required=True,type=Path)
    parser.add_argument("--compiler",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args()
    report=evaluate(json.loads(args.registry.read_text()),args.graph.read_bytes(),
                    args.compiler.read_bytes())
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("D24N_BLIND_RESULT",json.dumps({
        "compiled":report["compiled_targets"],
        "cases":{x["id"]:{"status":x["status"],"error":x.get("reason"),
                 "unsupported":x.get("cfg_unsupported"),
                 "compiler":x.get("compiler_version"),
                 "out_of_matrix_pragmas":x.get("out_of_matrix_source_pragmas",[]),
                 "candidate_methods":x.get("candidate_methods",[]),
                 "target_candidates":x["target_candidates"]} for x in report["targets"]},
        "verified_zero_days":0},sort_keys=True))
