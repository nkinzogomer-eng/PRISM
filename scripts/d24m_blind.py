"""True new target cohort measured with immutable D2.4M compiler/CFG engine.

Only tests source-to-hypothesis generalization, not bug recall or zero-days.
The selected frozen targets have never been used to tune this engine.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from time import perf_counter

from prism.d24m_cfg import cfg_hypotheses
from scripts.d24m_compiler_matrix import select_compiler
from scripts.d24m_retrospective import _project
from scripts.d24l_prospective import retrieve_closure
from scripts.d24j_label_free_trial import git_blob_digest


COHORT=(
    ("M1","compound-finance/comet","f766f51583c23acc33b2a7824654ef2029a96804",
     "contracts/Comet.sol"),
    ("M2","OpenZeppelin/openzeppelin-contracts","11565e5f6277a320408025e649240056ba6a3919",
     "contracts/governance/Governor.sol"),
)


def validate_frozen(reg:dict, cfg_source:bytes, compiler_source:bytes) -> None:
    if reg.get("schema")!="scm.prism.d24m.frozen-typed-cfg-generalization.v1":
        raise ValueError("invalid experiment schema")
    if git_blob_digest(cfg_source)!=reg["frozen_engine_blob_sha1"]:
        raise ValueError("CFG ENGINE CHANGED AFTER TARGET FREEZE")
    if git_blob_digest(compiler_source)!=reg["frozen_compiler_selector_blob_sha1"]:
        raise ValueError("COMPILER POLICY CHANGED AFTER TARGET FREEZE")
    selected=tuple((x.get("id"),x.get("repository"),x.get("commit"),x.get("path"))
                   for x in reg.get("cohort",[]))
    if selected!=COHORT:
        raise ValueError("prospective target list changed")
    if (reg.get("max_paths_per_function")!=64 or
        reg.get("max_candidates_per_source")!=64 or
        reg.get("max_source_closure_bytes")!=1_000_000 or
        reg.get("allowed_tool_versions")!=["0.8.24","0.8.33"]):
        raise ValueError("predeclared budget changed")


def run_blind(reg:dict,cfg_source:bytes,compiler_source:bytes,
              *,fetch_closure=retrieve_closure, compile_source=_project) -> dict:
    validate_frozen(reg,cfg_source,compiler_source)
    rows=[]
    for target in reg["cohort"]:
        started=perf_counter()
        row={"id":target["id"],"repository":target["repository"],
             "commit":target["commit"],"source_path":target["path"],
             "status":"UNKNOWN_NOT_SAFE","target_candidate_count":0,
             "dependency_candidate_count":0,"confirmed_vulnerabilities":0}
        try:
            closure=fetch_closure(target)
            row["root_source_git_blob_sha1"]=git_blob_digest(closure[target["path"]])
            row["source_count"]=len(closure)
            row["source_bytes"]=sum(map(len,closure.values()))
            policy=select_compiler(closure)
            row["compiler_version"]=policy["selected"]
            compiled=compile_source(closure,target["path"],policy["selected"])
            graph=cfg_hypotheses(compiled,max_candidates=64,max_paths_per_function=64)
        except (ValueError,OSError,UnicodeError,subprocess.SubprocessError,KeyError) as exc:
            row.update(reason=str(exc)[:500],error_type=type(exc).__name__)
        else:
            primary=[x for x in graph["candidates"] if x["source"]==target["path"]]
            dependency=[x for x in graph["candidates"] if x["source"]!=target["path"]]
            row.update(status="TARGET_HYPOTHESES_UNVERIFIED" if primary
                       else ("DEPENDENCY_ONLY_TARGET_UNKNOWN" if dependency
                             else "NO_CANDIDATE_TARGET_UNKNOWN"),
                       contracts=graph["contract_count"],
                       functions=graph["function_count"],
                       d24l_unsupported=graph["baseline_unsupported_functions"],
                       d24m_unsupported=graph["cfg_unsupported_functions"],
                       target_candidate_count=len(primary),
                       dependency_candidate_count=len(dependency),
                       target_hypothesis_methods=[x["contract"]+"."+x["signature"]
                                                  for x in primary],
                       verification="NOT_PERFORMED_NO_INDEPENDENT_NATIVE_ORACLE")
        row["wall_seconds"]=perf_counter()-started
        rows.append(row)
    return {"schema":"scm.prism.d24m.prospective-new-source-results.v1",
            "target_count":2,"recorded_targets":rows,
            "compiled_count":sum("contracts" in r for r in rows),
            "abstention_count":sum(r["status"]=="UNKNOWN_NOT_SAFE" for r in rows),
            "target_hypotheses_total":sum(r["target_candidate_count"] for r in rows),
            "dependency_hypotheses_total":sum(r["dependency_candidate_count"] for r in rows),
            "confirmed_new_vulnerabilities":0,"confirmed_zero_days":0,
            "native_oracles_executed":0,"classical_baselines_run_on_new_cohort":False,
            "no_model_calls":True,"frozen_without_posthoc_engine_tuning":True,
            "epistemic_scope":"SOURCE_ONLY_GENERALIZATION_NOT_VULNERABILITY_RECALL"}


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--registration",type=Path,required=True)
    ap.add_argument("--cfg",type=Path,required=True)
    ap.add_argument("--compiler",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    report=run_blind(json.loads(a.registration.read_text()),
                     a.cfg.read_bytes(),a.compiler.read_bytes())
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("D24M_PROSPECTIVE",json.dumps({
        "compiled":report["compiled_count"],
        "targets":{x["id"]:{"status":x["status"],
                 "reason":x.get("reason"),"old_unknown":x.get("d24l_unsupported"),
                 "new_unknown":x.get("d24m_unsupported"),
                 "target_candidates":x["target_candidate_count"]}
                 for x in report["recorded_targets"]},
        "zero_days":0},sort_keys=True))
