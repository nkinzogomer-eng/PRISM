"""D2.4M: transparent compiler/CFG repair replay and native branch EVM gate.

L1/L2 were already exposed during D2.4L. This is a RETROSPECTIVE
development measurement, never another prospective zero-day holdout.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter

from prism.d24m_cfg import cfg_hypotheses
from scripts.d24m_compiler_matrix import select_compiler
from scripts.d24l_prospective import retrieve_closure, TARGETS
from scripts.d24j_label_free_trial import git_blob_digest


NATIVE_TESTS={
    "test_branch_true_has_reentrant_value_capture()",
    "test_branch_false_blocks_reentrant_value_capture()",
    "test_honest_single_withdraw_preserves_value_on_both_paths()",
}


def _build_info(project:Path, selected: str, relative: str) -> dict:
    (project/"foundry.toml").write_text(
        '[profile.default]\nsrc = "contracts"\ntest = "test"\n'
        'out = "out"\nlibs = []\n'
        f'solc_version = "{selected}"\n'
        'ffi = false\nbuild_info = true\n',encoding="utf-8")
    run=subprocess.run(["forge","build","--force","--build-info","--ast"],
                       cwd=project,text=True,capture_output=True,check=False,timeout=180)
    if run.returncode:
        raise ValueError("COMPILER_BUILD_FAILED:"+(run.stderr or run.stdout)[-450:])
    results=[]
    for path in (project/"out/build-info").glob("*.json"):
        root=json.loads(path.read_text())
        if relative in root.get("output",{}).get("sources",{}):
            results.append(root["output"])
    if len(results)!=1:
        raise ValueError("COMPILER_AST_NOT_SINGLE_BUILD")
    return results[0]


def _project(sources:dict[str,bytes],relative: str,version: str) -> dict:
    with TemporaryDirectory(prefix="prism-d24m-compiler-") as directory:
        path=Path(directory)
        (path/"test").mkdir()
        (path/"contracts").mkdir()
        for rel,raw in sources.items():
            file=path/rel
            file.parent.mkdir(parents=True,exist_ok=True)
            file.write_bytes(raw)
        return _build_info(path,version,relative)


def _verify_native(raw: str, code: int) -> dict:
    try:
        value=json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("native oracle not structured JSON") from exc
    rows={}
    for case in value.values():
        if not isinstance(case,dict):
            continue
        for name,result in case.get("test_results",{}).items():
            if name in rows:
                raise ValueError("duplicate native test")
            rows[name]=result.get("status")
    if set(rows)!=NATIVE_TESTS or code!=0 or any(status!="Success" for status in rows.values()):
        raise ValueError("known branch EVM controls do not all pass")
    return {"passed":len(rows),"total":len(NATIVE_TESTS),
            "stdout_sha256":sha256(raw.encode()).hexdigest()}


def branch_witness(source:Path,out:Path) -> dict:
    if not source.is_file():
        raise ValueError("independently authored branch test missing")
    with TemporaryDirectory(prefix="prism-d24m-branch-evm-") as directory:
        root=Path(directory)
        (root/"contracts").mkdir()
        (root/"test").mkdir()
        target=root/"test"/source.name
        target.write_bytes(source.read_bytes())
        ast=_build_info(root,"0.8.24","test/"+source.name)
        analysis=cfg_hypotheses(ast)
        relevant=[c for c in analysis["candidates"] if c["contract"]=="D24MConditionalBank"
                  and c["signature"].startswith("withdraw(")]
        if len(relevant)!=1 or not relevant[0]["branches"] or not relevant[0]["branches"][0].startswith("T:"):
            raise ValueError("compiler typed CFG did not isolate intentionally vulnerable true branch")
        run=subprocess.run(["forge","test","--match-contract","D24MBranchValueTest","--json"],
                           cwd=root,text=True,capture_output=True,check=False,timeout=180)
        (out/"branch-native.stdout.json").write_text(run.stdout)
        (out/"branch-native.stderr.txt").write_text(run.stderr)
        native=_verify_native(run.stdout,run.returncode)
    return {"known_synthetic_branch_candidates":len(relevant),
            "syntactic_branch_evidence":relevant[0]["branches"],
            "native":native,"intentionally_known_reentrancy_not_zero_day":True,
            "original_fixture_sha256":sha256(source.read_bytes()).hexdigest()}


def run_retro(registration:dict, project:Path, out:Path) -> dict:
    if registration.get("schema")!="scm.prism.d24l.prospective-compiler-holdout.v1" or tuple(
        (x.get("id"),x.get("repository"),x.get("commit"),x.get("path"))
        for x in registration.get("targets",[]))!=TARGETS:
        raise ValueError("retrospective targets must remain the exact published D2.4L negatives")
    out.mkdir(parents=True,exist_ok=True)
    started=perf_counter()
    rows=[]
    for target in registration["targets"]:
        start=perf_counter()
        entry={"id":target["id"],"source_repo":target["repository"],
               "source_commit":target["commit"],"path":target["path"],
               "status":"UNKNOWN_NOT_SAFE","new_vulnerabilities":0}
        try:
            closure=retrieve_closure(target)
            selected=select_compiler(closure)
            ast=_project(closure,target["path"],selected["selected"])
            graph=cfg_hypotheses(ast)
        except (ValueError,OSError,UnicodeError,subprocess.SubprocessError,KeyError) as exc:
            entry["reason"]=str(exc)[:600]
        else:
            primaries=[x for x in graph["candidates"] if x["source"]==target["path"]]
            dependencies=[x for x in graph["candidates"] if x["source"]!=target["path"]]
            entry.update(status="COMPILED_SOURCE_HYPOTHESES_ONLY",
                         compiler=selected["selected"],
                         original_git_blob_sha1=git_blob_digest(closure[target["path"]]),
                         number_of_sources=len(closure),
                         contracts=graph["contract_count"],
                         functions=graph["function_count"],
                         d24l_unsupported=graph["baseline_unsupported_functions"],
                         d24m_unsupported=graph["cfg_unsupported_functions"],
                         scoped_target_hypotheses=len(primaries),
                         dependency_hypotheses=len(dependencies),
                         target_hypothesis_methods=[x["contract"]+"."+x["signature"]
                                                    for x in primaries],
                         vulnerability_verdict="NOT_EVALUATED_NO_INDEPENDENT_TARGET_ORACLE")
        entry["seconds"]=perf_counter()-start
        rows.append(entry)
    branch=branch_witness(project/"benchmarks/defi/d24m/D24MBranchValue.t.sol",out)
    result={"schema":"scm.prism.d24m.retrospective-repair-plus-native-branch.v1",
            "methodology":"RETROSPECTIVE_ALREADY_SEEN_TARGETS_NOT_NEW_BLIND_EVIDENCE",
            "targets":rows,"compiled":sum(x["status"]!="UNKNOWN_NOT_SAFE" for x in rows),
            "native_branch":branch,"confirmed_new_vulnerabilities":0,
            "confirmed_zero_days":0,"real_ciel_hypotheses_tested":0,
            "gpu_used":False,"llm_calls":0,"total_wall_seconds":perf_counter()-started}
    (out/"result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--registration",type=Path,required=True)
    ap.add_argument("--root",type=Path,default=Path("."))
    ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args()
    report=run_retro(json.loads(a.registration.read_text()),a.root.resolve(),a.out.resolve())
    print("D24M_REPLAY_GATE",json.dumps({
        "compiled":report["compiled"],
        "targets":{r["id"]:{"status":r["status"],"compiler":r.get("compiler"),
                  "old_unknown":r.get("d24l_unsupported"),
                  "new_unknown":r.get("d24m_unsupported"),
                  "target_hypotheses":r.get("scoped_target_hypotheses"),
                  "reason":r.get("reason")} for r in report["targets"]},
        "branch_native":report["native_branch"]["native"]["passed"],
        "zero_days":0},sort_keys=True))
