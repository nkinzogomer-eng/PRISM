"""D2.4L independent new-contract-family compiler coverage holdout.

The hypotheses engine was published and frozen BEFORE choosing either new
source. This gate measures AST/graph coverage only: unknown compilation and
zero candidates stay in the denominator; no fabricated vulnerability recall.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import posixpath
import re
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter
from urllib.request import Request, urlopen

from prism.d24l_typed_graph import typed_graph
from scripts.d24j_label_free_trial import git_blob_digest
from scripts.d24k_value_influence import IMPORT


TARGETS=(
    ("L1","OpenZeppelin/openzeppelin-contracts","11565e5f6277a320408025e649240056ba6a3919",
     "contracts/access/manager/AccessManager.sol"),
    ("L2","aave/aave-v3-core","782f51917056a53a2c228701058a6c3fb233684a",
     "contracts/protocol/pool/Pool.sol"),
)


def validate_registration(reg: dict, engine: bytes) -> None:
    if reg.get("schema")!="scm.prism.d24l.prospective-compiler-holdout.v1":
        raise ValueError("prospective schema mismatch")
    if git_blob_digest(engine)!=reg.get("frozen_engine_blob_sha1"):
        raise ValueError("frozen AST graph source modified after cohort selection")
    if tuple((r.get("id"),r.get("repository"),r.get("commit"),r.get("path"))
             for r in reg.get("targets", []))!=TARGETS:
        raise ValueError("cohort target changed after preregistration")
    p=reg.get("policy",{})
    if (p.get("source_count")!=2 or p.get("max_source_files_per_target")!=60 or
        p.get("max_source_closure_bytes")!=1_000_000 or
        p.get("fixed_solc_version")!="0.8.24" or p.get("max_candidates")!=64):
        raise ValueError("preregistered resource budget altered")


def fetch_pinned(repo: str, revision: str, path: str) -> bytes:
    if (not re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+",repo)
        or not re.fullmatch(r"[a-f0-9]{40}",revision)
        or not re.fullmatch(r"[a-zA-Z0-9_./-]+\.sol",path)
        or ".." in path.split("/")):
        raise ValueError("untrusted pinned source path")
    url=f"https://raw.githubusercontent.com/{repo}/{revision}/{path}"
    with urlopen(Request(url,headers={"User-Agent":"PRISM-D24L-registered-holdout"}),
                 timeout=25) as response:
        return response.read(1_000_001)


def retrieve_closure(target: dict, fetch=fetch_pinned) -> dict[str,bytes]:
    repo,rev=target["repository"],target["commit"]
    pending=[target["path"]]
    result={}
    while pending:
        name=pending.pop()
        if name in result:
            continue
        if len(result)>=60:
            raise ValueError("SOURCE_CLOSURE_FILE_BUDGET")
        raw=fetch(repo,rev,name)
        if type(raw) is not bytes or not raw or len(raw)>1_000_000:
            raise ValueError("SOURCE_INVALID_OR_OVERSIZED")
        result[name]=raw
        if sum(map(len,result.values()))>1_000_000:
            raise ValueError("SOURCE_CLOSURE_BYTE_BUDGET")
        for import_name in IMPORT.findall(raw.decode("utf-8",errors="strict")):
            if not import_name.startswith("."):
                raise ValueError("UNRESOLVED_PACKAGE_IMPORT")
            child=posixpath.normpath(posixpath.join(posixpath.dirname(name),import_name))
            if (not child.startswith("contracts/") or
                ".." in child.split("/") or not child.endswith(".sol")):
                raise ValueError("IMPORT_OUTSIDE_FROZEN_REPOSITORY_SCOPE")
            pending.append(child)
    return result


def compile_ast(sources: dict[str,bytes], target: dict) -> dict:
    with TemporaryDirectory(prefix="prism-d24l-unseen-") as folder:
        root=Path(folder)
        for relative,blob in sources.items():
            local=root/relative
            local.parent.mkdir(parents=True,exist_ok=True)
            local.write_bytes(blob)
        (root/"test").mkdir()
        (root/"foundry.toml").write_text(
            '[profile.default]\nsrc = "contracts"\ntest = "test"\n'
            'out = "out"\nlibs = []\nsolc_version = "0.8.24"\n'
            'ffi = false\nbuild_info = true\n',encoding="utf-8")
        run=subprocess.run(["forge","build","--force","--build-info","--ast"],
                           cwd=root,text=True,capture_output=True,check=False,timeout=180)
        if run.returncode:
            raise ValueError("ORIGINAL_SOLIDITY_COMPILATION_FAILED")
        selected=[]
        for item in (root/"out/build-info").glob("*.json"):
            content=json.loads(item.read_text())
            out=content.get("output",{})
            if target["path"] in out.get("sources",{}):
                selected.append(out)
        if len(selected)!=1:
            raise ValueError("AST_BUILD_INFO_NOT_UNAMBIGUOUS")
        return selected[0]


def evaluate(reg: dict, engine: bytes, *, fetch=fetch_pinned, compiler=compile_ast) -> dict:
    validate_registration(reg,engine)
    records=[]
    for target in reg["targets"]:
        started=perf_counter()
        row={"id":target["id"],"repository":target["repository"],
             "commit":target["commit"],"path":target["path"],
             "status":"UNKNOWN_NOT_SAFE", "candidates":0,
             "confirmed_real_world_vulnerabilities":0,"zero_days_confirmed":0}
        try:
            sources=retrieve_closure(target,fetch)
            row["root_source_blob_sha1"]=git_blob_digest(sources[target["path"]])
            row["source_file_count"]=len(sources)
            row["closure_bytes"]=sum(map(len,sources.values()))
            compiled=compiler(sources,target)
            hypothesis=typed_graph(compiled,max_candidates=reg["policy"]["max_candidates"])
        except (ValueError,OSError,UnicodeError,subprocess.SubprocessError,KeyError) as exc:
            row.update(reason=str(exc)[:160],error_class=type(exc).__name__)
        else:
            row.update(status="HYPOTHESES_UNVERIFIED" if hypothesis["candidates"]
                       else "NO_CANDIDATES_UNKNOWN",
                       candidates=len(hypothesis["candidates"]),
                       generated_before_budget=hypothesis["candidate_count_before_budget"],
                       compiler_contracts=hypothesis["contract_count"],
                       compiler_functions=hypothesis["function_count"],
                       unsupported_functions=hypothesis["unsupported_function_count"],
                       unverified_candidate_summaries=[{
                           "contract":c["contract"],"signature":c["signature"],
                           "family":c["family"],"status":c["status"]}
                           for c in hypothesis["candidates"]],
                       family_counts={family:sum(c["family"]==family for c in hypothesis["candidates"])
                           for family in sorted({c["family"] for c in hypothesis["candidates"]})})
        row["wall_seconds"]=perf_counter()-started
        records.append(row)
    return {"schema":"scm.prism.d24l.prospective-compiler-coverage-result.v1",
            "frozen_engine_blob_sha1":reg["frozen_engine_blob_sha1"],
            "frozen_targets":2,"target_results":records,
            "compiled_count":sum("compiler_contracts" in x for x in records),
            "abstained_count":sum(x["status"]=="UNKNOWN_NOT_SAFE" for x in records),
            "no_candidates_unknown":sum(x["status"]=="NO_CANDIDATES_UNKNOWN" for x in records),
            "unverified_candidate_total":sum(x["candidates"] for x in records),
            "confirmed_new_vulnerabilities":0,"confirmed_zero_days":0,
            "real_evm_oracles_executed":0,
            "baseline_on_these_targets_executed":False,
            "no_post_target_engine_tuning":True,
            "scope":"Prospective compiler/code-shape generalization, NOT vulnerability recall"}


if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--registration",type=Path,required=True)
    ap.add_argument("--engine",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    x=ap.parse_args()
    data=evaluate(json.loads(x.registration.read_text()),x.engine.read_bytes())
    x.out.parent.mkdir(parents=True,exist_ok=True)
    x.out.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
    print("D24L_PROSPECTIVE",json.dumps({
        "statuses":{r["id"]:r["status"] for r in data["target_results"]},
        "candidates":{r["id"]:r["candidates"] for r in data["target_results"]},
        "details":{r["id"]:{
            "reason":r.get("reason"),
            "contracts":r.get("compiler_contracts"),
            "functions":r.get("compiler_functions"),
            "unknown_functions":r.get("unsupported_functions"),
            "hypotheses":r.get("unverified_candidate_summaries",[])}
            for r in data["target_results"]},
        "real_vulns":0,"zero_days":0},sort_keys=True))
