"""Reproducible public-source, label-free D2.4J DeFi candidate experiment.

Only downloads immutable public source blobs; never invokes target code, makes
chain transactions, or consumes any vulnerability classification/patch labels.
An unavailable upstream source is ERROR, not 'zero findings'.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import resource
from time import perf_counter
from urllib.request import Request, urlopen

from prism.defi_blind_proposer import propose_relations


_REPO = re.compile(r"^[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PATH = re.compile(r"^[A-Za-z0-9_./-]+\.sol$")
_SHA1 = _COMMIT


def validate_target(row: dict) -> None:
    if type(row) is not dict or set(row) != {
        "id","repository","commit","path","source_kind","git_blob_sha1"
    }:
        raise ValueError("unexpected frozen target fields")
    if row["id"] not in ("A","B","C") or row["source_kind"]!="public_open_source_solidity":
        raise ValueError("unapproved target type")
    if not _REPO.fullmatch(row["repository"]) or not _COMMIT.fullmatch(row["commit"]):
        raise ValueError("must fetch fixed public GitHub commit")
    if not _PATH.fullmatch(row["path"]) or ".." in row["path"].split("/"):
        raise ValueError("unsafe source path")
    if not _SHA1.fullmatch(row["git_blob_sha1"]):
        raise ValueError("source git blob checksum required")


def git_blob_digest(data: bytes) -> str:
    return sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def evaluate_frozen_sources(manifest: dict, source_bytes: dict[str,bytes]) -> dict:
    """Pure experiment: source never receives a label, expected bug count or patch."""
    if type(manifest) is not dict or manifest.get("schema") != "scm.prism.d24j.blind-defi-preregistration.v1":
        raise ValueError("unknown preregistration schema")
    if set(source_bytes)!=set(row["id"] for row in manifest["cohort"]):
        raise ValueError("incomplete frozen cohort")
    cap=manifest["budgets"]["max_candidates_per_source"]
    records=[]
    for row in manifest["cohort"]:
        validate_target(row)
        data=source_bytes[row["id"]]
        if type(data) is not bytes or not 0 < len(data) <= 1_000_000:
            raise ValueError("invalid source size")
        if git_blob_digest(data)!=row["git_blob_sha1"]:
            raise ValueError("source git blob digest mismatch")
        text=data.decode("utf-8",errors="strict")
        t=perf_counter()
        trial=propose_relations(text,max_candidates=cap)
        records.append({"id":row["id"],"source_sha256":sha256(data).hexdigest(),
                        "source_git_blob_sha1":row["git_blob_sha1"],
                        "candidates":trial["candidates"],
                        "generated":trial["generated_before_budget"],
                        "omitted_for_budget":trial["omitted_for_budget"],
                        "function_count":trial["function_count"],
                        "source_only_cpu_wall_seconds":perf_counter()-t,
                        "status":"HYPOTHESES_NOT_FINDINGS" if trial["candidates"]
                                 else "NO_HYPOTHESES_UNKNOWN",
                        "actual_native_evm_verification":"NOT_PERFORMED"})
    return {
        "schema":"scm.prism.d24j.frozen-source-label-free-v1",
        "stage":"source_only_candidate_generation",
        "preregistration_sha256":sha256(json.dumps(manifest,sort_keys=True,
             separators=(",",":"),ensure_ascii=False).encode()).hexdigest(),
        "source_count":len(records),"cases":records,
        "candidates_total":sum(r["generated"] for r in records),
        "confirmed_new_vulnerability_classes":0,
        "confirmed_real_world_zero_days":0,
        "real_ciel_hypotheses_tested":0,
        "confidence":"HYPOTHESES_ONLY_NO_SEMANTIC_ATTESTATION",
        "classical_baseline_compared":False,
        "honest_limit":"Must still run independent native EVM observers before scoring bug recall",
    }


def fetch_public_source(row: dict) -> bytes:
    validate_target(row)
    url=("https://raw.githubusercontent.com/"+row["repository"]+"/"+
         row["commit"]+"/"+row["path"])
    req=Request(url,headers={"User-Agent":"PRISM-D24J-preregistered-public-source-research"})
    with urlopen(req,timeout=25) as response:
        content=response.read(1_000_001)
    if len(content)>1_000_000:
        raise ValueError("source response larger than resource budget")
    if git_blob_digest(content)!=row["git_blob_sha1"]:
        raise ValueError("remote source integrity failed")
    return content


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--preregistration",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    frozen=json.loads(args.preregistration.read_text(encoding="utf-8"))
    sources={row["id"]:fetch_public_source(row) for row in frozen["cohort"]}
    result=evaluate_frozen_sources(frozen,sources)
    peak_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    result["process_max_rss_kib_linux"]=peak_kib
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print("D24J_LABEL_FREE",json.dumps({
        "source_count":result["source_count"],
        "candidate_counts":{r["id"]:r["generated"] for r in result["cases"]},
        "new_verified_zero_days":0,"native_EVM":"NOT_PERFORMED",
        "status":"SOURCE_HYPOTHESIS_GATE_ONLY",
    },sort_keys=True))
