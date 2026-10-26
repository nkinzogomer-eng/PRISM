"""D2.4J prospective evaluation of a FROZEN proposer on unseen sources.

Chosen repositories/commits were published before source inspection. Parser
abstentions, unavailable files and no candidates are negative/unknown results;
the experiment NEVER retries with retuned hypotheses or different targets.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
from time import perf_counter
from urllib.request import Request, urlopen

from prism.defi_blind_proposer import propose_relations
from scripts.d24j_label_free_trial import git_blob_digest

FROZEN_MANIFEST_SHA256="f0aaad730638ebc02e10af280da0d28c68492d9a00eafa720ea4b6ea2705bc37"
FROZEN_TARGETS=(
    ("P1","Vectorized/solady","258f67cc71e39cff307b726939ade17e9d8bcf5c","src/tokens/ERC4626.sol"),
    ("P2","morpho-org/morpho-blue","9cf6d5b844625ba108e36d1cf911f5d2faf7c136","src/Morpho.sol"),
    ("P3","Uniswap/v3-core","5ea68a77cb541c6b3812df783be71ba8c081e25f","contracts/UniswapV3Pool.sol"),
)


def run_prospective(manifest: dict, *, frozen_engine_source: bytes,
                    fetch: callable) -> dict:
    if manifest.get("schema")!="scm.prism.d24j.prospective-unknown-defi.v1":
        raise ValueError("unexpected preregistration version")
    if git_blob_digest(frozen_engine_source)!=manifest["frozen_proposer_git_blob_sha1"]:
        raise ValueError("frozen proposer source has changed: prohibit post-hoc tuning")
    cohort=manifest["corpus"]
    if tuple((r.get("id"),r.get("repository"),r.get("commit"),r.get("path"))
             for r in cohort)!=FROZEN_TARGETS:
        raise ValueError("prospective source list has changed")
    records=[]
    for row in cohort:
        started=perf_counter()
        record={"id":row["id"],"repository":row["repository"],
                "commit":row["commit"],"path":row["path"],
                "generated":0,"family_counts":{},
                "confirmed_real_vulnerabilities":0}
        try:
            source=fetch(row)
            if type(source) is not bytes or not 0<len(source)<=manifest["source_budget_bytes"]:
                raise ValueError("source violates size/type budget")
            record["source_sha256"]=sha256(source).hexdigest()
            record["source_git_blob_sha1"]=git_blob_digest(source)
        except (OSError,ValueError,UnicodeError) as exc:
            record.update(status="UNKNOWN_NOT_SAFE",reason="SOURCE_UNAVAILABLE_OR_INVALID",
                          error_type=type(exc).__name__)
        else:
            try:
                result=propose_relations(source.decode("utf-8",errors="strict"),
                        max_candidates=manifest["max_candidates_per_source"])
            except (ValueError,UnicodeError) as exc:
                record.update(status="UNKNOWN_NOT_SAFE",reason="FRONTEND_UNSUPPORTED",
                              error_type=type(exc).__name__)
            else:
                family_counts={}
                for candidate in result["candidates"]:
                    family=candidate["family"]
                    family_counts[family]=family_counts.get(family,0)+1
                record.update(status="HYPOTHESES_UNVERIFIED" if result["candidates"]
                              else "NO_CANDIDATES_UNKNOWN",
                              generated=len(result["candidates"]),
                              omitted_for_budget=result["omitted_for_budget"],
                              family_counts=family_counts,
                              function_count=result["function_count"])
        record["source_trial_wall_seconds"]=perf_counter()-started
        records.append(record)
    return {
        "schema":"scm.prism.d24j.prospective-output-v1",
        "precommitted_engine_git_blob_sha1":manifest["frozen_proposer_git_blob_sha1"],
        "cohort_count":len(cohort),"results":records,
        "candidates_total":sum(r["generated"] for r in records),
        "abstained_or_unavailable":sum(r["status"]=="UNKNOWN_NOT_SAFE" for r in records),
        "no_candidate_unknown":sum(r["status"]=="NO_CANDIDATES_UNKNOWN" for r in records),
        "new_vulnerability_classes_verified":0,
        "new_zero_days_confirmed":0,
        "native_evm_tests_performed":0,
        "baseline_comparisons_performed":0,
        "no_post_hoc_engine_tuning":True,
        "interpretation":"Prospective source-only generalization diagnostic; not a vulnerability recall benchmark",
    }


def fetch_pinned(row: dict) -> bytes:
    if ((row.get("id"),row.get("repository"),row.get("commit"),row.get("path"))
            not in FROZEN_TARGETS):
        raise ValueError("unapproved prospective public source")
    if (not re.fullmatch(r"[a-zA-Z0-9_./-]+\.sol",row["path"])
            or ".." in row["path"].split("/")):
        raise ValueError("unsafe frozen source path")
    url=("https://raw.githubusercontent.com/"+row["repository"]+"/"+
         row["commit"]+"/"+row["path"])
    with urlopen(Request(url,headers={"User-Agent":"PRISM-D24J-prospective-source"}),
                 timeout=25) as response:
        return response.read(1_000_001)


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--preregistration",required=True,type=Path)
    p.add_argument("--engine",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args()
    source_bytes=a.preregistration.read_bytes()
    if sha256(source_bytes).hexdigest()!=FROZEN_MANIFEST_SHA256:
        raise ValueError("prospective manifest changed after published freeze")
    registry=json.loads(source_bytes)
    output=run_prospective(registry,frozen_engine_source=a.engine.read_bytes(),fetch=fetch_pinned)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(output,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("D24J_PROSPECTIVE",json.dumps({
        "statuses":{row["id"]:row["status"] for row in output["results"]},
        "candidates":{row["id"]:row["generated"] for row in output["results"]},
        "abstained":output["abstained_or_unavailable"],
        "confirmed_zero_days":0},sort_keys=True))
