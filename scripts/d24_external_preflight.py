"""D2.4 reproducible external corpus preflight, NOT a vulnerability detector.

Downloads only three PINNED GitHub source blobs into a TEMPORARY directory
(no redistribution in the repository), verifies original Git blob hashes,
and classifies obvious labels/comments as leakage risks. Never presents this
public training corpus as a blind real-world holdout. Zero external targets
are contacted for exploit/probe; sources are read-only.
"""
from __future__ import annotations

import argparse
from hashlib import sha1, sha256
import json
from pathlib import Path, PurePosixPath
import re
from urllib.request import urlopen

CORPUS_REPO = "SunWeb3Sec/DeFiVulnLabs"
REF_PATTERN = re.compile(r"^[0-9a-f]{40}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
LEAK_TERMS = re.compile(
    r"(?i)\b(vulnerab(?:ility|le)|exploit|attack|hacked|mitigation|bug|front.run|"
    r"price manipulation|first deposit|stale|poc|security issue)\b")


def verify_manifest(m: dict) -> list[dict]:
    if not isinstance(m, dict) or m.get("schema")!="prism-d24-external-corpus-v1":
        raise ValueError("wrong corpus manifest")
    if m.get("status")!="PUBLIC_DEVELOPMENT_ONLY":
        raise ValueError("unsupported blind label claim")
    commit=m.get("commit")
    if not isinstance(commit,str) or not REF_PATTERN.fullmatch(commit):
        raise ValueError("unpinned or invalid external commit")
    if m.get("source_repository")!=f"https://github.com/{CORPUS_REPO}":
        raise ValueError("source repository mismatch")
    cases=m.get("cases")
    if not isinstance(cases,list) or len(cases)!=3:
        raise ValueError("expected 3 specified external cases")
    seen=set()
    for row in cases:
        if not isinstance(row,dict) or set(row)!={"id","path","git_blob_sha1"}:
            raise ValueError("invalid external case keys")
        ident=row["id"]
        if not isinstance(ident,str) or not ident.isidentifier() or ident in seen:
            raise ValueError("invalid or repeated id")
        seen.add(ident)
        path=row["path"]
        if (not isinstance(path,str) or not path.startswith("src/test/")
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or "\\" in path or not path.endswith(".sol")):
            raise ValueError("unsafe external path")
        if not isinstance(row["git_blob_sha1"],str) or not HEX40.fullmatch(row["git_blob_sha1"]):
            raise ValueError("missing immutable git blob fingerprint")
    return cases


def blob_sha(payload: bytes) -> str:
    return sha1(f"blob {len(payload)}\0".encode()+payload).hexdigest()


def comment_exposure(source: str) -> dict:
    """Conservative detector of label-bearing comments; never pretends to
    parse Solidity syntax or to know whether comments are harmless."""
    pattern=re.compile(r"/\*.*?\*/|//[^\r\n]*",flags=re.S)
    comments=pattern.findall(source)
    flagged=[x.strip()[:240] for x in comments if LEAK_TERMS.search(x)]
    return {"comment_count":len(comments),
            "possible_label_comment_count":len(flagged),
            "possible_label_comment_excerpts":flagged[:3],
            "leakage_risk":"PUBLIC_LABELED_TRAINING_CORPUS" if flagged else "UNKNOWN"}


def acquire(manifest_file: Path, out: Path, *, fetcher=None) -> dict:
    manifest=json.loads(manifest_file.read_text(encoding="utf-8"))
    cases=verify_manifest(manifest)
    commit=manifest["commit"]
    if fetcher is None:
        def fetcher(url: str) -> bytes:
            with urlopen(url,timeout=25) as response:
                return response.read(2_000_001)
    result=[]
    for case in cases:
        url=f"https://raw.githubusercontent.com/{CORPUS_REPO}/{commit}/{case['path']}"
        raw=fetcher(url)
        if not isinstance(raw,bytes) or len(raw)>2_000_000:
            raise ValueError("invalid or oversized source response")
        if blob_sha(raw)!=case["git_blob_sha1"]:
            raise ValueError(f"external source integrity mismatch: {case['id']}")
        decoded=raw.decode("utf-8")
        info=comment_exposure(decoded)
        result.append({
            "id":case["id"],"source_path":case["path"],
            "source_sha256":sha256(raw).hexdigest(),
            "git_blob_sha1":blob_sha(raw),
            "source_bytes":len(raw),
            "external_commit":commit,
            "source_url":url,
            **info,
            "property_or_vulnerability_class":"WITHHELD_FROM_DETECTOR",
            "verified_reproduction":"NOT_RUN",
        })
    output={
        "schema":"prism-d24-external-preflight-v1",
        "status":"INTEGRITY_VERIFIED_NOT_VULNERABILITY_EVALUATED",
        "corpus_is_blind":False,
        "source_commit":commit,
        "input_manifest_sha256":sha256(manifest_file.read_bytes()).hexdigest(),
        "files":result,
        "read_only":True,
        "scientific_limit":"Public vulnerability training examples leak classes in names, comments and test bodies; cannot serve as honest blind holdout. No TP/FP/FN can be claimed.",
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"preflight.json").write_text(json.dumps(output,indent=2,sort_keys=True)+"\n")
    print("D24_VERIFIED_EXTERNAL_FILES",len(result))
    for row in result:
        print("D24_FILE",row["id"],row["source_sha256"],
              "COMMENT_LABEL_SIGNALS",row["possible_label_comment_count"])
    print("D24_STATUS",output["status"])
    return output


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--manifest",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    acquire(args.manifest,args.output)


if __name__=="__main__":
    main()
