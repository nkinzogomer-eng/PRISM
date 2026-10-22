"""D2.4: fail-closed ingestion of *independent* revision-pinned DeFi benchmarks.

This does not discover vulnerabilities. In particular, known_bugs.json is
judge-only ground truth, NOT detector input. Public historical examples are
NOT a sealed blind holdout. A canary never counts as a vulnerability.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
TARGET_IDS = frozenset({
    "aave-v4", "superform-v2-periphery", "liquity-v2-governance",
    "origin-dollar", "drips",
})
SCHEMA = "prism-d24-independent-catalog-v1"


@dataclass(frozen=True)
class CatalogResult:
    public: dict
    judge: dict
    statistics: dict


def _must_digest(value: Any, context: str) -> None:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError(f"invalid immutable SHA at {context}")


def ingest(targets: dict, known: dict, *, catalog_commit: str) -> CatalogResult:
    """Validate pinned source repos, root-cause IDs, revisions and canary split.

    Never reuse the judge result as detector input; tests explicitly enforce
    separate schema, naming and fingerprints.
    """
    _must_digest(catalog_commit, "catalog")
    if targets.get("schema_version") != 1 or known.get("schema_version") != 1:
        raise ValueError("unsupported external catalog schema")
    tlist, klist = targets.get("targets"), known.get("targets")
    if not isinstance(tlist, list) or not isinstance(klist, list):
        raise ValueError("missing external target inventory")
    if len(tlist) != len(TARGET_IDS) or len(klist) != len(TARGET_IDS):
        raise ValueError("wrong number of pinned external targets")

    by_id = {}
    public_cases = []
    for entry in tlist:
        ident, commit, repo = entry["id"], entry["commit"], entry["repo"]
        if ident not in TARGET_IDS or ident in by_id:
            raise ValueError("duplicate or unknown target")
        _must_digest(commit, ident)
        if repo != "https://github.com/scfuzzbench/" + {
            "aave-v4": "aave-v4-scfuzzbench",
            "superform-v2-periphery": "superform-v2-periphery-scfuzzbench",
            "liquity-v2-governance": "liquity-V2-gov-scfuzzbench",
            "origin-dollar": "origin-dollar-scfuzzbench",
            "drips": "drips-fuzzing-scfuzzbench",
        }[ident]:
            raise ValueError("unapproved external target repo")
        path = entry["properties_path"]
        if not isinstance(path, str) or path.startswith("/") or ".." in path.split("/") or not path.endswith(".sol"):
            raise ValueError("unsafe property path")
        by_id[ident] = entry
        public_cases.append({"target_id": ident, "repo": repo, "commit": commit,
                             "properties_path": path,
                             "source_kind": "independent_public_scfuzzbench_target"})
    refs = {}
    total_bugs = total_canaries = indirect_evidence = 0
    for entry in klist:
        ident, commit = entry["target_id"], entry["target_commit"]
        if ident not in by_id or ident in refs:
            raise ValueError("unknown/duplicate ground-truth target")
        if commit != by_id[ident]["commit"]:
            raise ValueError(f"ground truth revision drift: {ident}")
        alias_keys = set()
        canonical = set()
        normalized_bugs = []
        normalized_canaries = []
        for kind, destination in (("known_bugs", normalized_bugs), ("canaries", normalized_canaries)):
            raw_items = entry.get(kind)
            if not isinstance(raw_items, list):
                raise ValueError(f"missing {kind}")
            for item in raw_items:
                bug_id = item["id"]
                if not isinstance(bug_id,str) or not bug_id or bug_id in canonical:
                    raise ValueError("duplicate or invalid root-cause id")
                canonical.add(bug_id)
                evidence = item.get("evidence")
                if not isinstance(evidence,list) or not evidence:
                    raise ValueError("missing reviewed root-cause evidence")
                # One upstream documented Drips issue uses a GitHub PR as evidence,
                # not a commit-anchored code URL. Treat it as WEAKER evidence
                # requiring human review, never promote to pinned proof.
                direct_evidence = False
                indirect_pr = False
                root = by_id[ident]["repo"]
                for proof in evidence:
                    u=proof["url"]
                    if not isinstance(u,str):
                        raise ValueError("unpinned external evidence")
                    if u.startswith(root + "/blob/" + commit + "/"):
                        direct_evidence = True
                    elif re.fullmatch(re.escape(root) + r"/pull/[1-9][0-9]*",u):
                        indirect_pr = True
                    else:
                        raise ValueError("unpinned external evidence")
                if indirect_pr:
                    indirect_evidence += 1
                aliases = item.get("aliases")
                if not isinstance(aliases,list) or not aliases:
                    raise ValueError("missing event aliases")
                events = []
                for a in aliases:
                    event, fuzzers = a["event"], a["fuzzers"]
                    if not isinstance(event,str) or not event or not isinstance(fuzzers,list) or not fuzzers:
                        raise ValueError("invalid alias")
                    for fuzzer in fuzzers:
                        if not isinstance(fuzzer,str) or (fuzzer,event) in alias_keys:
                            raise ValueError("ambiguous alias or fuzzer")
                        alias_keys.add((fuzzer,event))
                    events.append({"event":event, "fuzzers":sorted(fuzzers)})
                destination.append({"bug_id":bug_id, "aliases":events, "class":kind,
                                    "evidence_direct_commit_anchor":direct_evidence,
                                    "evidence_requires_human_review":indirect_pr})
        refs[ident] = {
            "target_id":ident, "target_commit":commit,
            "known_bugs":normalized_bugs, "canaries":normalized_canaries,
        }
        total_bugs += len(normalized_bugs)
        total_canaries += len(normalized_canaries)
    if set(by_id) != set(refs):
        raise ValueError("known-bug catalog missing targets")

    public = {
        "schema": SCHEMA, "catalog_commit": catalog_commit,
        "cases": sorted(public_cases,key=lambda x:x["target_id"]),
        "policy": "No known-bug IDs, canary aliases, labels or exploit sequences supplied to detector",
    }
    judge = {
        "schema":"prism-d24-judge-only-v1",
        "catalog_commit":catalog_commit,
        "entries":[refs[ident] for ident in sorted(refs)],
        "warning":"PUBLIC labels: independent origin, not an actual blind holdout",
    }
    return CatalogResult(public,judge,{
        "target_count":len(public_cases),
        "externally_documented_issue_count":total_bugs,
        "canary_count":total_canaries,
        "indirect_pr_evidence_count":indirect_evidence,
        "catalogued_issues_needing_evidence_review":sum(
            int(x["evidence_requires_human_review"]) for record in refs.values()
            for x in record["known_bugs"]
        ),
        "execution_status":"NOT_RUN",
        "confirmed_prism_discoveries":None,
        "baseline_comparison":"NOT_RUN",
    })


def normalize_events(judge: dict, *, target_id: str, fuzzer: str,
                     observed_events: list[str]) -> dict:
    """Normalize *reported event names* without treating a canary as a bug.

    Event mapping alone is NOT evidence that the scanner really ran or that
    a PRISM candidate was independently confirmed. No TP/FP/FN claim here.
    """
    groups=[x for x in judge.get("entries",[]) if x["target_id"]==target_id]
    if len(groups)!=1:
        raise ValueError("unknown target")
    lookup={}
    for category in ("known_bugs","canaries"):
        for bug in groups[0][category]:
            for alias in bug["aliases"]:
                if fuzzer in alias["fuzzers"]:
                    key=alias["event"]
                    if key in lookup:
                        raise ValueError("ambiguous event")
                    lookup[key]=(category,bug["bug_id"])
    known=set()
    canary=set()
    unmapped=set()
    for event in observed_events:
        if not isinstance(event,str) or not event:
            raise ValueError("invalid event name")
        if event not in lookup:
            unmapped.add(event)
        elif lookup[event][0]=="canaries":
            canary.add(lookup[event][1])
        else:
            known.add(lookup[event][1])
    return {
        "known_event_ids":sorted(known),
        "canary_ids_excluded":sorted(canary),
        "unmapped_events":sorted(unmapped),
        "observation_claim":"EVENT_MAPPING_ONLY_NOT_INDEPENDENTLY_EVM_CONFIRMED",
    }


def fingerprints(raw_targets: bytes, raw_truth: bytes) -> dict:
    return {"targets_sha256":sha256(raw_targets).hexdigest(),
            "known_bugs_sha256":sha256(raw_truth).hexdigest()}
