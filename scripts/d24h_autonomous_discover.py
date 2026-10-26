"""D2.4H: source-first automatic security hypothesis discovery CLI.

Input = a single local third-party Python source file, NOT a vulnerability
label, patch, human-selected property or preselected adapter.

Compiler proposes ALL supported families; bounded local executors verify only
safe, explicitly recognized method signatures. Other hypotheses remain
UNVERIFIED, not reported as vulnerabilities.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from time import perf_counter

from prism.cyber_hypotheses import compile_python_hypotheses
from scripts.d24g_source_only_discover import starlette_scan, werkzeug_scan, django_scan


def _strategy(source: str, candidate: dict) -> str | None:
    name = candidate["function"]
    if candidate["family"] != "path_boundary":
        return None
    if name.endswith(".lookup_path") and "StaticFiles." in name:
        return "staticfiles_local"
    if name == "safe_join":
        if "_windows_device_files" in source and "posixpath" in source:
            return "windows_url_path"
        if "SuspiciousFileOperation" in source and "abspath" in source:
            return "path_boundary_join"
    return None


def inspect_source(source_file: Path, *,
                   max_probes: int = 64,
                   max_candidates: int = 128,
                   authorized_local: bool = False,
                   enable_execution: bool = True) -> dict:
    if authorized_local is not True:
        raise PermissionError("explicit local-source authorization required")
    if not (source_file.is_file() and source_file.suffix == ".py"):
        raise ValueError("supported local Python source required")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 512:
        raise ValueError("invalid candidate resource budget")
    if type(max_probes) is not int or not 1 <= max_probes <= 1000:
        raise ValueError("invalid probe resource budget")
    before = source_file.read_bytes()
    if len(before) > 1_000_000:
        raise ValueError("source exceeds bounded AST analysis size")
    started = perf_counter()
    source = before.decode("utf-8")
    hypotheses = compile_python_hypotheses(source)
    selected = hypotheses["candidates"][:max_candidates]
    attempts = []
    remaining = max_probes
    for hypothesis in selected:
        decision = {
            "hypothesis": hypothesis["identifier"],
            "family": hypothesis["family"],
            "source_line": hypothesis["line"],
            "discovery_verdict": "HYPOTHESIS_UNVERIFIED",
            "status": "UNVERIFIED",
            "source_derived": True,
        }
        strategy = _strategy(source, hypothesis)
        if strategy and enable_execution and remaining >= 1:
            try:
                # Only source/AST methods with an explicitly supported, known
                # isolated local API contract may be executed.
                # Remaining budget is strict: if candidate requires more,
                # it returns UNKNOWN_RESOURCE_BUDGET rather than partial proof.
                required = 6 if strategy=="staticfiles_local" else (
                    17 if strategy=="windows_url_path" else 7)
                if remaining < required:
                    decision["status"] = "UNKNOWN_RESOURCE_BUDGET"
                else:
                    if strategy=="staticfiles_local":
                        result=starlette_scan(source_file, remaining)
                    elif strategy=="windows_url_path":
                        result=werkzeug_scan(source_file, remaining)
                    else:
                        result=django_scan(source_file, remaining)
                    used=result["budget"]["used_probes"]
                    remaining-=used
                    decision.update({
                        "status": result["status"],
                        "discovery_verdict": (
                            "REPRODUCED_LOCAL_PROPERTY_WITNESS" if result["status"]=="LOCAL_PROPERTY_WITNESS"
                            else "TESTED_WITHOUT_WITNESS_NOT_SAFE"),
                        "verification_scope": result["limitations"],
                        "used_probes": used,
                        "observed_violations": result["observed_property_violations"],
                        "minimal_witness": result["minimal_observed_witness"],
                        "replay_sha256": result["replay_sha256"],
                    })
            except (ValueError, OSError, TypeError, RuntimeError, AssertionError) as exc:
                # Failed real-source execution is not a negative finding.
                decision["status"] = "UNKNOWN_RUNTIME_OR_MODEL"
                decision["reason"] = type(exc).__name__+":"+str(exc)[:220]
        elif strategy is None:
            decision["reason"] = "NO_TRUSTWORTHY_EXECUTION_ADAPTER_FOR_HYPOTHESIS"
        elif not enable_execution:
            decision["reason"] = "EXECUTION_DISABLED"
        else:
            decision["status"] = "UNKNOWN_RESOURCE_BUDGET"
        attempts.append(decision)
    if sha256(source_file.read_bytes()).digest()!=sha256(before).digest():
        raise RuntimeError("original third-party source mutated during evaluation")
    confirmed=[a for a in attempts if a["status"]=="LOCAL_PROPERTY_WITNESS"]
    unknown=[a for a in attempts if a["status"].startswith(("UNVERIFIED","UNKNOWN"))]
    overall=("LOCAL_PROPERTY_WITNESS" if confirmed
             else "NO_WITNESS_NOT_SAFE" if attempts and not unknown
             else "INCOMPLETE_UNKNOWN")
    if not selected:
        overall="NO_HYPOTHESIS_UNKNOWN"
    return {
        "schema": "scm.prism.d24h.autonomous.hypotheses.v1",
        "mode": "SOURCE_ONLY_NO_USER_SUPPLIED_VULNERABILITY_OR_PROPERTY",
        "source": {"sha256": sha256(before).hexdigest(),"filename":source_file.name},
        "compiler": {
            "candidate_count":len(hypotheses["candidates"]),
            "tested_or_scheduled":len(selected),
            "families":hypotheses["counts_by_family"],
        },
        "budget":{"max_probes":max_probes,
                  "used_probes":max_probes-remaining,
                  "max_candidates":max_candidates},
        "status":overall,
        "source_derived_hypotheses":selected,
        "evaluations":attempts,
        "local_behavior_witnesses":len(confirmed),
        "unresolved_hypotheses":len(unknown),
        "elapsed_seconds":perf_counter()-started,
        "independently_new_unknown_vulnerabilities":0,
        "claim_of_security_for_no_witness":False,
        "not_a_sound_all_bug_scanner":True,
        "limitations":hypotheses["limitations"],
    }


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--max-probes",type=int,default=64)
    p.add_argument("--max-candidates",type=int,default=128)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--authorized-local",action="store_true")
    p.add_argument("--dry-run",action="store_true")
    args=p.parse_args()
    result=inspect_source(args.source,max_probes=args.max_probes,
                          max_candidates=args.max_candidates,
                          authorized_local=args.authorized_local,
                          enable_execution=not args.dry_run)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",
                        encoding="utf-8")
    print("D24H_AUTONOMOUS_SOURCE_DISCOVERY",json.dumps({
        "file":args.source.name,
        "status":result["status"],
        "source_candidate_count":result["compiler"]["candidate_count"],
        "families":result["compiler"]["families"],
        "witnesses":result["local_behavior_witnesses"],
        "unknowns":result["unresolved_hypotheses"],
        "probes":result["budget"]["used_probes"],
        "new_vulnerabilities":0,
    },sort_keys=True))
