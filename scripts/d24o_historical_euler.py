"""Source-only *retrospective* Euler V1 peer-guard challenge.

No RPC, Solidity deployment, vulnerability exploit or live funds. This
script reads the exact commit provided by the caller from a local Git mirror.
The historical issue was publicly documented BEFORE this experiment; a match
is calibration evidence, not independent zero-day discovery.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from time import perf_counter

from prism.d24o_guard_consistency import propose_peer_debit_guards


UPSTREAM = "euler-legacy-xyz/euler-contracts"
SOURCE_PATH = "contracts/modules/EToken.sol"
HISTORICAL_COMMIT = "b1ee3265853628d5a529081d7908c38404201b4e"


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *arguments],
                            capture_output=True, text=True, check=False,
                            timeout=30)
    if result.returncode:
        raise ValueError("pinned historical Git source unavailable: " + result.stderr[-200:])
    return result.stdout


def run_trial(repo: Path, *, commit: str = HISTORICAL_COMMIT) -> dict:
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("require a pinned forty-digit Git commit")
    if commit != HISTORICAL_COMMIT:
        raise ValueError("different commit requires a separate preregistered cohort")
    resolved = _git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").strip()
    if resolved != commit:
        raise ValueError("commit does not match pinned historical revision")
    remote = _git(repo, "remote", "get-url", "origin").strip()
    if not remote.rstrip("/").removesuffix(".git").endswith("/" + UPSTREAM):
        raise ValueError("unexpected historical source repository")
    blob_id = _git(repo, "rev-parse", f"{commit}:{SOURCE_PATH}").strip()
    start = perf_counter()
    source = _git(repo, "show", f"{commit}:{SOURCE_PATH}")
    result = propose_peer_debit_guards(source)
    seconds = perf_counter()-start
    return {
        "schema": "scm.prism.d24o.euler-retrospective-source-trial.v1",
        "upstream": UPSTREAM,
        "commit": commit,
        "source_path": SOURCE_PATH,
        "source_blob_git_sha1": blob_id,
        "source_sha256": sha256(source.encode()).hexdigest(),
        "source_first_candidate_engine": result,
        "calibration_disclosure": (
            "Root cause is publicly known and investigator has read source. "
            "Not a blinded or prospective discovery trial."
        ),
        "native_evm_transactions": 0,
        "financial_loss_reproduced": False,
        "exploit_constructed": False,
        "historical_real_flaws_independently_verified": 0,
        "new_zero_days": 0,
        "cpu_only_no_model_or_paid_api": True,
        "source_analysis_wall_seconds": seconds,
        "verdict": "RETROSPECTIVE_SOURCE_HYPOTHESIS_ONLY",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run_trial(args.upstream)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
    candidates = result["source_first_candidate_engine"]["candidates"]
    print("D24O_HISTORICAL_SOURCE", json.dumps({
        "functions": result["source_first_candidate_engine"]["source_functions"],
        "candidate_methods": [x["function"] for x in candidates],
        "native_evm_transactions": 0,
        "zero_days": 0,
        "status": result["verdict"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
