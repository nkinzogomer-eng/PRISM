"""D2.4F proof bundle: fail-closed consolidated delivery evidence.

Input: two independently executed immutable third-party source revision trials.
Output: a compact, independently auditable engineering result. Never report
historical regression witnesses as new CVEs or novel vulnerabilities.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path


def aggregate(werkzeug: dict, starlette: dict) -> dict:
    expected = (
        ("werkzeug", werkzeug,
         "HISTORICAL_THIRD_PARTY_BEHAVIORAL_REGRESSION_REPRODUCED",
         "pallets/werkzeug", "CVE-2026-27199"),
        ("starlette", starlette,
         "HISTORICAL_THIRD_PARTY_REAL_FILE_BOUNDARY_REPRODUCED",
         "Kludex/starlette", "CVE-2023-29159"),
    )
    roots = []
    for key, record, status, project, cve in expected:
        if record.get("status") != status or record.get("external_library") != project:
            raise ValueError(f"unproven or substituted target: {key}")
        if (record.get("novel_vulnerability_confirmed") is not False
                or record.get("after_property_failures")
                or record.get("minimal_observed_witness") is None):
            raise ValueError(f"invalid security evidence or novelty label: {key}")
        if (record.get("probe_count", 0) < 4
                or len(str(record.get("deterministic_replay_sha256", ""))) != 64):
            raise ValueError(f"missing reproducibility: {key}")
        roots.append({
            "project": project,
            "already_public_historical_root_cause": cve,
            "inputs_executed": record["probe_count"],
            "witnesses_same_root_cause": record["historical_regression_candidates"],
            "minimum_reproduced_input": record["minimal_observed_witness"]["input"],
            "before_revision": record["revisions"]["before"],
            "fixed_revision": record["revisions"]["after"],
            "replay_sha256": record["deterministic_replay_sha256"],
            "third_party_behavior_observed": True,
            "novel_vulnerability": False,
        })
    counts = {
        "distinct_historical_root_causes_reproduced": len(roots),
        "independent_third_party_projects": len({r["project"] for r in roots}),
        "total_behavioral_inputs": sum(r["inputs_executed"] for r in roots),
        "total_confirmed_before_after_witnesses": sum(
            r["witnesses_same_root_cause"] for r in roots),
    }
    if (counts["distinct_historical_root_causes_reproduced"] != 2
            or counts["total_confirmed_before_after_witnesses"] < 5):
        raise ValueError("historical gate unfulfilled")
    facts = {"roots": roots, "counts": counts}
    return {
        "schema": "prism-d24f-delivery-proof-bundle-v1",
        "status": "TWO_REAL_HISTORICAL_ROOT_CAUSES_REPRODUCED",
        **facts,
        "attestation_sha256": sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest(),
        "proof_kind": "known historical before/after third-party behavioral regression",
        "scope": "local Python original-source method execution, one Windows branch emulated",
        "novel_cves_discovered": 0,
        "demonstrated_general_superiority": False,
        "unknown_future_cyber_discovery_recall": None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--werkzeug", type=Path, required=True)
    parser.add_argument("--starlette", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    record = aggregate(
        json.loads(args.werkzeug.read_text(encoding="utf-8")),
        json.loads(args.starlette.read_text(encoding="utf-8")),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print("D24F_DELIVERY", json.dumps(record["counts"], sort_keys=True))
    print("D24F_ATTESTATION", record["attestation_sha256"])
