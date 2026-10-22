"""Prepare a pinned external DeFi benchmark without giving labels to PRISM.

Network I/O is ONLY allowed for downloading catalogs from a fixed upstream
commit on raw.githubusercontent.com. The immutable target revisions come from
the independent benchmark. The output is a preflight, not a vulnerability
discovery result.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from time import perf_counter
from urllib.request import Request, urlopen

from prism.defi_external_catalog import fingerprints, ingest

CATALOG_SHA = "de70065957a32fc5dd5fba3e53bb60f8564c722c"
URL_PREFIX = f"https://raw.githubusercontent.com/scfuzzbench/scfuzzbench/{CATALOG_SHA}/benchmarks/"


def fetch_public(name: str) -> bytes:
    if name not in ("targets.json", "known_bugs.json"):
        raise ValueError("not an allowlisted benchmark input")
    req = Request(URL_PREFIX + name,
                  headers={"User-Agent":"PRISM-D24-readonly-benchmark-research"})
    with urlopen(req,timeout=45) as handle:
        data=handle.read(1_000_001)
    if len(data)>1_000_000:
        raise ValueError("catalog larger than 1MB allowed maximum")
    return data


def prepare(out: Path, raw_targets: bytes, raw_truth: bytes) -> dict:
    source = json.loads(raw_targets)
    truth = json.loads(raw_truth)
    result=ingest(source,truth,catalog_commit=CATALOG_SHA)
    out.mkdir(parents=True,exist_ok=True)
    # Deliberately separate the only input permitted for an eventual
    # detector from truth available to the *scorer*.
    (out/"detector-public-targets.json").write_text(
        json.dumps(result.public,indent=2,sort_keys=True)+"\n",
        encoding="utf-8")
    (out/"judge-only-known-bugs.json").write_text(
        json.dumps(result.judge,indent=2,sort_keys=True)+"\n",
        encoding="utf-8")
    ledger={
        "phase":"D2.4A",
        "status":"PINNED_EXTERNAL_CATALOG_VALIDATED_NOT_EVM_TESTED",
        "upstream_catalog_repo":"https://github.com/scfuzzbench/scfuzzbench",
        "upstream_catalog_commit":CATALOG_SHA,
        "source_sha256":fingerprints(raw_targets,raw_truth),
        "measured_at":datetime.now(timezone.utc).isoformat(),
        "inventory":result.statistics,
        "external_target_ids":[case["target_id"] for case in result.public["cases"]],
        "external_commit_pins":{case["target_id"]:case["commit"]
                                for case in result.public["cases"]},
        "no_discovery_claim":True,
        "limitations":[
            "Public known-bug labels are not a sealed, blind holdout",
            "A known issue listed by third parties is not a PRISM discovery",
            "Canaries are instrumentation controls, NOT real vulnerabilities",
            "Only a pinned external target suite is prepared; no attack executed",
            "True TP/FP/FN cannot be computed without actual detector runs and validation",
            "Catalog known bug coverage does not prove all vulnerabilities are annotated",
            "A real equivalent Foundry/Echidna/Medusa campaign is not run by this step",
        ]
    }
    (out/"readiness.json").write_text(json.dumps(ledger,indent=2,sort_keys=True)+"\n",
                                      encoding="utf-8")
    return ledger


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    cli=parser.parse_args()
    t0=perf_counter()
    targets=fetch_public("targets.json")
    truth=fetch_public("known_bugs.json")
    ledger=prepare(cli.output,targets,truth)
    ledger["catalog_fetch_and_validation_wall_seconds"]=perf_counter()-t0
    (cli.output/"readiness.json").write_text(json.dumps(ledger,indent=2,sort_keys=True)+"\n",
                                             encoding="utf-8")
    print("D24_CATALOG_COMMIT",CATALOG_SHA)
    print("D24_SOURCE_SHA256",ledger["source_sha256"])
    print("D24_INVENTORY",ledger["inventory"])
    print("D24_STATUS",ledger["status"])


if __name__=="__main__":
    main()
