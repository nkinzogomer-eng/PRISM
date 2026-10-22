"""D2.3 collect pinned compiler ABI output and select security properties.

Compiler is run before EVM evaluation and does not read case labels, finding
history, branch names or source vulnerability flags. Inspecting interfaces
alone does NOT prove the properties are implemented correctly.
"""
from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path
import subprocess
import time

from prism.defi_property_compiler import freeze_input


ABI_CONTRACTS = {"oracle": "D22Oracle", "lender": "D22Credit", "asset": "D22Coin"}


def _inspect(root: Path, contract: str) -> tuple[list[dict], dict]:
    started = time.perf_counter()
    cmd = ["forge", "inspect", contract, "abi", "--json"]
    p = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=90)
    elapsed = time.perf_counter()-started
    if p.returncode:
        raise RuntimeError(f"ABI inspection failed for {contract}, exit={p.returncode}: {p.stderr[-1500:]}")
    try:
        decoded = json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"forge inspect {contract} did not return JSON") from exc
    if isinstance(decoded, dict) and isinstance(decoded.get("abi"), list):
        decoded = decoded["abi"]
    if not isinstance(decoded, list):
        raise RuntimeError("unexpected Foundry ABI inspect result")
    return decoded, {
        "contract": contract,
        "wall_seconds": elapsed,
        "output_sha256": sha256(p.stdout.encode()).hexdigest(),
        "stderr_last_500": p.stderr[-500:],
    }


def main(root: Path, out: Path) -> dict:
    if not (root/"src"/"MultiRisk.sol").is_file():
        raise FileNotFoundError(root/"src"/"MultiRisk.sol")
    out.mkdir(parents=True,exist_ok=True)
    abis, timings={}, {}
    for role, contract in ABI_CONTRACTS.items():
        abi, detail = _inspect(root, contract)
        abis[role] = abi
        timings[role] = detail
    record = freeze_input(abis)
    record["input_source_sha256"] = sha256((root/"src"/"MultiRisk.sol").read_bytes()).hexdigest()
    record["inspector"] = timings
    record["limitations"] = [
        "ABI-based property candidates, not verified invariant extraction from Solidity AST",
        "Template library hand-written based on conventional financial security assumptions",
        "No labels are read by this compiler; downstream synthetic test suites still share researcher assumptions",
        "A semantic-free baseline could select the same templates from ABI signatures",
        "ABI matching may produce false-positive hypotheses and misses renamed operations",
    ]
    (out/"abi-bundle.json").write_text(json.dumps(abis,indent=2,sort_keys=True)+"\n")
    (out/"compiled-hypotheses.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
    print("D23_ABI_SHA",record["abi_bundle_sha256"])
    print("D23_PROPERTIES",[(x["identifier"],x["decision"]) for x in record["hypotheses"]])
    print("D23_UNKNOWN",record["unknown"])
    print("D23_INSPECTION_WALL", {k:round(v["wall_seconds"],5) for k,v in timings.items()})
    return record


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    main(args.root.resolve(), args.output.resolve())
