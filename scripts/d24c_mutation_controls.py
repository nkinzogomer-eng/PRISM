"""D2.4C mutation sensitivity CONTROL on a temporary OUSD source copy.

The mutated code is not an independently discovered external vulnerability.
No mutant output enters the ABI property generator or the clean evaluation.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from scripts.d24c_real_evm import execute

NEEDLE = "allowances[_from][msg.sender] = userAllowance - _value;"
MUTANT = "allowances[_from][msg.sender] = userAllowance;"
EXPECTED = {
    "generated": "testFuzz_SCMMultistepAllowance(uint96,uint96)",
    "matched_reference": "testFuzz_ReferenceAllowance(uint96,uint96)",
    "stateful_reference": "invariant_SupplyConsistentAcrossActions()",
}


def mutate(text: str) -> str:
    if text.count(NEEDLE) != 1:
        raise ValueError("cannot establish unique pinned source mutation site")
    if text.count(MUTANT) != 0:
        raise ValueError("source already modified in expected mutant form")
    return text.replace(NEEDLE, MUTANT, 1)


def run_mutation(root: Path, out: Path) -> dict:
    source = root / "contracts/contracts/token/OUSD.sol"
    clean = source.read_bytes()
    original = clean.decode()
    altered = mutate(original).encode()
    if clean == altered:
        raise AssertionError("vacuous mutation")
    report = {
        "schema": "prism-d24c-mutant-positive-control-v1",
        "mutant": "ERC20_ALLOWANCE_DEBIT_REMOVED",
        "category": "SYNTHETIC_MUTATION_NOT_THIRD_PARTY_DISCOVERY",
        "status": "INCOMPLETE",
        "original_source_sha256": sha256(clean).hexdigest(),
        "mutated_source_sha256": sha256(altered).hexdigest(),
        "source_restored": False,
        "runs": [],
        "limitations": [
            "Intentional one-line source mutation, not a historical external vulnerability",
            "Manually specified generic property detects a transparent mutation",
            "Both PRISM and native Foundry are fully informed by same property",
            "No discovery precision/recall, no scientific superiority",
        ],
    }
    out.mkdir(parents=True, exist_ok=True)
    try:
        source.write_bytes(altered)
        if source.read_bytes() != altered:
            raise RuntimeError("source mutation not installed")
        for mode, test_name in EXPECTED.items():
            outcome = execute(root, out, mode, 0)
            matches = [x for x in outcome["outcomes"] if x["name"] == test_name]
            if len(matches) != 1 or matches[0]["status"] != "Failure":
                raise RuntimeError(f"mutant not detected by {mode}: {outcome['outcomes']}")
            if not ("D24C_" in matches[0]["reason"]):
                raise RuntimeError(f"mutant detection unrelated to accounting: {mode}")
            report["runs"].append({"mode": mode, "target": test_name,
                                   "status": "SYNTHETIC_MUTANT_DETECTED",
                                   "reason": matches[0]["reason"][:350],
                                   "wall_seconds": outcome["wall_seconds"],
                                   "cpu_seconds": outcome["child_cpu_seconds"]})
            print("D24C_MUTANT", mode, "DETECTED", matches[0]["reason"][:120])
        report["status"] = "THREE_REFERENCES_DETECTED_SYNTHETIC_MUTANT"
    finally:
        source.write_bytes(clean)
        report["source_restored"] = source.read_bytes() == clean
        (out / "mutation-control.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    record = run_mutation(args.root, args.out)
    if record["status"] != "THREE_REFERENCES_DETECTED_SYNTHETIC_MUTANT" or not record["source_restored"]:
        raise SystemExit("D2.4C mutation-control gate failed")
    print("D24C_MUTATION_FINAL", record["status"])
