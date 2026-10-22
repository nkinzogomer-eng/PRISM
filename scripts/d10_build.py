"""Materialize the immutable D1.0 development-only source corpus and manifests."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from benchmarks.d10_dev.specification import VERSION, generate


def stable_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def build(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    cases = root / "cases"
    cases.mkdir(exist_ok=True)
    generated = generate()
    expected_names = {x[0]["case_id"] + ".py" for x in generated}
    unexpected = {p.name for p in cases.iterdir()} - expected_names
    if unexpected:
        raise ValueError("unexpected corpus source files: " + repr(sorted(unexpected)))
    public = [item[0] for item in generated]
    oracle = [item[1] for item in generated]
    public_blob = stable_json(public).encode("utf8")
    source_manifest_hash = hashlib.sha256(public_blob).hexdigest()
    generator_hash = hashlib.sha256(
        (Path(__file__).resolve().parents[1] /
         "benchmarks/d10_dev/specification.py").read_bytes()
    ).hexdigest()
    for pub, _, raw in generated:
        dest = root / pub["path"]
        if dest.exists() and dest.read_bytes() != raw:
            raise ValueError("refusing to overwrite unexpected changed corpus source " + str(dest))
        dest.write_bytes(raw)
    public_manifest = {
        "schema": VERSION,
        "split": "development_only",
        "ground_truth_embargoed_for_scanners": True,
        "holdout_created": False,
        "source_specification_sha256": generator_hash,
        "public_manifest_sha256": source_manifest_hash,
        "cases": public,
        "warning": "Public metadata excludes labels, but this open development repository "
                   "contains oracle.json. It is NOT a blind held-out benchmark.",
    }
    private_manifest = {
        "schema": VERSION,
        "public_manifest_sha256": source_manifest_hash,
        "oracle": oracle,
        "warning": "Do not supply this file to a detector under evaluation.",
    }
    (root / "public.json").write_text(stable_json(public_manifest), encoding="utf8")
    (root / "oracle.json").write_text(stable_json(private_manifest), encoding="utf8")
    return {"cases": len(public), "pairs": len(public) // 2,
            "source_specification_sha256": generator_hash,
            "public_manifest_sha256": source_manifest_hash,
            "out_dir": str(root)}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    print(stable_json(build(args.out)))


if __name__ == "__main__":
    main()
