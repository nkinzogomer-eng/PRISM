"""D2.4H Solidity source property candidate catalog: no CVE or oracle supplied.

This phase creates potential work items only. Solidity EVM property checking
requires a separate typed/stateful verifier; results are always UNVERIFIED.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from prism.cyber_solidity_hypotheses import compile_solidity_hypotheses

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    raw=a.source.read_text(encoding="utf-8")
    if len(raw)>2_000_000:raise ValueError("bounded Solidity analysis requires <=2MB")
    record=compile_solidity_hypotheses(raw)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(record,sort_keys=True,indent=2)+"\n")
    print("D24H_SOLIDITY_UNVERIFIED",json.dumps({
        "functions":record["source_functions"],
        "candidate_hypotheses":len(record["hypotheses"]),
        "families":record["families"],
        "new_bugs_found":0,
        "has_an_executable_oracle":False,
    },sort_keys=True))
