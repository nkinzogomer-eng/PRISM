"""D2.4H source-derived *candidate* security invariants for Solidity.

Conservative lexical extraction uses the pre-existing D2.4C frontend. No
Solidity compiler semantics, inheritance resolution, storage alias model, or
proof is implied. Candidate invariants are work items, not discoveries.
"""
from __future__ import annotations

from hashlib import sha256
import re

from scripts.d24c_structural_frontier import extract_functions, mask_noncode


def compile_solidity_hypotheses(source: str) -> dict:
    functions=extract_functions(source)
    clean=mask_noncode(source)
    candidates=[]
    for name, (_, _, body) in sorted(functions.items()):
        check=re.search(r"\b(?:delegatecall|call)\s*(?:\{|\()",body)
        has_value=re.search(r"\bcall\s*\{\s*value\s*:",body)
        accounting = bool(re.search(r"\b(?:mint|burn|changeSupply|transferFrom|transfer)\b",name,re.I))
        declaration=re.search(r"\bfunction\s+"+re.escape(name)+r"\s*\([^)]*\)\s*([^{};]*)\{",clean)
        modifiers=declaration.group(1) if declaration else ""
        auth = bool(re.search(r"\b(?:onlyOwner|onlyGovernor|onlyRole|hasRole|msg\.sender)\b",body+" "+modifiers))
        if check or has_value:
            candidates.append({
                "id":f"external_state:{name}",
                "family":"external_call_state_consistency",
                "function":name,
                "signals":["delegatecall" if "delegatecall" in body else "external_call"],
                "hypothesis":"State and authority boundaries must remain valid across external callbacks",
                "status":"UNVERIFIED",
                "executable_oracle":"NOT_IMPLEMENTED",
            })
        if accounting:
            candidates.append({
                "id":f"asset_conservation:{name}",
                "family":"asset_conservation",
                "function":name,
                "signals":["accounting_named_entrypoint"],
                "hypothesis":"Token balance and supply relationships must respect the protocol's declared invariants",
                "status":"UNVERIFIED",
                "executable_oracle":"NOT_IMPLEMENTED",
            })
        if auth:
            candidates.append({
                "id":f"authorization:{name}",
                "family":"authorization_boundary",
                "function":name,
                "signals":["access_control_expression"],
                "hypothesis":"Privileged changes must be restricted to authorized callers across state transitions",
                "status":"UNVERIFIED",
                "executable_oracle":"NOT_IMPLEMENTED",
            })
    candidates.sort(key=lambda x:(x["family"],x["function"]))
    return {
        "schema":"scm.prism.d24h.solidity-hypotheses.v1",
        "source_sha256":sha256(source.encode()).hexdigest(),
        "language":"solidity-lexical",
        "source_functions":len(functions),
        "hypotheses":candidates,
        "families":{family:sum(x["family"]==family for x in candidates)
                    for family in ("external_call_state_consistency","asset_conservation","authorization_boundary")},
        "independent_vulnerability_witnesses":0,
        "discovered_novel_vulnerabilities":0,
        "complete_semantics":False,
        "limitations":[
            "Lexical heuristics for function entrypoint names and calls",
            "Contract inheritance, modifiers and storage flow not resolved",
            "Potentially missing zero-days is UNKNOWN, not absence of bugs",
            "No Solidity runtime check or independent verification performed in this phase",
        ],
    }
