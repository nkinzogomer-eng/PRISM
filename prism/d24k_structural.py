"""D2.4K experimental source-first structural security obligations.

This version is developed AFTER D2.4J holdouts. Earlier holdout results must
not be rescored as blind successes. Generates verification *hypotheses*, never
vulnerability verdicts; recognizes overloads without discarding a whole file.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import re

from scripts.d24c_structural_frontier import mask_noncode


_FUNCTION=re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")


def function_records(source: str) -> list[dict]:
    """Bounded overload-aware lexical functions, not compiler AST semantics."""
    if type(source) is not str or not source or len(source.encode())>1_000_000:
        raise ValueError("source missing or exceeds byte budget")
    clean=mask_noncode(source)
    result=[]
    for match in _FUNCTION.finditer(clean):
        name=match.group(1)
        index=match.end()
        bracket=1
        while index<len(clean) and bracket:
            if clean[index]=="(": bracket+=1
            elif clean[index]==")": bracket-=1
            index+=1
        if bracket:
            raise ValueError("unclosed Solidity signature")
        declaration=clean[match.start():index]
        while index<len(clean) and clean[index] not in "{;":
            index+=1
        if index>=len(clean):
            raise ValueError("unclosed Solidity function")
        if clean[index]==";":
            result.append({"name":name,"declaration":declaration,
                           "body":"","implemented":False})
            continue
        start=index
        index+=1
        depth=1
        while index<len(clean) and depth:
            if clean[index]=="{": depth+=1
            elif clean[index]=="}": depth-=1
            index+=1
        if depth:
            raise ValueError("unclosed Solidity function body")
        result.append({"name":name,"declaration":declaration,
                       "body":clean[start:index],"implemented":True})
    if not result:
        raise ValueError("no Solidity functions to inspect")
    return result


def propose_value_influence(source: str, *, max_candidates: int = 20) -> dict:
    """Recognize dependent asset/share conversion and unpriced external assets.

    Semantic attestation is absent. Whether direct donations count as assets,
    whether there is slippage protection and who can profit are UNKNOWN until
    an external observer executes those transitions.
    """
    if type(max_candidates) is not int or not 1<=max_candidates<=64:
        raise ValueError("invalid cognitive candidate budget")
    functions=function_records(source)
    by_name={}
    for row in functions:
        if row["implemented"]:
            by_name.setdefault(row["name"],[]).append(row["body"])
    candidates=[]
    converter=by_name.get("convertToShares",[])
    consumption=by_name.get("deposit",[])
    if (converter and consumption and "totalAssets" in by_name
            and "convertToAssets" in by_name):
        depends_on_outstanding=any(re.search(r"\btotalSupply\b",body) for body in converter)
        depends_on_assets=any(re.search(r"\btotalAssets\s*\(",body) for body in converter)
        nonlinear_quote=any(re.search(r"mulDiv(?:Down|Up)\s*\(|\s/\s",body)
                            for body in converter)
        deposit_depends_on_quote=any(
            re.search(r"\bpreviewDeposit\s*\(|\bconvertToShares\s*\(",body)
            for body in consumption)
        if all((depends_on_outstanding,depends_on_assets,nonlinear_quote,
                deposit_depends_on_quote)):
            candidates.append({
                "identifier":"asset_share_rate:donation_without_share_issuance",
                "family":"EXTERNAL_ASSET_RATE_INFLUENCE",
                "from_source_signals":["totalSupply","totalAssets()","convertToShares()","deposit()"],
                "conditional_obligation":(
                    "If externally transferred assets increase totalAssets without increasing "
                    "totalSupply, test whether a bounded deposit/redeem sequence redistributes "
                    "assets to previous share holders without user slippage consent"),
                "required_independent_observations":[
                    "assets_before_and_after_unmatched_donation",
                    "shares_outstanding_before_and_after_donation",
                    "attacker_total_spent_and_redeemed",
                    "victim_total_deposited_and_redeemed",
                    "undonated_counterfactual_and_minimum_share_guard"],
                "status":"UNVERIFIED_CONDITIONAL_ECONOMIC_HYPOTHESIS",
                "known_public_class_possible":True,
                "claim_of_new_vulnerability":False,
            })
    # Overloaded methods are now counted, not silently discarded. They may
    # still be semantically ambiguous and are not treated as authorization.
    counts=Counter(f["name"] for f in functions)
    overloads={name:count for name,count in sorted(counts.items()) if count>1}
    return {
        "schema":"scm.prism.d24k.structural-hypotheses.v1",
        "source_sha256":sha256(source.encode()).hexdigest(),
        "functions_extracted":len(functions),
        "overloads_observed":overloads,
        "candidates":candidates[:max_candidates],
        "omitted_for_budget":max(0,len(candidates)-max_candidates),
        "unknown_semantics":True,
        "native_evm_traces_checked":0,
        "new_vulnerabilities_confirmed":0,
        "zero_days_confirmed":0,
        "limitations":["Overload-aware lexical extraction still lacks compiler-typed AST",
                        "Only one conditional economic relation currently synthesized",
                        "Missing candidate is UNKNOWN, not proof that no flaw exists",
                        "The hypothesis is based on public ERC4626 design patterns"],
    }
