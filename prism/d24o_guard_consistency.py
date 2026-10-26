"""D2.4O: infer candidate *post-debit* obligations from Solidity peers.

This is a deliberately bounded, source-only screening component. It has no
whole-program semantics and cannot establish an economic exploit. The caller
must provide a separate EVM/financial oracle to upgrade any hypothesis.

Unlike a detector keyed to a known incident function, the rule looks for
account-balance reductions and learns recurring post-condition checks from
other functions in the *same* source. The hypothesis is conditional on those
functions having comparable authorization and account-health semantics.
"""
from __future__ import annotations

from hashlib import sha256
import re

from prism.d24k_structural import function_records


_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_GUARD_NAME = re.compile(r"^(?:check|assert|validate|verify|ensure|enforce)[A-Z]\w*$")
_DEBIT_HELPER = re.compile(
    r"^(?:decrease|reduce|transfer|remove|burn|move)"
    r"(?:Balance|Collateral|Shares|Position|[A-Z]\w*(?:Balance|Collateral|Shares|Position))$"
)
_ACCOUNT_BALANCE_WRITE = re.compile(
    r"\b[A-Za-z_]\w*\.users\s*\[[^\]]+\]\.balance\s*(\-=|=(?!=))\s*"
    r"(?:encodeAmount\s*\(\s*)?([A-Za-z_]\w*|\d+)"
)


def _debit_evidence(body: str) -> tuple[str | None, int]:
    """Find a *possible* share/collateral reduction, never infer actual value."""
    for match in _CALL.finditer(body):
        if _DEBIT_HELPER.fullmatch(match.group(1)):
            return "DEBIT_NAMED_HELPER", match.start()
    for match in _ACCOUNT_BALANCE_WRITE.finditer(body):
        assignment, rhs = match.groups()
        prefix = body[:match.start()]
        if assignment == "-=":
            return "ACCOUNT_BALANCE_SUBTRACTION", match.start()
        # A branch may set the entire balance to zero; source-only proof of
        # actual reduction is impossible, hence this remains a candidate.
        if (re.search(r"\b"+re.escape(rhs)+r"\s*=\s*0\s*;", prefix)
                or re.search(r"\b"+re.escape(rhs)+r"\s*=\s*\w+\s*-", prefix)):
            return "DERIVED_ACCOUNT_BALANCE_REPLACEMENT", match.start()
    return None, -1


def _guards_after(body: str, offset: int) -> tuple[str, ...]:
    # An if/loop/catch-local check is NOT evidence of an unconditional
    # postcondition. We keep only top-level calls in this small lexical model.
    # Rich conditional proofs must go through a compiler-typed CFG instead.
    levels = []
    level = 0
    for char in body:
        levels.append(level)
        if char == "{":
            level += 1
        elif char == "}":
            level -= 1
    guards = set()
    for match in _CALL.finditer(body, offset):
        if not _GUARD_NAME.fullmatch(match.group(1)) or levels[match.start()] != 1:
            continue
        # Solidity also permits `if (condition) checkHealthy(account);`
        # without braces; brace depth alone cannot certify this call.
        delim = max(body.rfind(char, 0, match.start()) for char in ";{}")
        fragment = body[delim+1:match.start()]
        if re.search(r"\b(?:if|while|for)\s*\([^;{}]*\)\s*$", fragment):
            continue
        guards.add(match.group(1))
    return tuple(sorted(guards))


def propose_peer_debit_guards(source: str, *, minimum_peers: int = 2,
                              max_candidates: int = 32) -> dict:
    """Return hypotheses about absent checks relative to same-file peers.

    ``UNVERIFIED`` is mandatory regardless of candidate count. Missing guards
    may be an intentional policy, an inherited modifier, or a helper effect.
    The result must *not* be interpreted as proof of a vulnerability or safety.
    """
    if type(minimum_peers) is not int or not 2 <= minimum_peers <= 16:
        raise ValueError("peer evidence threshold outside approved bound")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 128:
        raise ValueError("candidate budget outside approved bound")
    rows = []
    for record in function_records(source):
        if not record["implemented"]:
            continue
        body = record["body"]
        evidence, debit_at = _debit_evidence(body)
        if evidence is not None:
            rows.append({"name": record["name"], "debit_signal": evidence,
                         "post_checks": _guards_after(body, debit_at)})

    # Infer policy from peer methods, not from particular bug names. Each
    # supporting method counts once, regardless of repeat calls/overloads.
    support: dict[str, set[str]] = {}
    for row in rows:
        for check in row["post_checks"]:
            support.setdefault(check, set()).add(row["name"])
    candidates = []
    for row in rows:
        absent = []
        for guard, peers in sorted(support.items()):
            others = peers - {row["name"]}
            if guard not in row["post_checks"] and len(others) >= minimum_peers:
                absent.append({"guard": guard, "supporting_peer_methods": sorted(others)})
        if absent:
            candidates.append({
                "function": row["name"],
                "debit_signal": row["debit_signal"],
                "unmet_peer_obligations": absent,
                "hypothesis": (
                    "If the debit can reduce collateral for an indebted account, "
                    "determine whether omitted post-debit checks permit an "
                    "unauthorized account-health or liquidation transition"
                ),
                "status": "UNVERIFIED_CONDITIONAL_PEER_ANOMALY",
                "requires_independent_evm_oracle": True,
            })
    candidates.sort(key=lambda x: x["function"])
    return {
        "schema": "scm.prism.d24o.peer-guard-hypotheses.v1",
        "source_sha256": sha256(source.encode()).hexdigest(),
        "source_functions": len(function_records(source)),
        "debit_compatible_functions": len(rows),
        "inferred_peer_checks": {guard: sorted(peers) for guard, peers in
                                 sorted(support.items()) if len(peers) >= minimum_peers},
        "candidates": candidates[:max_candidates],
        "omitted_for_budget": max(0, len(candidates)-max_candidates),
        "status": "SOURCE_ONLY_HYPOTHESES_NOT_VERIFIED",
        "native_evm_witnesses": 0,
        "verified_real_vulnerabilities": 0,
        "verified_zero_days": 0,
        "limitations": [
            "Lexical helper names and direct assignments are not complete value flow",
            "Unknown modifiers, inheritance, account-debt relationships and paths",
            "Same-file peers can implement different legitimate policy",
            "Absence of an inferred guard does not prove a vulnerability",
            "No candidate does not establish safety",
        ],
    }
