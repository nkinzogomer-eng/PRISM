"""D2.4N: strictly bounded, genuine semver compiler constraint resolver.

Supports simple Solidity pragma AND/OR semver ranges and official pinned
0.8.24 / 0.8.33 compilers. Unknown grammar, conflicts or source errors
must abstain; never bypass signed compiler integrity checks.
"""
from __future__ import annotations

import re

from scripts.d24c_structural_frontier import mask_noncode


PINNED=("0.8.24","0.8.33")
_PRAGMA=re.compile(r"\bpragma\s+solidity\s+([^;]+);")
_CONSTRAINT=re.compile(r"(\^|>=|<=|>|<|=)?\s*(\d+)\.(\d+)\.(\d+)$")


def _range_satisfied(token: str, candidate: tuple[int,int,int]) -> bool:
    match=_CONSTRAINT.fullmatch(token)
    if not match:
        raise ValueError("UNRECOGNIZED_SOLIDITY_SEMVER_CONSTRAINT")
    operator,major,minor,patch=match.groups()
    point=(int(major),int(minor),int(patch))
    if operator=="^":
        # npm / Solidity caret semantics for 0.x: up to next nonzero digit.
        if point[0]>0: upper=(point[0]+1,0,0)
        elif point[1]>0: upper=(0,point[1]+1,0)
        else: upper=(0,0,point[2]+1)
        return point<=candidate<upper
    if operator==">=": return candidate>=point
    if operator==">": return candidate>point
    if operator=="<=": return candidate<=point
    if operator=="<": return candidate<point
    return candidate==point


def permits(spec: str, version: str) -> bool:
    candidate=tuple(map(int,version.split(".")))
    clauses=spec.strip().split("||")
    if not 1<=len(clauses)<=4:
        raise ValueError("COMPLEX_SOLIDITY_SEMVER_UNSUPPORTED")
    matched=False
    for clause in clauses:
        pieces=clause.split()
        if not 1<=len(pieces)<=4:
            raise ValueError("COMPLEX_SOLIDITY_SEMVER_UNSUPPORTED")
        # Always validate ALL clauses; malformed alternatives cannot be hidden
        # behind an earlier successful clause.
        valid=[_range_satisfied(piece,candidate) for piece in pieces]
        matched=matched or all(valid)
    return matched


def choose(sources:dict[str,bytes]) -> dict:
    if not sources or len(sources)>60 or sum(map(len,sources.values()))>1_000_000:
        raise ValueError("SOURCE_CLOSURE_TOO_LARGE")
    constraints={}
    for name,content in sorted(sources.items()):
        if not name.endswith(".sol") or type(content) is not bytes:
            raise ValueError("INVALID_SOLIDITY_INPUT")
        masked=mask_noncode(content.decode("utf-8",errors="strict"))
        clauses=_PRAGMA.findall(masked)
        if len(clauses)!=1:
            raise ValueError("MISSING_OR_MULTIPLE_SOLIDITY_PRAGMAS")
        constraints[name]=clauses[0].strip()
    for version in PINNED:
        if all(permits(spec,version) for spec in constraints.values()):
            return {"compiler":version,"source_count":len(constraints),
                    "constraints":constraints,"integrity_check_required":True,
                    "protocol":"BOUNDED_SEMVER_NO_CHECKSUM_BYPASS"}
    raise ValueError("NO_PINNED_COMPILER_CAN_SATISFY_CLOSURE")
