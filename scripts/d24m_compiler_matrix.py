"""D2.4M deterministic resource-bounded Solidity compiler version selection.

No remote execution or auto-upgrade: select only explicitly pinned supported
0.8.x compilers using constraints extracted from the full immutable closure.
Conflicting or unsupported pragmas return UNKNOWN via ValueError.
"""
from __future__ import annotations

import re

from scripts.d24c_structural_frontier import mask_noncode

# Solidity 0.8.31 failed the Foundry 1.3.6 integrity checksum on the
# actual CI runner. 0.8.33 is an official bugfix/hotfix-compatible
# alternative for caret-0.8.31 sources; NEVER disable compiler checksums.
PINNED_COMPILERS=("0.8.24","0.8.33")
_PRAGMA=re.compile(r"\bpragma\s+solidity\s+([^;]+);")
_TOKEN=re.compile(r"^(\^|>=|>|<=|<|=)?\s*(0\.8\.\d+)$")


def _accepts(spec: str, version: str) -> bool:
    """Conservative subset of Solidity semver; unsupported ranges abstain."""
    major,minor,patch=map(int,version.split("."))
    if (major,minor)!=(0,8):
        return False
    parts=spec.strip().split()
    if not 1<=len(parts)<=3 or "||" in parts:
        raise ValueError("UNSUPPORTED_COMPILER_PRAGMA_GRAMMAR")
    for part in parts:
        match=_TOKEN.fullmatch(part)
        if not match:
            raise ValueError("UNSUPPORTED_COMPILER_PRAGMA_GRAMMAR")
        operator,required=match.groups()
        boundary=int(required.split(".")[-1])
        if operator=="^":
            okay=patch>=boundary  # 0.8.x caret excludes 0.9.x
        elif operator==">=": okay=patch>=boundary
        elif operator==">": okay=patch>boundary
        elif operator=="<=": okay=patch<=boundary
        elif operator=="<": okay=patch<boundary
        else: okay=patch==boundary
        if not okay:
            return False
    return True


def select_compiler(sources: dict[str,bytes], *, pinned=PINNED_COMPILERS) -> dict:
    if not sources or len(sources)>60 or sum(map(len,sources.values()))>1_000_000:
        raise ValueError("COMPILER_CLOSURE_BUDGET_EXCEEDED")
    pragmas={}
    for name,data in sorted(sources.items()):
        if not name.endswith(".sol") or type(data) is not bytes:
            raise ValueError("INVALID_SOLIDITY_SOURCE")
        clean=mask_noncode(data.decode("utf-8",errors="strict"))
        declarations=_PRAGMA.findall(clean)
        if len(declarations)!=1:
            raise ValueError("MISSING_OR_AMBIGUOUS_COMPILER_PRAGMA")
        pragmas[name]=declarations[0].strip()
    for version in pinned:
        if all(_accepts(spec,version) for spec in pragmas.values()):
            return {"selected":version,"pinned_choices":list(pinned),
                    "source_count":len(pragmas),"constraints":pragmas,
                    "status":"PINNED_COMPILER_MATCH"}
    raise ValueError("NO_PINNED_COMPILER_SATISFIES_ALL_SOURCE_PRAGMAS")
