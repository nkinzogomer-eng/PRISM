"""D2.3: compile *candidate* DeFi security properties from Solidity ABI shapes.

This is NOT autonomous contract auditing: function names + ABI types suggest
generic financial invariants. The checks are hypothesized, not proven, and
source-independent flags / vulnerability IDs are forbidden as inputs.

A certificate records the observations the verifier MUST have; missing
interfaces return UNKNOWN rather than an assertion of safety. The compiler
never accesses developer labels, prior results or generated exploit traces.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any


@dataclass(frozen=True)
class Hypothesis:
    identifier: str
    observable_dependencies: tuple[str, ...]
    property_statement: str
    decision: str
    independent_observation: str
    limitations: tuple[str, ...]

    def json_record(self) -> dict:
        return asdict(self)


SPECIFICATIONS = {
    "ORACLE_AUTH": {
        "requires": (
            ("oracle", "owner()"),
            ("oracle", "price()"),
            ("oracle", "update(uint256)"),
        ),
        "statement": "Any oracle price change initiated by a non-owner must revert.",
        "verify": "Compare price before/after attempted non-owner update on local EVM.",
        "limits": (
            "Only direct owner identity, no delegated managers, multisigs or governance.",
            "An owner may be economically malicious; this property will not detect it.",
        ),
    },
    "WITHDRAW_SOLVENCY": {
        "requires": (
            ("lender", "borrow(uint256)"),
            ("lender", "debt(address)"),
            ("lender", "deposit(uint256)"),
            ("lender", "limit(address)"),
            ("lender", "locked(address)"),
            ("lender", "withdraw(uint256)"),
        ),
        "statement": "Borrower withdrawal must not create debt above its current loan limit.",
        "verify": "Read debt/limit before and after independently generated withdrawal sequences.",
        "limits": (
            "Market price moves and liquidations can cause undercollateralization independently.",
            "Valid only for the particular borrowing limit and zero-interest test semantics.",
        ),
    },
    "REPAY_CONSERVATION": {
        "requires": (
            ("lender", "debt(address)"),
            ("lender", "loanAsset()"),
            ("lender", "repay(uint256)"),
            ("asset", "balanceOf(address)"),
        ),
        "statement": "Accepted debt repayment must transfer loan assets into pool, not forgive debt.",
        "verify": "Observe debt decrease and asset balance changes for borrower and pool.",
        "limits": (
            "Explicit debt forgiveness, insurance and socialized losses require distinct specs.",
            "Fee-on-transfer, rebasing and hooks may invalidate simple balance-delta assumptions.",
        ),
    },
}


def _canonical(entry: dict[str, Any]) -> str:
    if not isinstance(entry, dict) or entry.get("type") != "function":
        raise ValueError("not an ABI function")
    name = entry.get("name")
    inputs = entry.get("inputs", [])
    if not isinstance(name, str) or not name or not isinstance(inputs, list):
        raise ValueError("malformed ABI function")
    kinds = []
    for arg in inputs:
        if not isinstance(arg, dict) or not isinstance(arg.get("type"), str):
            raise ValueError("malformed ABI argument")
        kinds.append(arg["type"])
    return name + "(" + ",".join(kinds) + ")"


def signatures(abi: Any) -> set[str]:
    if isinstance(abi, dict) and isinstance(abi.get("abi"), list):
        abi = abi["abi"]
    if not isinstance(abi, list):
        raise ValueError("ABI must be a JSON function-array")
    present = set()
    for entry in abi:
        if not isinstance(entry, dict):
            raise ValueError("invalid ABI entry")
        if entry.get("type") != "function":
            continue
        sig = _canonical(entry)
        if sig in present:
            raise ValueError("duplicate ABI selector signature")
        present.add(sig)
    if not present:
        raise ValueError("no functions in ABI")
    return present


def compile_properties(abis: dict[str, Any]) -> dict:
    """No per-variant labels, compiler flags, code byte patterns or EVM outcomes.

    Three stable generic property templates are considered. Unsupported
    capabilities are explicitly marked UNKNOWN, never inferred safe.
    """
    if set(abis) != {"oracle", "lender", "asset"}:
        raise ValueError("ABI roles must be exactly oracle,lender,asset")
    present = {key: signatures(value) for key, value in abis.items()}
    hypotheses = []
    unsupported = []
    for ident, spec in sorted(SPECIFICATIONS.items()):
        requirements = tuple(f"{role}.{sig}" for role, sig in spec["requires"])
        missing = tuple(f"{role}.{sig}" for role, sig in spec["requires"]
                        if sig not in present[role])
        if missing:
            unsupported.append({"identifier": ident, "decision": "UNKNOWN",
                                "missing_capabilities": missing})
            continue
        hypotheses.append(Hypothesis(
            identifier=ident,
            observable_dependencies=requirements,
            property_statement=spec["statement"],
            decision="CANDIDATE_REQUIRES_DYNAMIC_VERIFICATION",
            independent_observation=spec["verify"],
            limitations=spec["limits"],
        ).json_record())
    return {
        "schema": "prism-d23-property-compiler-v1",
        "hypotheses": hypotheses,
        "unknown": unsupported,
        "scope": "Contract ABI surface + generic manually authored property templates",
        "guarantee": "These are test candidates, NOT facts about contract safety.",
    }


def freeze_input(abis: dict[str, Any]) -> dict:
    source = json.dumps(abis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    result = compile_properties(abis)
    result["abi_bundle_sha256"] = sha256(source).hexdigest()
    result["compiled_hypotheses_sha256"] = sha256(json.dumps(
        result["hypotheses"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result
