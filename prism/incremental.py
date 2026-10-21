"""Experimental exact-byte cache and cost-aware scan selection.

Nothing in this module proves that a scanner has module-local semantics.
Cross-file dependencies and implicit environment inputs invalidate naive caches.
A cache hit is admissible only under an explicitly frozen scanner contract,
and must be independently compared to a complete scan in this study.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import isfinite


def content_hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def changed_files(old: dict[str, str], current: dict[str, str],
                  same_scanner_contract: bool) -> set[str]:
    """Missing/replaced sources or scanner contract invalidate cache reuse."""
    if not same_scanner_contract:
        return set(current)
    return {name for name, digest in current.items() if old.get(name) != digest}


@dataclass(frozen=True)
class Plan:
    strategy: str
    execute: frozenset[str]
    predicted_full_seconds: float
    predicted_incremental_seconds: float
    predicted_gain: float
    contract_match: bool
    reason: str


def plan_update(mode: str, old_hashes: dict[str, str], current_hashes: dict[str, str],
                old_contract: str, current_contract: str,
                historical_full_seconds: float,
                estimated_setup_seconds: float = 1.0,
                minimum_fractional_gain: float = 0.10) -> Plan:
    """Pick full vs exact-hash incremental, using only pre-update observations.

    This planner is not a novel incremental computation algorithm. The fixed
    incremental cache is its primary strong comparator. The forecast cannot
    justify new semantics, cache correctness, or a security certificate.
    """
    if mode not in {"full", "hash_cache", "prism"}:
        raise ValueError("unrecognized strategy")
    for item in (historical_full_seconds, estimated_setup_seconds,
                 minimum_fractional_gain):
        if not isfinite(item):
            raise ValueError("non-finite calibration")
    if historical_full_seconds < 0 or estimated_setup_seconds < 0:
        raise ValueError("negative time")
    if not 0 <= minimum_fractional_gain < 1:
        raise ValueError("invalid minimum gain")
    if not current_contract:
        raise ValueError("empty scanner contract")
    if not set(current_hashes) <= set(old_hashes) and mode != "full":
        # Newly added modules can be scanned, but no negative is inferred.
        pass
    same = old_contract == current_contract
    delta = changed_files(old_hashes, current_hashes, same)
    count = len(current_hashes)
    fraction = len(delta) / count if count else 0
    setup = min(estimated_setup_seconds, historical_full_seconds)
    predicted_incremental = (
        0.0 if not delta
        else setup + max(0.0, historical_full_seconds - setup) * fraction
    )
    gain = ((historical_full_seconds - predicted_incremental)
            / historical_full_seconds if historical_full_seconds else 0.0)
    if mode == "full":
        strategy, execute, reason = "full", set(current_hashes), "forced_full"
    elif mode == "hash_cache":
        strategy, execute, reason = "incremental", delta, "exact_byte_cache"
    elif not delta and same:
        strategy, execute, reason = "incremental", set(), "no_changed_modules"
    elif not same:
        strategy, execute, reason = "full", set(current_hashes), "scanner_contract_changed"
    elif gain >= minimum_fractional_gain:
        strategy, execute, reason = "incremental", delta, "predicted_cost_saving"
    else:
        strategy, execute, reason = "full", set(current_hashes), "predicted_saving_too_small"
    return Plan(strategy, frozenset(execute), historical_full_seconds,
                predicted_incremental, gain, same, reason)


def merge_findings(current_hashes: dict[str, str], old_hashes: dict[str, str],
                   old_contract: str, current_contract: str,
                   old_ledger: dict[str, tuple[tuple, ...]],
                   refreshed_ledger: dict[str, tuple[tuple, ...]],
                   executed: set[str]) -> dict[str, tuple[tuple, ...]]:
    """Reject missing scans, changed file reuse, and stale tool/rule provenance."""
    current = set(current_hashes)
    if not executed <= current:
        raise ValueError("scan outside current inventory")
    if set(refreshed_ledger) != executed:
        raise ValueError("missing or extraneous scanner results")
    if not executed and old_contract != current_contract:
        raise ValueError("cannot reuse changed scanner/rules contract")
    merged = {}
    for name in current:
        if name in executed:
            merged[name] = refreshed_ledger[name]
        else:
            if old_contract != current_contract:
                raise ValueError("stale scanner configuration")
            if old_hashes.get(name) != current_hashes[name]:
                raise ValueError("stale source bytes")
            if name not in old_ledger:
                raise ValueError("missing cache provenance")
            merged[name] = old_ledger[name]
    return merged


def finding_fingerprint(ledger: dict[str, tuple[tuple, ...]]) -> str:
    """Canonical, multiplicity-preserving fingerprint (all tools included)."""
    import json
    items = []
    for name in sorted(ledger):
        for item in sorted(ledger[name], key=repr):
            items.append([name, list(item)])
    return sha256(json.dumps(items, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode()).hexdigest()
