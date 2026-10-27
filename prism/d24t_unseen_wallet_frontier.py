"""ABI-derived authorization/state exploration for a held-out smart account.

The frozen target and action families were registered before this source was
examined. This planner generates hypotheses, not any security verdict.
"""
from __future__ import annotations

from hashlib import sha256
from itertools import product
import json


_ABI_FUNCTIONS = {
    "initialize": ("address",),
    "execute": ("address", "uint256", "bytes"),
    "executeBatch": ("address[]", "uint256[]", "bytes[]"),
    "owner": (),
}


def propose_wallet_frontier(abi: list[dict], *, max_trials: int = 24) -> dict:
    if type(abi) is not list or len(abi) > 512 or len(json.dumps(abi)) > 200_000:
        raise ValueError("INVALID_ABI_BUDGET")
    if type(max_trials) is not int or not 1 <= max_trials <= 24:
        raise ValueError("INVALID_TRIAL_BUDGET")
    methods = set()
    for item in abi:
        if not isinstance(item, dict):
            raise ValueError("INVALID_ABI_ITEM")
        if item.get("type") != "function":
            continue
        params = item.get("inputs", [])
        if not isinstance(params, list) or any(not isinstance(x, dict) for x in params):
            raise ValueError("INVALID_ABI_INPUTS")
        methods.add((item.get("name"), tuple(x.get("type") for x in params)))
    missing = sorted((name, args) for name, args in _ABI_FUNCTIONS.items()
                     if (name, args) not in methods)
    if missing:
        return {"status": "UNSUPPORTED_ABI_UNKNOWN", "missing": repr(missing),
                "candidates": [], "verified_flaws": 0, "zero_days": 0}

    families = ("direct_execution_without_owner_authorization",
                "batched_execution_without_owner_authorization",
                "repeated_initialization_attempt")
    plans = [
        {"deployment_state": state, "family": family, "requested_token_outflow": amount,
         "attacker_start_units": 0, "authorized_owner_signatures": 0,
         "require_observation": ["original_impl_owner", "attacker_balance_delta",
                                 "treasury_balance_delta", "post_operation_owner"]}
        for state, family, amount in product(("official_initialized", "proxy_uninitialized"),
                                             families, (1, 1000, 1000000))
    ]
    # Do not pretend a direct ownership setter is covered if the ABI lacks it.
    setter = any(name in ("transferOwnership", "changeOwner") for name, _ in methods)
    unsupported = [] if setter else ["unauthorized_ownership_transfer"]
    return {"schema": "scm.prism.d24t.unseen-wallet-state-frontier.v1",
            "status": "SOURCE_INDEPENDENT_HYPOTHESES_PENDING_EVM",
            "abi_sha256": sha256(json.dumps(abi, sort_keys=True).encode()).hexdigest(),
            "candidates": plans[:max_trials], "total_proposed": len(plans),
            "omitted_for_budget": max(0, len(plans) - max_trials),
            "unsupported_registered_families": unsupported,
            "verified_flaws": 0, "zero_days": 0,
            "limits": ["Only ABI-supported caller routes represented",
                       "ERC4337 UserOperation and external EntryPoint not tested",
                       "Zero starting funds does not prove zero actual fees",
                       "No real wallet is contacted and no universal-safety claim"]}
