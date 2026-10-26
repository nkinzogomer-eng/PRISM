"""Bounded, ABI-led *hypothesis* generation for zero-capital treasury access.

This module cannot observe EVM execution or certify a vulnerability. It keeps
authorization hypotheses separate from local-EVM witnesses and from actual
profitability, which also depends on transaction sponsorship and gas.
"""
from __future__ import annotations

from hashlib import sha256
from itertools import product
import json


_REQUIRED = {
    ("setup", ("address[]", "uint256", "address", "bytes", "address", "address", "uint256", "address")),
    ("execTransaction", ("address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes")),
    ("execTransactionFromModule", ("address", "uint256", "bytes", "uint8")),
    ("addOwnerWithThreshold", ("address", "uint256")),
    ("changeThreshold", ("uint256",)),
    ("getThreshold", ()),
    ("isOwner", ("address",)),
}


def propose_treasury_trials(abi: list[dict], *, max_trials: int = 64) -> dict:
    if type(abi) is not list or len(abi) > 512 or len(json.dumps(abi)) > 200_000:
        raise ValueError("INVALID_ABI_BUDGET")
    if type(max_trials) is not int or not 1 <= max_trials <= 64:
        raise ValueError("INVALID_TRIAL_BUDGET")
    methods = set()
    for method in abi:
        if not isinstance(method, dict):
            raise ValueError("INVALID_ABI_ITEM")
        if method.get("type") != "function":
            continue
        inputs = method.get("inputs", [])
        if not isinstance(inputs, list) or any(not isinstance(x, dict) for x in inputs):
            raise ValueError("INVALID_ABI_INPUTS")
        methods.add((method.get("name"), tuple(x.get("type") for x in inputs)))
    missing = sorted(_REQUIRED - methods)
    if missing:
        return {"schema": "scm.prism.d24r.zero-capital.v1", "status": "UNSUPPORTED_ABI_UNKNOWN",
                "missing": repr(missing), "candidates": [], "verified_flaws": 0, "zero_days": 0}

    # Pinned before implementation-source inspection: four covered families,
    # three amounts per family. Full signature replay is *not* covered.
    families = ("unapproved_module_execution", "unsigned_direct_treasury_execution",
                "unauthorized_owner_or_threshold_change", "reinitialization_after_legitimate_setup")
    candidates = [{"family": family, "requested_transfer_units": amount,
                   "attacker_start_assets": 0, "owner_signatures_supplied": 0,
                   "authorized_modules_supplied": 0,
                   "required_native_observation": ["attacker_asset_delta",
                       "owner_threshold_state_delta", "original_code_attestation"]}
                  for family, amount in product(families, (1, 1000, 1000000))]
    return {"schema": "scm.prism.d24r.zero-capital.v1",
            "abi_sha256": sha256(json.dumps(abi, sort_keys=True).encode()).hexdigest(),
            "status": "FROZEN_HYPOTHESES_AWAIT_NATIVE_EVM",
            "candidates": candidates[:max_trials],
            "total_proposed": len(candidates),
            "omitted_for_budget": max(0, len(candidates) - max_trials),
            "uncovered_frozen_families": ["signature_replay_without_fresh_authorization"],
            "verified_flaws": 0, "zero_days": 0,
            "limits": ["No EVM witness from static proposal alone",
                       "No live asset access or on-chain transactions",
                       "Zero starting assets is not zero actual gas expense",
                       "No bounded search can establish global safety"]}
