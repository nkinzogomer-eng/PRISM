"""Adaptive initialization-state hypothesis frontier (source-independent grammar).

D2.4S is an explicitly *post-inspection extension* of D2.4R. Its first
regression on Safe is NOT an independent or blind zero-day discovery.
"""
from __future__ import annotations

from itertools import product

from prism.d24r_zero_capital_probe import propose_treasury_trials


def propose_state_frontier(abi: list[dict], *, max_trials: int = 64) -> dict:
    initial = propose_treasury_trials(abi, max_trials=max_trials)
    if initial["status"] != "FROZEN_HYPOTHESES_AWAIT_NATIVE_EVM":
        return {"status": "UNSUPPORTED_ABI_UNKNOWN", "candidates": [],
                "verified_flaws": 0, "zero_days": 0}
    # Explore deployment-state boundaries, then compare identical operations.
    # Crucially the proposer itself never ingests original Safe source code.
    families = ("unapproved_module_execution", "unsigned_direct_treasury_execution",
                "unauthorized_owner_or_threshold_change", "reinitialization_after_legitimate_setup")
    candidates = [
        {"initialized_by_legitimate_owners": ready, "family": family,
         "requested_transfer_units": amount, "starting_attacker_assets": 0,
         "original_owner_signatures_supplied": 0}
        for ready, family, amount in product((False, True), families, (1, 1000, 1000000))
    ]
    return {"schema": "scm.prism.d24s.deployment-state-frontier.v1",
            "status": "POST_INSPECTION_EXPLORATORY_REPRODUCTION",
            "candidates": candidates[:max_trials],
            "total_proposed": len(candidates),
            "omitted_for_budget": max(0, len(candidates) - max_trials),
            "verified_flaws": 0, "zero_days": 0,
            "classification_rule": "unsafe_uninitialized_deployment != source_vulnerability",
            "limitations": ["known Safe source already inspected",
                            "zero starting assets does not prove zero gas costs",
                            "not an exhaustive state search"]}
