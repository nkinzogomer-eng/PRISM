"""Bounded, label-free native-EVM *experiment planner* for ETH vaults.

The engine accepts a public ABI, not a vulnerability label or a test oracle.
It does not assume a vulnerability, and all candidate sequences must be run
against fresh EVM deployments before any verdict. This is only the first,
very narrow, autonomous dynamic-search capability; it is not a zero-day tool.
"""
from __future__ import annotations

from hashlib import sha256
from itertools import product
import json


def propose_trials(abi: list[dict], *, max_trials: int = 24) -> dict:
    if type(abi) is not list or len(abi) > 256 or len(json.dumps(abi)) > 100_000:
        raise ValueError("INVALID_OR_UNBOUNDED_ABI")
    if type(max_trials) is not int or not 1 <= max_trials <= 48:
        raise ValueError("INVALID_TRIAL_BUDGET")
    methods = {}
    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "function":
            continue
        name = item.get("name")
        if not isinstance(name, str):
            raise ValueError("INVALID_FUNCTION_NAME")
        signature = (tuple(x.get("type") for x in item.get("inputs", [])),
                     item.get("stateMutability"))
        methods.setdefault(name, set()).add(signature)
    # A deliberately *declared*, bounded interaction grammar. It is not a
    # general ABI solver. No fallback to guessing signatures/semantics.
    if (((), "payable") not in methods.get("deposit", set()) or
        not any(sig[0] == () for sig in methods.get("withdraw", set()))):
        return {"schema":"scm.prism.d24p.abi-trial-plan.v1",
                "abi_sha256":sha256(json.dumps(abi,sort_keys=True).encode()).hexdigest(),
                "status":"UNSUPPORTED_ABI_NOT_SAFE", "trials":[],
                "native_witness_count":0,"confirmed_vulnerabilities":0}
    trials=[]
    # Vary honest liquidity, attacker capital and reentry budget; each trial
    # must use a NEW deployment. No hardcoded target sequence/witness labels.
    for honest, stake, retries in product((1, 2, 3), (1, 2), (0, 1, 2)):
        trials.append({"honest_ether":honest,"stake_ether":stake,
                       "callback_retry_budget":retries,
                       "operations":["honest.deposit", "attacker.deposit",
                                     "attacker.withdraw", "observe_balances_and_eth"]})
    return {"schema":"scm.prism.d24p.abi-trial-plan.v1",
            "abi_sha256":sha256(json.dumps(abi,sort_keys=True).encode()).hexdigest(),
            "status":"READY_FOR_NATIVE_EVM_SEARCH_NOT_VERIFIED",
            "trials":trials[:max_trials],
            "trials_skipped_for_budget":max(0,len(trials)-max_trials),
            "native_witness_count":0,"confirmed_vulnerabilities":0,
            "budget_cap":max_trials,
            "limitations":["Only payable deposit() and zero-argument withdraw() vaults",
                           "No governance, oracle, liquidation, ERC20 or general ABI synthesis",
                           "Witness requires real EVM value conservation and honest-liability shortfall",
                           "Any untested target or excluded ABI is UNKNOWN, never SAFE"]}
