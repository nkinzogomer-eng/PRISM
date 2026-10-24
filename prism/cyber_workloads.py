"""Three model-level cyber families sharing the same structural search core.

The web fixtures are researcher-authored negative controls, and the DeFi case
wraps the existing restricted D2.2 reference model. None is a real zero-day.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from random import Random

from prism.cyber_kernel import Domain, Effect


def effect(reads: str, writes: str) -> Effect:
    return Effect(frozenset(reads.split()), frozenset(writes.split()))


@dataclass(frozen=True)
class AuthState:
    signed_in: bool = False
    fallback_enabled: bool = False
    admin: bool = False
    unauthorized_access: bool = False
    theme: bool = False
    logs: bool = False
    cache: bool = False
    metric: bool = False


def auth_case(*, vulnerable: bool, seed: int) -> Domain:
    effects = {
        "sign_in": effect("signed_in", "signed_in"),
        "activate_fallback": effect("signed_in fallback_enabled", "fallback_enabled"),
        "access_private": effect("signed_in fallback_enabled admin unauthorized_access", "unauthorized_access"),
        "flip_theme": effect("theme", "theme"),
        "rotate_logs": effect("logs", "logs"),
        "set_cache": effect("cache", "cache"),
        "update_metric": effect("metric", "metric"),
    }
    actions = [(name, 0) for name in effects]
    Random(seed).shuffle(actions)

    def step(state: AuthState, action: tuple[str, int]) -> AuthState | None:
        op, _ = action
        if op == "sign_in":
            return replace(state, signed_in=True)
        if op == "activate_fallback":
            if not state.signed_in:
                return None
            return replace(state, fallback_enabled=True)
        if op == "access_private":
            if not state.signed_in:
                return None
            if not (state.admin or (state.fallback_enabled and vulnerable)):
                return None
            return replace(state, unauthorized_access=not state.admin)
        name = {"flip_theme": "theme", "rotate_logs": "logs",
                "set_cache": "cache", "update_metric": "metric"}.get(op)
        if name is None:
            raise ValueError(op)
        return replace(state, **{name: not getattr(state, name)})

    return Domain("web_authorization", "broken_fallback" if vulnerable else "guarded",
                  AuthState(), tuple(actions), effects, frozenset({"unauthorized_access"}),
                  step, lambda s: s.unauthorized_access,
                  "synthetic authz regression, no live target")


@dataclass(frozen=True)
class InputState:
    received: bool = False
    prepared: bool = False
    route_open: bool = False
    sanitized: bool = False
    unsafe_exec: bool = False
    ui: bool = False
    metrics: bool = False
    cache: bool = False
    log_rotation: bool = False


def input_case(*, vulnerable: bool, seed: int) -> Domain:
    effects = {
        "receive": effect("received", "received"),
        "prepare": effect("received prepared", "prepared"),
        "open_route": effect("route_open", "route_open"),
        "sanitize": effect("received sanitized", "sanitized"),
        "execute": effect("received prepared route_open sanitized unsafe_exec", "unsafe_exec"),
        "change_ui": effect("ui", "ui"),
        "sample_metrics": effect("metrics", "metrics"),
        "warm_cache": effect("cache", "cache"),
        "rotate_log": effect("log_rotation", "log_rotation"),
    }
    actions = [(name, 0) for name in effects]
    Random(seed).shuffle(actions)

    def step(state: InputState, action: tuple[str, int]) -> InputState | None:
        op, _ = action
        if op == "receive":
            return replace(state, received=True)
        if op == "prepare":
            return replace(state, prepared=True) if state.received else None
        if op == "open_route":
            return replace(state, route_open=True)
        if op == "sanitize":
            return replace(state, sanitized=True) if state.received else None
        if op == "execute":
            if not (state.received and state.prepared and state.route_open):
                return None
            if not state.sanitized and not vulnerable:
                return None
            return replace(state, unsafe_exec=not state.sanitized)
        name = {"change_ui": "ui", "sample_metrics": "metrics",
                "warm_cache": "cache", "rotate_log": "log_rotation"}.get(op)
        if name is None:
            raise ValueError(op)
        return replace(state, **{name: not getattr(state, name)})

    return Domain("untrusted_input_flow", "unsafe_sink" if vulnerable else "guarded",
                  InputState(), tuple(actions), effects, frozenset({"unsafe_exec"}),
                  step, lambda s: s.unsafe_exec,
                  "synthetic taint/sink regression, no live application")


def defi_case(*, scenario: str, property_id: str, seed: int) -> Domain:
    from prism import defi_multi
    if scenario not in defi_multi.CASES or property_id not in defi_multi.PROPERTIES:
        raise ValueError("unsupported DeFi benchmark")
    effects = {
        "deposit": effect("owned_collateral locked", "owned_collateral locked"),
        "borrow": effect("debt locked price pool_stable owned_stable", "debt pool_stable owned_stable"),
        "withdraw": effect("debt price locked owned_collateral unsafe_withdrawal", "locked owned_collateral unsafe_withdrawal"),
        "repay": effect("debt owned_stable pool_stable unfunded_repayment", "debt owned_stable pool_stable unfunded_repayment"),
        "price": effect("price unauthorized_price_write", "price unauthorized_price_write"),
    }
    fields = {
        "unauthorized_oracle_write": "unauthorized_price_write price",
        "unsafe_collateral_withdrawal": "unsafe_withdrawal debt locked price",
        "unfunded_debt_repayment": "unfunded_repayment",
    }
    actions = list(defi_multi.ACTIONS)
    Random(seed).shuffle(actions)
    flags = defi_multi.flags_for(scenario)
    return Domain("defi_accounting_D22", f"{scenario}:{property_id}",
                  defi_multi.State(), tuple(actions), effects,
                  frozenset(fields[property_id].split()),
                  lambda state, action: defi_multi.transition(state, action, flags),
                  lambda state: defi_multi.violated(state, property_id),
                  "previously published researcher-authored D2.2 DeFi model")


def cases(seeds: range | tuple[int, ...] = range(8)) -> list[Domain]:
    items = []
    for seed in seeds:
        items.extend((auth_case(vulnerable=True, seed=seed),
                      auth_case(vulnerable=False, seed=seed),
                      input_case(vulnerable=True, seed=seed),
                      input_case(vulnerable=False, seed=seed)))
        for goal, defect in (("unauthorized_oracle_write", "oracle_bug"),
                             ("unsafe_collateral_withdrawal", "withdraw_bug"),
                             ("unfunded_debt_repayment", "repay_bug")):
            items.append(defi_case(scenario=defect, property_id=goal, seed=seed))
            items.append(defi_case(scenario="safe", property_id=goal, seed=seed))
    return items
