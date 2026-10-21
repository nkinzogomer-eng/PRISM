"""Cost-aware execution planning for a *binary OR* decision.

A success here cannot certify absence of vulnerabilities or preserve the
complete list of findings. It is not a general-purpose static analyzer.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


@dataclass(frozen=True)
class CostEstimate:
    first_seconds: float
    second_seconds: float
    first_positive_fraction: float
    planning_seconds: float = 0.0

    def __post_init__(self):
        numbers = (self.first_seconds, self.second_seconds,
                   self.first_positive_fraction, self.planning_seconds)
        if not all(isfinite(x) for x in numbers):
            raise ValueError("estimates must be finite")
        if min(self.first_seconds, self.second_seconds, self.planning_seconds) < 0:
            raise ValueError("costs must be non-negative")
        if not 0 <= self.first_positive_fraction <= 1:
            raise ValueError("positive fraction must be in [0, 1]")

    def full_cost(self) -> float:
        return self.first_seconds + self.second_seconds

    def sequential_cost(self) -> float:
        return (self.first_seconds + self.planning_seconds
                + (1 - self.first_positive_fraction) * self.second_seconds)


def choose_plan(estimate: CostEstimate, minimum_fractional_gain: float = 0.10) -> dict:
    """Select full or first-then-second using *external*, frozen cost estimates.

    The second tool may be omitted only for a module already positive under
    the first tool, and only for a module-level binary OR decision. This is a
    forecast, not a claim of actual savings or sound program analysis.
    """
    if not isfinite(minimum_fractional_gain) or not 0 <= minimum_fractional_gain < 1:
        raise ValueError("invalid improvement threshold")
    full = estimate.full_cost()
    sequential = estimate.sequential_cost()
    gain = (full - sequential) / full if full else 0.0
    mode = "sequential" if full and gain >= minimum_fractional_gain else "full"
    return {
        "mode": mode, "predicted_full_seconds": full,
        "predicted_sequential_seconds": sequential,
        "predicted_fractional_gain": gain,
        "minimum_fractional_gain": minimum_fractional_gain,
        "assumption": "independent whole-module binary OR; no claim about individual findings",
    }


def second_stage_inventory(universe: set[str], first_positive: set[str]) -> set[str]:
    """Skip the second scanner only after a verified first-scanner positive."""
    if not first_positive <= universe:
        raise ValueError("first scanner returned an unknown module")
    return universe - first_positive


def checked_or(universe: set[str], first_positive: set[str],
               second_positive: set[str], second_scanned: set[str],
               sequential: bool) -> set[str]:
    """Fail closed on incomplete stage coverage; never convert skipped to negative."""
    if not first_positive <= universe or not second_positive <= universe:
        raise ValueError("unknown module in findings")
    required = second_stage_inventory(universe, first_positive) if sequential else universe
    if second_scanned != required:
        raise ValueError("missing, unexpected or unverified second-stage modules")
    if not second_positive <= second_scanned:
        raise ValueError("findings outside the verified scan inventory")
    return first_positive | second_positive
