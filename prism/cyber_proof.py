"""SCM cross-domain: reproducible behavioral witnesses across real program revisions.

Pure deterministic protocol core. A property-specific adapter supplies
candidate inputs, execution and an independent predicate. No CVE IDs, labels
or 'known vulnerability' flags may influence candidate synthesis.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Callable, Iterable


@dataclass(frozen=True)
class Probe:
    id: str
    input: str
    expects_rejection: bool
    provenance: str


@dataclass(frozen=True)
class Observation:
    probe: str
    input: str
    expectation: str
    before: str
    after: str
    before_matches: bool
    after_matches: bool
    property_changed: bool


def run_revision_pair(
    probes: Iterable[Probe],
    *,
    before: Callable[[str], str | None],
    after: Callable[[str], str | None],
    render: Callable[[str | None], str] | None = None,
) -> dict:
    """Run the SAME frozen probes against two independently obtained binaries/sources.

    Only explicit REJECT/ACCEPT classification is considered for decision.
    Never equate a returned string with file disclosure or remote exploit.
    """
    checked = list(probes)
    if not checked or len({p.id for p in checked}) != len(checked):
        raise ValueError("empty or duplicated proof obligations")
    if any(not p.provenance for p in checked):
        raise ValueError("missing candidate provenance")
    observations = []
    for probe in checked:
        pre = before(probe.input)
        post = after(probe.input)
        if pre is not None and not isinstance(pre, str):
            raise TypeError("invalid first revision output")
        if post is not None and not isinstance(post, str):
            raise TypeError("invalid second revision output")
        pre_rejected = pre is None
        post_rejected = post is None
        observations.append(Observation(
            probe.id, probe.input, "REJECT" if probe.expects_rejection else "ACCEPT",
            "REJECT" if pre_rejected else "ACCEPT",
            "REJECT" if post_rejected else "ACCEPT",
            pre_rejected == probe.expects_rejection,
            post_rejected == probe.expects_rejection,
            pre_rejected != post_rejected,
        ))
    regressions = [asdict(item) for item in observations
                   if not item.before_matches and item.after_matches]
    failures = [asdict(item) for item in observations if not item.after_matches]
    regressions.sort(key=lambda x: (len(x["input"]), x["input"], x["probe"]))
    raw = [asdict(item) for item in observations]
    return {
        "schema": "scm-verifiable-behavioral-witness-v1",
        "status": "REVISION_PAIR_OBSERVED_UNADJUDICATED",
        "probe_count": len(checked),
        "historical_regression_candidates": len(regressions),
        "after_property_failures": failures,
        "minimal_observed_witness": regressions[0] if regressions else None,
        "observations": raw,
        "deterministic_replay_sha256": sha256(
            __import__("json").dumps(raw, sort_keys=True).encode()).hexdigest(),
        "independent_real_world_exploit_proved": False,
        "novel_discovery_proved": False,
    }
