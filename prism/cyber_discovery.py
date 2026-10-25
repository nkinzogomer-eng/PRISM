"""D2.4G: source-only, bounded, verifiable cyber discovery interface.

No vulnerability labels, fix versions, patch diffs or CVE identifiers enter
the discovery engine.  The caller supplies a security PROPERTY and a real
execution adapter.  A witness is not a full exploit and a run with no witness
does not establish safety.  This is an adapter protocol, not a general scanner.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from time import perf_counter
from typing import Callable, Iterable


@dataclass(frozen=True)
class SecurityProbe:
    identifier: str
    payload: str
    expected: str  # "ALLOW" / "DENY" under the explicitly scoped property
    derivation: str


@dataclass(frozen=True)
class ProbeObservation:
    identifier: str
    payload: str
    expected: str
    observed: str
    violation: bool
    derivation: str
    witness: str | None


def discover(
    *,
    project: str,
    source_sha256: str,
    property_id: str,
    probes: Iterable[SecurityProbe],
    observe: Callable[[str], tuple[str, str | None]],
    max_probes: int,
    context: dict | None = None,
) -> dict:
    """Execute genuine target code through observe; evaluate independent oracle.

    observe(payload) returns (ALLOW|DENY, optional observed resource).
    Caller owns containment/safety policy and source isolation. Failed calls
    raise, rather than silently proving safety. Results distinguish confirmed
    local property violation from new vulnerability adjudication.
    """
    if not project or not property_id or len(source_sha256) != 64:
        raise ValueError("project, property and source digest required")
    if type(max_probes) is not int or not 1 <= max_probes <= 1000:
        raise ValueError("invalid explicit per-mission probe budget")
    frozen = list(probes)
    if not frozen or len(frozen) > max_probes:
        raise ValueError("candidate set empty/exceeds mission probe budget")
    if len(set(p.identifier for p in frozen)) != len(frozen):
        raise ValueError("repeated candidate identifiers")
    if any(p.expected not in ("ALLOW", "DENY") or not p.derivation
           for p in frozen):
        raise ValueError("unknown or unattributed security property candidate")
    t0 = perf_counter()
    observations: list[ProbeObservation] = []
    for candidate in frozen:
        actual, target = observe(candidate.payload)
        if actual not in ("ALLOW", "DENY"):
            raise ValueError("oracle returned non-discrete or unsupported status")
        observations.append(ProbeObservation(
            identifier=candidate.identifier,
            payload=candidate.payload,
            expected=candidate.expected,
            observed=actual,
            violation=actual != candidate.expected,
            derivation=candidate.derivation,
            witness=target,
        ))
    mistakes = [asdict(x) for x in observations if x.violation]
    # Deterministic ordering makes it easy for Ciel to budget follow-up steps.
    mistakes.sort(key=lambda x: (len(x["payload"]), x["payload"], x["identifier"]))
    stable = [asdict(x) for x in observations]
    source_state = "LOCAL_PROPERTY_WITNESS" if mistakes else "NO_WITNESS_NOT_SAFE"
    return {
        "schema": "scm.prism.discovery.v1",
        "status": source_state,
        "target": {"project": project, "source_sha256": source_sha256,
                   "security_property": property_id},
        "budget": {"max_probes": max_probes, "used_probes": len(observations)},
        "hypotheses_generated": len(frozen),
        "observed_property_violations": len(mistakes),
        "minimal_observed_witness": mistakes[0] if mistakes else None,
        "all_violations": mistakes,
        "observations": stable,
        "replay_sha256": sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest(),
        "elapsed_seconds": perf_counter() - t0,
        "verification": {
            "method": "isolated_real_source_execution_and_explicit_property_oracle",
            "local_property_reproduced": bool(mistakes),
            "real_world_exploit_confirmed": False,
            "previously_unknown_vulnerability_confirmed": False,
            "overall_program_safety_proved": False,
        },
        "limitations": context or {},
    }


def ciel_capability_result(findings: dict, *, mission_id: str,
                           task_id: str, authorized: bool) -> dict:
    """Pure JSON interoperability contract: Ciel still verifies independently.

    Does NOT claim execution within Ciel. A Ciel adapter must validate scope,
    hashes, provenance and verifier before trusting these observations.
    """
    if not mission_id or not task_id:
        raise ValueError("Ciel correlation identifiers required")
    if authorized is not True:
        raise PermissionError("unauthorized target; never export as an executable mission")
    if findings.get("schema") != "scm.prism.discovery.v1":
        raise ValueError("unsupported/untrusted PRISM evidence schema")
    return {
        "schema": "scm.prism.ciel-capability.v1",
        "capability": "prism.cyber.discovery",
        "mission_id": mission_id,
        "task_id": task_id,
        "execution_policy": "LOCAL_READ_ONLY",
        "requires_external_runtime": True,
        "observation": findings,
        "ciel_verification_state": "UNVERIFIED",
        "needs_independent_attestation": True,
        "claim_of_new_vulnerability": False,
    }
