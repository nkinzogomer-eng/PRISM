"""Independent finite certificate verification.

This module consumes only a declared problem and a received certificate. It does
not call `FiniteProblem.certificate` or trust a result produced by a runner.
The guarantee is relative to the declared finite hypothesis class only.
"""
from __future__ import annotations

from typing import Any

from .reference import Certificate


def verify_certificate(problem: Any, certificate: Any) -> bool:
    """Recompute certificate compatibility and decision invariance."""
    if not isinstance(certificate, Certificate):
        return False
    if certificate.scope != "declared_hypothesis_class":
        return False
    if (
        not isinstance(certificate.hypothesis_ids, tuple)
        or not certificate.hypothesis_ids
        or any(not isinstance(value, str) for value in certificate.hypothesis_ids)
        or len(set(certificate.hypothesis_ids)) != len(certificate.hypothesis_ids)
    ):
        return False
    if any(value not in problem.hypotheses for value in certificate.hypothesis_ids):
        return False
    if (
        not isinstance(certificate.evidence, tuple)
        or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or any(not isinstance(value, str) for value in item)
            for item in certificate.evidence
        )
        or not isinstance(certificate.decision, str)
    ):
        return False
    evidence_ids = tuple(item[0] for item in certificate.evidence)
    if (
        len(set(evidence_ids)) != len(evidence_ids)
        or any(value not in problem.observations for value in evidence_ids)
    ):
        return False
    compatible = {
        hypothesis_id
        for hypothesis_id, hypothesis in problem.hypotheses.items()
        if all(hypothesis.observations[key] == value for key, value in certificate.evidence)
    }
    if compatible != set(certificate.hypothesis_ids):
        return False
    decisions = {problem.hypotheses[value].decision for value in compatible}
    return decisions == {certificate.decision}
