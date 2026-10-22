"""D1.0 vulnerability-level scoring, with executable witness validation.

No case contributes a true positive on the strength of a text label or an
unverified scanner alert. Wrong/missing evidence counts as unsupported, not TP.
Unknown source files, oracle contradictions and corrupt provenance are hard
errors. Duplicate proposals cannot create additional true positives.
"""
from __future__ import annotations

from collections import Counter
from time import perf_counter

from prism.discovery_oracle import Corpus, PROPERTY_CLASSES


class OracleConflict(RuntimeError):
    """Candidate demonstrates a new violation in a supposedly patched case.

    Stop evaluation; do not quietly call the candidate a false positive or
    retroactively alter the frozen benchmark truth.
    """


def _safe_ratio(numerator: int, denominator: int):
    return numerator / denominator if denominator else None


def score(corpus: Corpus, findings: list[dict]) -> dict:
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    if len(findings) > 500:
        raise ValueError("too many findings")
    start = perf_counter()
    truth = corpus.validate_all()  # independent check for every evaluation
    positive = {k for k in corpus.truth if
                corpus.truth[k]["ground_truth"] == "vulnerable"}
    all_cases = set(corpus.rows)
    found = set()
    seen = set()
    audits = []
    false_positive = 0
    unsupported = 0
    duplicates = 0

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            raise ValueError("finding must be a JSON object")
        case_id = finding.get("case_id")
        if not isinstance(case_id, str) or case_id not in all_cases:
            raise ValueError(f"finding {index}: case ID out of frozen scope")
        property_id = finding.get("property_id")
        correct_property = corpus.rows[case_id]["property_id"]
        key = (case_id, property_id)
        if key in seen:
            duplicates += 1
            false_positive += 1
            audits.append({"index": index, "case_id": case_id,
                           "verdict": "DUPLICATE_UNSUPPORTED"})
            continue
        seen.add(key)
        if property_id != correct_property:
            false_positive += 1
            unsupported += 1
            audits.append({"index": index, "case_id": case_id,
                           "verdict": "WRONG_PROPERTY"})
            continue
        witness = finding.get("witness")
        try:
            observed = corpus.observe(case_id, witness)
            confirmed = (observed["benign_control_pass"] and
                         observed["unauthorized_disclosure"])
        except (ValueError, TypeError, KeyError) as exc:
            confirmed = False
            observed = {"error": type(exc).__name__}
        if confirmed and case_id not in positive:
            raise OracleConflict(
                f"Potential incorrectly labeled patched fixture {case_id}; "
                "freeze result and adjudicate manually before any score."
            )
        if confirmed:
            found.add(case_id)
            verdict = "TRUE_POSITIVE_WITH_BEHAVIORAL_WITNESS"
        else:
            false_positive += 1
            unsupported += 1
            verdict = "UNSUPPORTED_FINDING"
        audits.append({
            "index": index, "case_id": case_id, "property_id": property_id,
            "verdict": verdict,
            "proof": {k: v for k, v in observed.items()
                      if k != "oracle_wall_seconds"},
        })
    tp = len(found)
    fn = len(positive - found)
    # A negative with no accepted finding is negative only within the
    # specific frozen oracle test and property, not generally secure.
    tn = len(all_cases - positive -
             {row["case_id"] for row in audits if row["verdict"] !=
              "TRUE_POSITIVE_WITH_BEHAVIORAL_WITNESS"})
    fp = false_positive
    precision = _safe_ratio(tp, tp + fp)
    recall = tp / len(positive) if positive else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and
          precision + recall > 0 else 0.0)
    family = {}
    for property_id in PROPERTY_CLASSES:
        members = {k for k, val in corpus.rows.items()
                   if val["property_id"] == property_id}
        denominator = len(members & positive)
        family[property_id] = {
            "confirmed": len(members & found),
            "oracle_positive": denominator,
            "recall": _safe_ratio(len(members & found), denominator),
        }
    return {
        "schema": "d10-evaluation-v1",
        "oracle_status": truth["status"],
        "scope": "development-only canonical property and executable witness",
        "public_manifest_sha256": corpus.public["public_manifest_sha256"],
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "duplicate_proposals": duplicates,
        "unsupported_proposals": unsupported,
        "predicted_count": len(findings),
        "true_positive_count": len(positive),
        "true_negative_count": len(all_cases) - len(positive),
        "precision": precision, "recall": recall, "f1": f1,
        "property_recall": family,
        "confirmed_case_ids": sorted(found),
        "missed_case_ids": sorted(positive - found),
        "audit": audits,
        "oracle_and_scoring_wall_seconds": perf_counter() - start,
        "detector_resource_usage": "NOT_MEASURED_BY_THIS_SCORER",
        "warning": "These numbers only measure the generated development "
                   "fixtures. They are not independent or natural prevalence "
                   "estimates and cannot support 18/20 or critical-CVE claims.",
    }
