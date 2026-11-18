"""Small offline JSON CLI for the finite PRISM reference kernel."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .reference import Certificate, FiniteProblem, Hypothesis, Observation, abstain, certified_stop
from .verifier import verify_certificate


class UserInputError(ValueError):
    """Expected malformed or unreadable user input."""


def _read_json_file(path: str, label: str) -> Any:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise UserInputError(f"cannot read {label} file '{path}': {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UserInputError(f"invalid JSON in {label} file '{path}': {exc.msg}") from exc


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise UserInputError(f"{field} must be a non-empty string")
    return value


def _load_problem(path: str) -> FiniteProblem:
    data = _read_json_file(path, "problem")
    if not isinstance(data, dict):
        raise UserInputError("problem must be a JSON object")
    if not isinstance(data.get("hypotheses"), list) or not data["hypotheses"]:
        raise UserInputError("problem.hypotheses must be a non-empty array")
    if not isinstance(data.get("observations"), list):
        raise UserInputError("problem.observations must be an array")
    hypotheses = []
    for index, item in enumerate(data["hypotheses"]):
        if not isinstance(item, dict):
            raise UserInputError(f"hypotheses[{index}] must be an object")
        if not isinstance(item.get("observations"), dict):
            raise UserInputError(f"hypotheses[{index}].observations must be an object")
        observation_values = {
            _require_string(key, f"hypotheses[{index}] observation id"): _require_string(
                value, f"hypotheses[{index}] observation value"
            )
            for key, value in item["observations"].items()
        }
        hypotheses.append(
            Hypothesis(
                _require_string(item.get("id"), f"hypotheses[{index}].id"),
                observation_values,
                _require_string(item.get("decision"), f"hypotheses[{index}].decision"),
            )
        )
    observations = []
    for index, item in enumerate(data["observations"]):
        if not isinstance(item, dict):
            raise UserInputError(f"observations[{index}] must be an object")
        if "cost" not in item:
            raise UserInputError(f"observations[{index}].cost is required")
        observations.append(
            Observation(
                _require_string(item.get("id"), f"observations[{index}].id"),
                item["cost"],
            )
        )
    try:
        return FiniteProblem(hypotheses, observations)
    except (KeyError, TypeError, ValueError) as exc:
        raise UserInputError(f"invalid problem: {exc}") from exc


def _result_payload(result: Any) -> dict[str, Any]:
    payload = {
        "status": result.status,
        "decision": result.decision,
        "reason": result.reason,
        "state": {
            "evidence": dict(result.state.evidence),
            "compatible_hypotheses": sorted(result.state.compatible),
            "cost": {
                name: getattr(result.state.cost, name)
                for name in result.state.cost.__dataclass_fields__
            },
        },
    }
    if result.certificate is not None:
        payload["certificate"] = {
            "hypothesis_ids": list(result.certificate.hypothesis_ids),
            "evidence": [list(item) for item in result.certificate.evidence],
            "decision": result.certificate.decision,
            "scope": result.certificate.scope,
        }
    return payload


def _certificate(data: Any) -> Certificate:
    if not isinstance(data, dict):
        raise UserInputError("certificate must be a JSON object")
    ids = data.get("hypothesis_ids")
    evidence = data.get("evidence")
    if not isinstance(ids, list) or not isinstance(evidence, list):
        raise UserInputError("certificate requires array fields hypothesis_ids and evidence")
    if any(not isinstance(value, str) for value in ids):
        raise UserInputError("certificate hypothesis_ids must contain strings")
    parsed_evidence = []
    for index, item in enumerate(evidence):
        if not isinstance(item, list) or len(item) != 2:
            raise UserInputError(f"certificate evidence[{index}] must be a two-item array")
        parsed_evidence.append((_require_string(item[0], "certificate evidence id"), _require_string(item[1], "certificate evidence value")))
    return Certificate(
        hypothesis_ids=tuple(ids),
        evidence=tuple(parsed_evidence),
        decision=_require_string(data.get("decision"), "certificate decision"),
        scope=data.get("scope", "declared_hypothesis_class"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="prism", description="Offline PRISM SCM reference CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="apply declared observations and attempt certified stopping")
    run.add_argument("problem", help="problem JSON file")
    run.add_argument("--evidence", default="{}", help='JSON object such as {"a":"0"}')
    verify = sub.add_parser("verify-certificate", help="independently verify a certificate")
    verify.add_argument("problem", help="problem JSON file")
    verify.add_argument("certificate", help="certificate JSON file")
    args = parser.parse_args(argv)
    try:
        problem = _load_problem(args.problem)
        if args.command == "run":
            try:
                evidence = json.loads(args.evidence)
            except json.JSONDecodeError as exc:
                raise UserInputError(f"--evidence is not valid JSON: {exc.msg}") from exc
            if not isinstance(evidence, dict):
                raise UserInputError("--evidence must be a JSON object")
            if any(not isinstance(key, str) or not isinstance(value, str) for key, value in evidence.items()):
                raise UserInputError("--evidence keys and values must be strings")
            state = problem.initial_state()
            for observation_id, value in evidence.items():
                state = problem.apply(state, observation_id, value)
            result = certified_stop(problem, state)
            if result is None:
                result = abstain(problem, state, "decision_not_sufficient")
            print(json.dumps(_result_payload(result), sort_keys=True, indent=2))
            return 0 if result.status == "CERTIFIED_DECISION" else 2
        certificate = _certificate(_read_json_file(args.certificate, "certificate"))
        valid = verify_certificate(problem, certificate)
        print(json.dumps({"status": "VERIFIED" if valid else "INVALID", "valid": valid}, indent=2))
        return 0 if valid else 2
    except (UserInputError, KeyError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
