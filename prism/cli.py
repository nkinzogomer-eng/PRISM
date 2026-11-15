"""Small offline JSON CLI for the finite PRISM reference kernel."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .reference import Certificate, FiniteProblem, Hypothesis, Observation, certified_stop


def _load_problem(path: str) -> FiniteProblem:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("problem must be a JSON object")
    hypotheses = [
        Hypothesis(str(item["id"]), dict(item["observations"]), str(item["decision"]))
        for item in data["hypotheses"]
    ]
    observations = [
        Observation(str(item["id"]), float(item["cost"]))
        for item in data["observations"]
    ]
    return FiniteProblem(hypotheses, observations)


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


def _certificate(data: dict[str, Any]) -> Certificate:
    return Certificate(
        hypothesis_ids=tuple(data["hypothesis_ids"]),
        evidence=tuple(tuple(item) for item in data["evidence"]),
        decision=data["decision"],
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
            evidence = json.loads(args.evidence)
            state = problem.initial_state()
            for observation_id, value in evidence.items():
                state = problem.apply(state, observation_id, str(value))
            result = certified_stop(problem, state)
            if result is None:
                from .reference import abstain
                result = abstain(problem, state, "decision_not_sufficient")
            print(json.dumps(_result_payload(result), sort_keys=True, indent=2))
            return 0 if result.status == "CERTIFIED_DECISION" else 2
        certificate = _certificate(json.loads(Path(args.certificate).read_text(encoding="utf-8")))
        valid = problem.verify(certificate)
        print(json.dumps({"status": "VERIFIED" if valid else "INVALID", "valid": valid}, indent=2))
        return 0 if valid else 2
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, indent=2))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
