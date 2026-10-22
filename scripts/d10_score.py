"""Evaluate external detector predictions against pinned local D1.0 oracle."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from prism.discovery_oracle import Corpus
from prism.discovery_scoring import score


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    submission = json.loads(args.predictions.read_text(encoding="utf8"))
    if not isinstance(submission, dict) or submission.get("schema") != "d10-predictions-v1":
        raise ValueError("expected d10-predictions-v1 submission object")
    findings = submission.get("findings")
    report = score(Corpus(args.corpus), findings)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)
                           + "\n", encoding="utf8")
    print(json.dumps({
        "tp": report["tp"], "fp": report["fp"], "fn": report["fn"],
        "precision": report["precision"], "recall": report["recall"],
        "detector_cost": "NOT_MEASURED", "output": str(args.output),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
