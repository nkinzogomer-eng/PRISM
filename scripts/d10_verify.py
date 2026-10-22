"""Verify D1.0 local ground truth and produce an auditable baseline score.

The empty-finding baseline is a scorer sanity check, NOT a detector benchmark.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter

from prism.discovery_oracle import Corpus
from prism.discovery_scoring import score


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = perf_counter()
    corpus = Corpus(args.corpus)
    report = {
        "schema": "d10-oracle-check-v1",
        "validation": corpus.validate_all(),
        "empty_prediction_scorer_smoke_test": score(corpus, []),
        "scope": "local toy development corpus with executable oracle",
        "detector_executed": False,
        "total_oracle_validation_seconds": perf_counter() - started,
    }
    if (report["empty_prediction_scorer_smoke_test"]["tp"] != 0 or
            report["empty_prediction_scorer_smoke_test"]["fn"] != 12):
        raise RuntimeError("empty prediction scorer sanity check failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)
                           + "\n", encoding="utf-8")
    print(json.dumps({
        "status": report["validation"]["status"],
        "cases": report["validation"]["case_count"],
        "positive": report["validation"]["positive_count"],
        "negative": report["validation"]["negative_count"],
        "empty_score": {
            "tp": 0, "fp": 0, "fn": 12,
            "recall": report["empty_prediction_scorer_smoke_test"]["recall"],
        },
        "detector_executed": False,
        "report": str(args.output),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
