"""Score normalized per-case predictions against an OWASP-style label CSV."""
import argparse
import csv
import json
from pathlib import Path


def read_labels(path):
    labels = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if row[0].strip().lower() in {"test name", "test_id"}:
                continue
            if len(row) < 3:
                raise ValueError("label row needs test ID, category, and expected boolean")
            key = row[0].strip()
            if key in labels:
                raise ValueError("duplicate label ID: " + key)
            labels[key] = (row[1].strip(), row[2].strip().lower() == "true")
            if row[2].strip().lower() not in {"true", "false"}:
                raise ValueError("expected boolean label for " + key)
    if not labels:
        raise ValueError("no labels found")
    return labels


def read_predictions(path, labels):
    predictions = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        required = {"test_id", "category", "detected", "status"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("predictions need test_id, category, detected, status columns")
        for row in reader:
            key = row["test_id"].strip()
            if key not in labels:
                raise ValueError("unknown test ID: " + key)
            if key in predictions:
                raise ValueError("duplicate prediction ID: " + key)
            if row["category"].strip() != labels[key][0]:
                raise ValueError("category mismatch: " + key)
            status = row["status"].strip().lower()
            if status not in {"ok", "error", "unsupported", "timeout", "skipped"}:
                raise ValueError("invalid status: " + status)
            value = row["detected"].strip().lower()
            if status == "ok" and value not in {"true", "false"}:
                raise ValueError("successful prediction must be true or false: " + key)
            if status != "ok" and value:
                raise ValueError("failed prediction must leave detected blank: " + key)
            predictions[key] = (status, value == "true" if status == "ok" else None)
    return predictions


def calculate(labels, predictions):
    result = {}
    categories = sorted({label[0] for label in labels.values()})
    for category in ["ALL"] + categories:
        ids = [key for key, label in labels.items() if category == "ALL" or label[0] == category]
        tp = fp = tn = fn = unknown_pos = unknown_neg = 0
        for key in ids:
            expected = labels[key][1]
            prediction = predictions.get(key)
            if prediction is None or prediction[0] != "ok":
                if expected:
                    unknown_pos += 1
                else:
                    unknown_neg += 1
            elif expected and prediction[1]:
                tp += 1
            elif expected:
                fn += 1
            elif prediction[1]:
                fp += 1
            else:
                tn += 1
        known = tp + fp + tn + fn
        total = len(ids)
        result[category] = {
            "cases": total, "evaluated": known,
            "coverage": known / total if total else None,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "unknown_positive": unknown_pos, "unknown_negative": unknown_neg,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            "recall_lower_bound": tp / (tp + fn + unknown_pos) if tp + fn + unknown_pos else None,
            "false_positive_rate_upper_bound": (fp + unknown_neg) / (fp + tn + unknown_neg) if fp + tn + unknown_neg else None,
        }
    return {
        "schema_version": 1,
        "label_count": len(labels),
        "prediction_rows": len(predictions),
        "missing_rows": len(set(labels) - set(predictions)),
        "results": result,
        "note": "Unknown/error/unsupported/timeout/skipped cases remain unknown; report coverage and bounds. Scores are relative to supplied labels only.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    labels = read_labels(args.labels)
    predictions = read_predictions(args.predictions, labels)
    report = json.dumps(calculate(labels, predictions), indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
