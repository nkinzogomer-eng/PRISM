import csv
import tempfile
import unittest
from pathlib import Path

from scripts.score_phase4 import calculate, read_labels, read_predictions


class Phase4ScoringTests(unittest.TestCase):
    def write(self, folder, name, text):
        path = Path(folder) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_counts_metrics_and_unknown_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            labels_path = self.write(
                folder, "labels.csv",
                "# source metadata\n"
                "CaseA,sqli,true,89\n"
                "CaseB,sqli,false,89\n"
                "CaseC,pathtraver,true,22\n"
                "CaseD,pathtraver,false,22\n",
            )
            predictions_path = self.write(
                folder, "predictions.csv",
                "test_id,category,detected,status\n"
                "CaseA,sqli,true,ok\n"
                "CaseB,sqli,true,ok\n"
                "CaseC,pathtraver,,timeout\n",
            )
            labels = read_labels(labels_path)
            predictions = read_predictions(predictions_path, labels)
            report = calculate(labels, predictions)
            overall = report["results"]["ALL"]
            self.assertEqual((overall["tp"], overall["fp"], overall["tn"], overall["fn"]), (1, 1, 0, 0))
            self.assertEqual(overall["unknown_positive"], 1)
            self.assertEqual(overall["unknown_negative"], 1)
            self.assertEqual(overall["evaluated"], 2)
            self.assertEqual(overall["coverage"], 0.5)
            self.assertEqual(overall["recall_lower_bound"], 0.5)
            self.assertEqual(overall["false_positive_rate_upper_bound"], 1.0)

    def test_rejects_unexpected_prediction_id(self):
        with tempfile.TemporaryDirectory() as folder:
            labels_path = self.write(folder, "labels.csv", "CaseA,sqli,true,89\n")
            predictions_path = self.write(
                folder, "predictions.csv",
                "test_id,category,detected,status\nCaseX,sqli,true,ok\n",
            )
            labels = read_labels(labels_path)
            with self.assertRaisesRegex(ValueError, "unknown test ID"):
                read_predictions(predictions_path, labels)

    def test_rejects_category_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            labels_path = self.write(folder, "labels.csv", "CaseA,sqli,true,89\n")
            predictions_path = self.write(
                folder, "predictions.csv",
                "test_id,category,detected,status\nCaseA,pathtraver,true,ok\n",
            )
            labels = read_labels(labels_path)
            with self.assertRaisesRegex(ValueError, "category mismatch"):
                read_predictions(predictions_path, labels)


if __name__ == "__main__":
    unittest.main()
