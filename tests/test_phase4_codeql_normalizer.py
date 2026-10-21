import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.normalize_codeql_sarif import main


class CodeQLSarifNormalizerTests(unittest.TestCase):
    def normalize_fixture(self, data, full=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sarif = root / 'r.json'
            sarif.write_text(json.dumps(data), encoding='utf-8')
            argv = ['normalizer', '--labels', 'unused', '--sarif', str(sarif),
                    '--predictions', str(root / 'p.csv'), '--summary', str(root / 's.json')]
            if full:
                argv.append('--verified-full-scan')
            with patch('scripts.normalize_codeql_sarif.load_labels', return_value={'BenchmarkTest00001': 'cat'}), patch('sys.argv', argv):
                main()
            with (root / 'p.csv').open() as handle:
                return list(csv.DictReader(handle))

    def test_empty_and_failed_sarif_rejected(self):
        for data in [{}, {'runs': [{'results': [], 'invocations': [{'executionSuccessful': False}]}]}]:
            with self.assertRaises(ValueError):
                self.normalize_fixture(data)

    def test_full_scan_requires_all_modules_extracted(self):
        with self.assertRaises(ValueError):
            self.normalize_fixture({'runs': [{'results': []}]}, full=True)
        data = {'runs': [{'results': [], 'invocations': [{'executionSuccessful': True,
            'toolExecutionNotifications': [{'descriptor': {'id': 'py/diagnostics/successfully-extracted-files'},
                'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'testcode/BenchmarkTest00001.py'}}}]}]}]}]}
        self.assertEqual(self.normalize_fixture(data, full=True)[0]['detected'], 'false')

    def test_maps_alert_to_case_and_emits_all_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            labels = root / "labels.csv"
            with labels.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["test name", "category", "expected"])
                for i in range(1, 1231):
                    writer.writerow([f"BenchmarkTest{i:05d}", "testcat", "true" if i == 1 else "false"])

            sarif = root / "results.sarif"
            sarif.write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{
                    "results": [{
                        "ruleId": "example-rule",
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "benchmark/testcode/BenchmarkTest00001.py"}
                            }
                        }]
                    }]
                }]
            }), encoding="utf-8")
            predictions = root / "predictions.csv"
            summary = root / "summary.json"
            with patch("sys.argv", [
                "normalize_codeql_sarif.py",
                "--labels", str(labels),
                "--sarif", str(sarif),
                "--predictions", str(predictions),
                "--summary", str(summary),
            ]):
                self.assertEqual(main(), 0)

            with predictions.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1230)
            by_id = {row["test_id"]: row for row in rows}
            self.assertEqual(by_id["BenchmarkTest00001"]["detected"], "true")
            self.assertEqual(by_id["BenchmarkTest00002"]["status"], "unsupported")
            self.assertEqual(json.loads(summary.read_text())["unique_cases_flagged"], 1)

    def test_unmapped_alert_is_counted_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            labels = root / "labels.csv"
            with labels.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(["test name", "category", "expected"])
                for i in range(1, 1231):
                    writer.writerow([f"BenchmarkTest{i:05d}", "testcat", "false"])
            sarif = root / "results.sarif"
            sarif.write_text(json.dumps({
                "runs": [{"results": [{"locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": "src/unrelated.py"}}
                }]}]}]
            }), encoding="utf-8")
            with patch("sys.argv", [
                "normalize_codeql_sarif.py", "--labels", str(labels),
                "--sarif", str(sarif), "--predictions", str(root / "p.csv"),
                "--summary", str(root / "s.json"),
            ]):
                self.assertEqual(main(), 0)
            summary = json.loads((root / "s.json").read_text())
            self.assertEqual(summary["unmapped_alerts"], 1)
            self.assertEqual(summary["unique_cases_flagged"], 0)


if __name__ == "__main__":
    unittest.main()
