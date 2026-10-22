"""Adversarial tests for the D1.0 vulnerability-level reference and scorer."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from benchmarks.d10_dev.specification import generate
from prism.discovery_oracle import Corpus
from prism.discovery_scoring import score
from scripts.d10_build import build


class D10ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="d10-oracle-")
        cls.root = Path(cls.temp.name) / "corpus"
        cls.manifest = build(cls.root)
        cls.corpus = Corpus(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_exactly_twelve_paired_positive_and_patched_fixtures(self):
        result = self.corpus.validate_all()
        self.assertEqual(result["case_count"], 24)
        self.assertEqual(result["positive_count"], 12)
        self.assertEqual(result["negative_count"], 12)
        for counts in result["family_counts"].values():
            self.assertEqual(counts, {"positive": 6, "negative": 6})

    def test_real_behavioral_witnesses_and_controls(self):
        for case_id, oracle in self.corpus.truth.items():
            for witness in oracle["witnesses"]:
                with self.subTest(case_id=case_id, witness=witness):
                    actual = self.corpus.observe(case_id, witness)
                    self.assertTrue(actual["benign_control_pass"])
                    self.assertEqual(actual["unauthorized_disclosure"],
                                     oracle["ground_truth"] == "vulnerable")

    def test_public_corpus_has_no_truth_label_metadata(self):
        public = (self.root / "public.json").read_text()
        doc = json.loads(public)
        for case in doc["cases"]:
            self.assertNotIn("ground_truth", case)
            self.assertNotIn("witnesses", case)
            self.assertNotIn("severity", case)
            self.assertNotIn("vulnerable", case["path"])
            self.assertNotIn("patched", case["path"])

    def test_rebuild_is_deterministic(self):
        with tempfile.TemporaryDirectory(prefix="d10-rebuild-") as path:
            second = build(Path(path) / "corpus")
            self.assertEqual(second["public_manifest_sha256"],
                             self.manifest["public_manifest_sha256"])
            self.assertEqual(second["source_specification_sha256"],
                             self.manifest["source_specification_sha256"])

    def test_corpus_change_refused_without_silent_relabel(self):
        with tempfile.TemporaryDirectory(prefix="d10-change-") as path:
            root = Path(path) / "corpus"
            build(root)
            source = root / "cases" / sorted(self.corpus.rows)[0].__add__(".py")
            source.write_bytes(source.read_bytes() + b"\n# unexpected modification\n")
            with self.assertRaisesRegex(ValueError, "integrity"):
                Corpus(root)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                build(root)

    def test_oracle_forgery_refused(self):
        with tempfile.TemporaryDirectory(prefix="d10-forged-") as path:
            root = Path(path) / "corpus"
            build(root)
            oracle_path = root / "oracle.json"
            oracle = json.loads(oracle_path.read_text())
            oracle["oracle"][0]["ground_truth"] = "patched" if (
                oracle["oracle"][0]["ground_truth"] == "vulnerable") else "vulnerable"
            oracle_path.write_text(json.dumps(oracle))
            with self.assertRaises(ValueError):
                Corpus(root)

    def test_public_hash_mismatch_refused(self):
        with tempfile.TemporaryDirectory(prefix="d10-public-") as path:
            root = Path(path) / "corpus"
            build(root)
            manifest_path = root / "public.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["cases"][0]["source_sha256"] = "0"*64
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "integrity"):
                Corpus(root)

    def test_unknown_case_rejected(self):
        with self.assertRaises(ValueError):
            self.corpus.observe("other", {"supplied": "' OR 1=1 -- "})

    def test_sql_payload_is_never_executed_outside_memory_db(self):
        for case_id in self.corpus.rows:
            if self.corpus.rows[case_id]["property_id"] != "SQLI_UNEXPECTED_OWNER":
                continue
            with self.subTest(case_id=case_id):
                outcome = self.corpus.observe(case_id, {"supplied": "' OR 1=1 -- "})
                self.assertTrue(outcome["benign_control_pass"])
                self.assertIsInstance(outcome["observed_owners"], list)

    def test_empty_predictions_are_zero_recall_not_fake_success(self):
        report = score(self.corpus, [])
        self.assertEqual((report["tp"], report["fp"], report["fn"], report["tn"]),
                         (0, 0, 12, 12))
        self.assertIsNone(report["precision"])
        self.assertEqual(report["recall"], 0.0)
        self.assertEqual(report["detector_resource_usage"], "NOT_MEASURED_BY_THIS_SCORER")

    def test_oracle_fed_perfect_submissions_only_validate_scoring(self):
        # This MUST NEVER be reported as scanner/detector effectiveness:
        # the predictions below deliberately leak oracle truth for test only.
        findings = [
            {
                "case_id": case_id,
                "property_id": self.corpus.rows[case_id]["property_id"],
                "witness": oracle["witnesses"][0],
            }
            for case_id, oracle in sorted(self.corpus.truth.items())
            if oracle["ground_truth"] == "vulnerable"
        ]
        report = score(self.corpus, findings)
        self.assertEqual((report["tp"], report["fp"], report["fn"]), (12, 0, 0))
        self.assertEqual(report["recall"], 1.0)
        self.assertEqual(report["precision"], 1.0)
        self.assertEqual(report["f1"], 1.0)

    def test_safe_fixture_with_wrong_evidence_counts_false_positive(self):
        case_id = next(i for i, val in sorted(self.corpus.truth.items())
                       if val["ground_truth"] == "patched")
        finding = {
            "case_id": case_id,
            "property_id": self.corpus.rows[case_id]["property_id"],
            "witness": self.corpus.truth[case_id]["witnesses"][0],
        }
        report = score(self.corpus, [finding])
        self.assertEqual((report["tp"], report["fp"], report["fn"]), (0, 1, 12))
        self.assertEqual(report["unsupported_proposals"], 1)
        self.assertEqual(report["tn"], 11)

    def test_bad_witness_never_counts_as_true_positive(self):
        case_id = next(i for i, val in sorted(self.corpus.truth.items())
                       if val["ground_truth"] == "vulnerable")
        report = score(self.corpus, [{
            "case_id": case_id,
            "property_id": self.corpus.rows[case_id]["property_id"],
            "witness": {},
        }])
        self.assertEqual((report["tp"], report["fp"], report["fn"]), (0, 1, 12))

    def test_duplicates_cannot_inflate_true_positives(self):
        case_id = next(i for i, val in sorted(self.corpus.truth.items())
                       if val["ground_truth"] == "vulnerable")
        row = {"case_id": case_id,
               "property_id": self.corpus.rows[case_id]["property_id"],
               "witness": self.corpus.truth[case_id]["witnesses"][0]}
        result = score(self.corpus, [row, dict(row)])
        self.assertEqual(result["tp"], 1)
        self.assertEqual(result["duplicate_proposals"], 1)
        self.assertEqual(result["fp"], 1)
        self.assertEqual(result["fn"], 11)

    def test_misclassified_case_never_counts_true_positive(self):
        case_id = next(i for i, val in sorted(self.corpus.truth.items())
                       if val["ground_truth"] == "vulnerable")
        wrong = "SQLI_UNEXPECTED_OWNER" if self.corpus.rows[case_id][
            "property_id"] == "BAC_CROSS_TENANT_READ" else "BAC_CROSS_TENANT_READ"
        report = score(self.corpus, [{
            "case_id": case_id,
            "property_id": wrong,
            "witness": self.corpus.truth[case_id]["witnesses"][0],
        }])
        self.assertEqual((report["tp"], report["fp"], report["fn"]), (0, 1, 12))

    def test_out_of_scope_case_hard_fails(self):
        with self.assertRaisesRegex(ValueError, "scope"):
            score(self.corpus, [{
                "case_id": "../../etc/passwd",
                "property_id": "SQLI_UNEXPECTED_OWNER", "witness": {},
            }])

    def test_excessive_proposals_hard_fail(self):
        with self.assertRaisesRegex(ValueError, "too many"):
            score(self.corpus, [{} for _ in range(501)])

    def test_independent_fixture_count(self):
        rows = generate()
        self.assertEqual(len(rows), 24)
        self.assertEqual(len({pub["source_sha256"] for pub, _, _ in rows}), 24)


if __name__ == "__main__":
    unittest.main()
