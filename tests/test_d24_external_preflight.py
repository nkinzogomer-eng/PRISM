"""D2.4 fail-closed integrity, provenance, and training-leak adversarial tests."""
import json
from hashlib import sha1
from pathlib import Path
import tempfile
import unittest

from scripts.d24_external_preflight import acquire, blob_sha, comment_exposure, verify_manifest


class D24PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.payloads=[
            b"pragma solidity ^0.8.18; // Price manipulation vulnerability\ncontract X {}\n",
            b"pragma solidity ^0.8.18; /* MITIGATION: stop exploit */\ncontract Y {}\n",
            b"pragma solidity ^0.8.18; contract Z {}\n",
        ]
        self.rows=[
            {"id":f"external_{x}",
             "path":f"src/test/Fixture{x}.sol",
             "git_blob_sha1":blob_sha(b)}
            for x,b in enumerate(self.payloads)
        ]
        self.m={
            "schema":"prism-d24-external-corpus-v1",
            "status":"PUBLIC_DEVELOPMENT_ONLY",
            "commit":"0"*40,
            "source_repository":"https://github.com/SunWeb3Sec/DeFiVulnLabs",
            "cases":self.rows,
        }
        self.manifest=self.root/"manifest.json"
        self.write_manifest()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.m))

    def fetch(self,url):
        for entry,content in zip(self.rows,self.payloads):
            if url.endswith(entry["path"]):
                return content
        raise AssertionError("unexpected fetched URL")

    def test_all_pins_acquired_without_trusting_titles(self):
        d=acquire(self.manifest,self.root/"out",fetcher=self.fetch)
        self.assertEqual(len(d["files"]),3)
        self.assertFalse(d["corpus_is_blind"])
        self.assertEqual(d["status"],"INTEGRITY_VERIFIED_NOT_VULNERABILITY_EVALUATED")
        self.assertGreater(d["files"][0]["possible_label_comment_count"],0)
        self.assertEqual(d["files"][2]["possible_label_comment_count"],0)
        self.assertEqual(d["files"][0]["verified_reproduction"],"NOT_RUN")

    def test_git_blob_hash_checks_actual_payload(self):
        content=b"alpha"
        self.assertEqual(blob_sha(content),sha1(b"blob 5\0alpha").hexdigest())

    def test_refuses_source_changed_behind_correct_url(self):
        with self.assertRaisesRegex(ValueError,"integrity mismatch"):
            acquire(self.manifest,self.root/"out",fetcher=lambda url:b"tampered")

    def test_refuses_unpinned_branch(self):
        self.m["commit"]="main"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError,"unpinned"):
            acquire(self.manifest,self.root/"out",fetcher=self.fetch)

    def test_refuses_claim_of_blind_dataset(self):
        self.m["status"]="SEALED_HOLDOUT"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError,"blind label"):
            verify_manifest(self.m)

    def test_rejects_untrusted_path_traversal(self):
        self.m["cases"][0]["path"]="src/test/../../private.sol"
        with self.assertRaisesRegex(ValueError,"unsafe"):
            verify_manifest(self.m)

    def test_rejects_duplicate_names(self):
        self.m["cases"][0]["id"]=self.m["cases"][1]["id"]
        with self.assertRaisesRegex(ValueError,"repeated"):
            verify_manifest(self.m)

    def test_rejects_wrong_git_blob_hash(self):
        self.m["cases"][0]["git_blob_sha1"]="abc"
        with self.assertRaisesRegex(ValueError,"fingerprint"):
            verify_manifest(self.m)

    def test_rejects_unknown_repo(self):
        self.m["source_repository"]="https://example.org/unknown"
        with self.assertRaisesRegex(ValueError,"repository"):
            verify_manifest(self.m)

    def test_comment_labels_not_classified_as_findings(self):
        comments=comment_exposure("contract Safe {} // exploit vulnerability\n")
        self.assertEqual(comments["possible_label_comment_count"],1)
        self.assertNotIn("tp",comments)
        self.assertEqual(comments["leakage_risk"],"PUBLIC_LABELED_TRAINING_CORPUS")

    def test_no_proof_or_zero_day_claim_from_acquisition(self):
        d=acquire(self.manifest,self.root/"out",fetcher=self.fetch)
        self.assertTrue(all(x["verified_reproduction"]=="NOT_RUN" for x in d["files"]))
        self.assertTrue(all(x["property_or_vulnerability_class"]=="WITHHELD_FROM_DETECTOR"
                            for x in d["files"]))


if __name__=="__main__":
    unittest.main()
