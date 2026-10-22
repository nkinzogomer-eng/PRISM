"""External SCFuzzBench readiness checks are not vulnerability discovery."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.d23_external_gate import (
    PINNED_TARGET, PINNED_TARGET_COMMIT, validate,
)


class D23ExternalGroundTruthGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.catalog=root/"targets.json"
        self.labels=root/"known_bugs.json"
        self.source=root/"OUSD.sol"
        self.source.write_text("contract OUSD { uint256 public totalSupply; }\n",encoding="utf-8")
        self.catalog.write_text(json.dumps({
            "schema_version":1,
            "targets":[{"id":PINNED_TARGET,
                        "repo":"https://github.com/scfuzzbench/origin-dollar-scfuzzbench",
                        "commit":PINNED_TARGET_COMMIT}]
        }))
        self.labels.write_text(json.dumps({
            "schema_version":1,
            "targets":[{"target_id":PINNED_TARGET,"target_commit":PINNED_TARGET_COMMIT,
                        "known_bugs":[{"id":"bug-a","evidence":[{"url":"reference"}],
                                       "aliases":[{"event":"testA"}]}],
                        "canaries":[{"id":"assertion-canary"}]}]
        }))

    def report(self):
        return validate(self.catalog,self.labels,self.source)

    def test_real_bug_distinguished_from_canary(self):
        r=self.report()
        self.assertEqual(r["documented_root_causes"],1)
        self.assertEqual(r["health_canaries_excluded"],1)
        self.assertEqual(r["detection_metric"],"NOT_EVALUATED")

    def test_benchmark_commit_drift_rejected(self):
        data=json.loads(self.labels.read_text())
        data["targets"][0]["target_commit"]="f"*40
        self.labels.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"drift"):
            self.report()

    def test_canary_collision_refused(self):
        data=json.loads(self.labels.read_text())
        data["targets"][0]["known_bugs"][0]["id"]="assertion-canary"
        self.labels.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"canary"):
            self.report()

    def test_missing_ground_truth_refused(self):
        data=json.loads(self.labels.read_text())
        data["targets"][0]["known_bugs"]=[]
        self.labels.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"no validated"):
            self.report()

    def test_source_missing_fails_safe(self):
        self.source.unlink()
        with self.assertRaisesRegex(ValueError,"missing"):
            self.report()

    def test_unsubstantiated_label_refused(self):
        data=json.loads(self.labels.read_text())
        data["targets"][0]["known_bugs"][0]["evidence"]=[]
        self.labels.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"unsubstantiated"):
            self.report()


if __name__=="__main__":
    unittest.main()
