"""The external tool must be accounted for without manufactured accuracy."""
import unittest

from scripts.d24l_baseline import classify_slither_json


class ExternalReferenceTests(unittest.TestCase):
    def test_detection_and_no_detection_are_not_skipped(self):
        root={"success":True,"results":{"detectors":[
            {"check":"reentrancy-eth","description":"Reentrancy in D24LUnsafeBank.withdraw()"}
        ]}}
        r=classify_slither_json(root)
        self.assertEqual((r["unsafe_withdraw_detections"],r["fixed_withdraw_detections"]),(1,0))
        self.assertEqual(classify_slither_json({"success":True,"results":{"detectors":[]}})
                         ["detector_total"],0)

    def test_detector_scope_and_parse_gates(self):
        with self.assertRaisesRegex(ValueError,"successful"):
            classify_slither_json({"success":False,"results":{"detectors":[]}})
        with self.assertRaisesRegex(ValueError,"missing"):
            classify_slither_json({"success":True,"results":{}})
        with self.assertRaisesRegex(ValueError,"unexpected"):
            classify_slither_json({"success":True,"results":{"detectors":[
                {"check":"incorrect-solc","description":"irrelevant"}]}})


if __name__=="__main__":
    unittest.main()
