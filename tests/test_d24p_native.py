"""Native-scoring fail-closed controls, no fabricated EVM success."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts.d24p_blind_native import generate, grade, plan


class D24PNativeHarnessTests(unittest.TestCase):
    def test_deterministic_seed_and_sealed_labels(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            a,b=Path(first),Path(second)
            x=generate(a,seed=777)
            y=generate(b,seed=777)
            self.assertEqual(x['source_sha256'],y['source_sha256'])
            self.assertEqual(x['labels_sha256'],y['labels_sha256'])
            p=plan(a)
            self.assertEqual(p['cases'],21)
            self.assertEqual(p['plans_per_case'],18)
            self.assertFalse(p['scanner_received_ground_truth'])
            native=(a/'test'/'D24PBlindProbe.t.sol').read_text()
            self.assertIn('stillOwedHonest',native)
            self.assertIn('received > attacker * 1 ether',native)
            self.assertNotIn('expected_evm_witness',native)
            self.assertNotIn('template_private',native)
            self.assertNotIn('D24PInstance0()',native)
            self.assertEqual(sum(r['expected_evm_witness'] for r in
                    json.loads((a/'sealed_labels.json').read_text())),6)

    def test_variant_nonleak_and_fail_closed_missing_native(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            generate(p,seed=19)
            with self.assertRaises(FileNotFoundError):grade(p)
            (p/'forge-output.txt').write_text('Suite result: failed.\nD24P_WITNESS_0')
            with self.assertRaises(ValueError):grade(p)
            (p/'forge-output.txt').write_text('Suite result: ok.\nD24P_WITNESS_0')
            with self.assertRaises(ValueError):grade(p)

    def test_reject_bad_generator_budgets(self):
        with tempfile.TemporaryDirectory() as folder:
            for seed in (-1,2**64,True):
                with self.assertRaises(ValueError):generate(Path(folder),seed=seed)
            for cases in (0,8,36):
                with self.assertRaises(ValueError):generate(Path(folder),seed=10,cases=cases)


if __name__=='__main__':unittest.main()
