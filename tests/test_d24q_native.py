import json
from pathlib import Path
import tempfile
import unittest

from prism.d24q_asset_share_probe import propose_asset_share_trials
from scripts.d24q_solmate_native import ERC4626_ABI, _solidity, score


class D24QNativeTests(unittest.TestCase):
    def test_native_replay_generated_from_frozen_plan(self):
        plan=propose_asset_share_trials(ERC4626_ABI)
        code=_solidity(plan['candidates'])
        self.assertEqual(code.count('if (_attempt('),27)
        self.assertIn('control.previewRedeem(noDonationShares)>=victim',code)
        self.assertIn('investorResult > seed + donation',code)
        self.assertNotIn('expected_vulnerability',code)

    def test_native_oracle_fails_closed_on_missing_fabricated_proof(self):
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder)
            (d/'source_attestation.json').write_text(json.dumps({'source_attested':True}))
            with self.assertRaises(FileNotFoundError):score(d)
            (d/'forge-output.txt').write_text('Suite result: failed.\nD24Q_SOME_ECONOMIC_WITNESSES')
            with self.assertRaises(ValueError):score(d)
            (d/'forge-output.txt').write_text('Suite result: ok.\nD24Q_SOME_ECONOMIC_WITNESSES')
            with self.assertRaises(ValueError):score(d)
            (d/'forge-output.txt').write_text('Suite result: ok.\nD24Q_WITNESS_4\nD24Q_SOME_ECONOMIC_WITNESSES')
            self.assertEqual(score(d)['economic_transfer_witness_count'],1)
            (d/'forge-output.txt').write_text('Suite result: ok.\nD24Q_WITNESS_4\nD24Q_WITNESS_4\nD24Q_SOME_ECONOMIC_WITNESSES')
            with self.assertRaises(ValueError):score(d)


if __name__=='__main__':unittest.main()
