import unittest

from prism.d24q_asset_share_probe import propose_asset_share_trials

PUBLIC_ABI=[{'type':'function','name':n,'inputs':[{'type':typ} for typ in args]}
     for n,args in [('deposit',['uint256','address']),('redeem',['uint256','address','address']),
                   ('balanceOf',['address']),('totalAssets',[]),('totalSupply',[])]]


class D24QAssetShareTests(unittest.TestCase):
    def test_budgeted_label_free_erc4626_action_grammar(self):
        p=propose_asset_share_trials(PUBLIC_ABI)
        self.assertEqual(p['status'],'UNVERIFIED_EVM_SEARCH_PENDING')
        self.assertEqual(len(p['candidates']),27)
        self.assertTrue(all('unmatched_asset_transfer' in x['actions'] for x in p['candidates']))
        self.assertEqual(p['verified_flaws'],0)

    def test_unsupported_incomplete_abi_is_unknown(self):
        self.assertEqual(propose_asset_share_trials(PUBLIC_ABI[:-1])['status'],
                         'UNSUPPORTED_ABI_UNKNOWN_NOT_SAFE')
        self.assertFalse(propose_asset_share_trials([])['candidates'])

    def test_limits_no_secret_labels(self):
        self.assertEqual(len(propose_asset_share_trials(PUBLIC_ABI,max_trials=3)['candidates']),3)
        for bound in (0,28,True):
            with self.assertRaises(ValueError):
                propose_asset_share_trials(PUBLIC_ABI,max_trials=bound)
        modified=PUBLIC_ABI+[{'type':'event','name':'BugExpected'}]
        self.assertEqual(propose_asset_share_trials(PUBLIC_ABI)['candidates'],
                         propose_asset_share_trials(modified)['candidates'])


if __name__=='__main__':unittest.main()
