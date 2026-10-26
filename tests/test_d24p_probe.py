import unittest
from prism.d24p_probe import propose_trials

ABI=[{"type":"function","name":"deposit","inputs":[],"stateMutability":"payable"},
     {"type":"function","name":"withdraw","inputs":[],"stateMutability":"nonpayable"},
     {"type":"function","name":"balances","inputs":[{"type":"address"}],
      "stateMutability":"view"}]


class D24PAutoProbeTests(unittest.TestCase):
    def test_bounded_label_free_search(self):
        r=propose_trials(ABI)
        self.assertEqual(r["status"],"READY_FOR_NATIVE_EVM_SEARCH_NOT_VERIFIED")
        self.assertEqual(len(r["trials"]),18)
        self.assertEqual({x["callback_retry_budget"] for x in r["trials"]},{0,1,2})
        self.assertEqual(r["confirmed_vulnerabilities"],0)
        self.assertTrue(all(x["operations"][0]=="honest.deposit" for x in r["trials"]))

    def test_no_labels_or_addresses_are_inputs(self):
        changed=ABI+[{'type':'event','name':'AttackSuccessful','inputs':[]}]
        self.assertEqual(propose_trials(ABI)["trials"],propose_trials(changed)["trials"])

    def test_fail_closed_on_unsupported_and_limits(self):
        for data in ([],ABI[:1],[{"type":"function","name":"deposit",
                                  "inputs":[],"stateMutability":"nonpayable"}]+ABI[1:]):
            self.assertEqual(propose_trials(data)["status"],"UNSUPPORTED_ABI_NOT_SAFE")
        for budget in (0,49,True):
            with self.assertRaises(ValueError):propose_trials(ABI,max_trials=budget)

    def test_no_duplicate_runs_or_false_verdicts(self):
        a=propose_trials(ABI,max_trials=7)
        self.assertEqual(len(a["trials"]),7)
        self.assertEqual(a["trials_skipped_for_budget"],11)
        self.assertEqual(len({tuple(x[k] for k in ('honest_ether','stake_ether',
                      'callback_retry_budget')) for x in a['trials']}),7)


if __name__=='__main__':unittest.main()
