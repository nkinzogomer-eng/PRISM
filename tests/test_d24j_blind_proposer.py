"""Counterexamples and metamorphic checks for label-free DeFi suggestions."""
import unittest

from prism.defi_blind_proposer import propose_relations


VAULT = '''
pragma solidity ^0.8.0;
contract V {
    function quote(uint256 x) public pure returns (uint256) { return x; }
    function previewMove(uint256 x) public pure returns (uint256) { return x; }
    function move(uint256 x) external returns (uint256) { return x; }
    function convertToGold(uint256 x) public pure returns (uint256) { return x; }
    function convertToSilver(uint256 x) public pure returns (uint256) { return x; }
}
'''

PAIR = '''
pragma solidity ^0.8.0;
contract P {
    uint256 private reserve;
    function getReserve() external view returns (uint256) { return reserve; }
    function _updateLedger(uint256 amount) internal { reserve = amount; }
    function rebalance(uint256 amount) external { _updateLedger(amount); }
    function unrelated(uint256 amount) external returns (uint256) { return amount; }
}
'''


class BlindRelationalCandidates(unittest.TestCase):
    def test_no_known_vulnerability_family_or_labels_needed(self):
        out=propose_relations(VAULT)
        groups={c["family"] for c in out["candidates"]}
        self.assertEqual(groups,{"PREVIEW_TRANSITION_RELATION","ROUND_TRIP_NONEXPANSION"})
        self.assertEqual(len(out["candidates"]),3)
        self.assertEqual(out["confirmed_vulnerabilities"],0)
        self.assertEqual(out["native_evm_traces_observed"],0)
        self.assertTrue(all(c["status"]=="UNVERIFIED_REQUIRES_INDEPENDENT_EVM"
                            for c in out["candidates"]))

    def test_semantic_labels_are_not_used_for_read_after_write(self):
        out=propose_relations(PAIR)
        candidates=out["candidates"]
        self.assertEqual(len(candidates),1)
        self.assertEqual(candidates[0]["family"],"READ_AFTER_WRITE_RECONCILIATION")
        self.assertEqual(candidates[0]["operations"],
                         ["rebalance","_updateLedger","getReserve"])
        self.assertEqual(candidates[0]["source_signals"],["reserve"])

    def test_comment_only_signals_cannot_generate_candidates(self):
        source='''
        pragma solidity ^0.8.0;
        contract M {
            /* function previewMove() {} function move() {} */
            string public marker = "function convertToA() {}";
            function noTransitions() external pure returns (bool) { return true; }
        }
        '''
        self.assertEqual(propose_relations(source)["candidates"],[])
        self.assertFalse(propose_relations(source)["no_candidates_means_safe"])

    def test_budget_keeps_remaining_work_explicitly_unknown(self):
        x=propose_relations(VAULT,max_candidates=1)
        self.assertEqual(len(x["candidates"]),1)
        self.assertEqual(x["generated_before_budget"],3)
        self.assertEqual(x["omitted_for_budget"],2)

    def test_negative_guard_of_unrelated_reader_without_shared_state(self):
        source=PAIR.replace("return reserve;","return 1;")
        self.assertEqual(propose_relations(source)["candidates"],[])

    def test_syntactic_ambiguity_fails_closed(self):
        source='''contract X { function f(uint x) public {} function f(address x) public {} }'''
        with self.assertRaisesRegex(ValueError,"overloaded"):
            propose_relations(source)
        with self.assertRaisesRegex(ValueError,"candidate budget"):
            propose_relations(VAULT,max_candidates=0)

    def test_rename_preserves_structure_and_hypothesis_count(self):
        alternative=PAIR.replace("reserve","tickets").replace("Reserve","Tickets").replace(
            "rebalance","reconcile")
        x=propose_relations(alternative)
        self.assertEqual(len(x["candidates"]),1)
        self.assertEqual(x["candidates"][0]["source_signals"],["tickets"])


if __name__ == "__main__":
    unittest.main()
