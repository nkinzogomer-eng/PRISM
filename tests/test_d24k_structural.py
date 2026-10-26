"""Overload, negative and metamorphic controls for D2.4K proposer."""
import unittest

from prism.d24k_structural import function_records,propose_value_influence


SOURCE='''
pragma solidity ^0.8.0;
contract X {
    uint public totalSupply;
    function totalAssets() public view returns(uint) { return 2; }
    function convertToShares(uint assets) public view returns(uint) {
        uint supply = totalSupply;
        return supply == 0 ? assets : assets.mulDivDown(supply,totalAssets());
    }
    function convertToAssets(uint shares) public view returns(uint) { return shares; }
    function previewDeposit(uint amount) public view returns(uint) { return convertToShares(amount); }
    function deposit(uint amount) public returns(uint) { return previewDeposit(amount); }
}
'''


class StructuralV2(unittest.TestCase):
    def test_dependent_asset_share_ratio_creates_conditional_not_confirmed_candidate(self):
        r=propose_value_influence(SOURCE)
        self.assertEqual(len(r["candidates"]),1)
        candidate=r["candidates"][0]
        self.assertEqual(candidate["family"],"EXTERNAL_ASSET_RATE_INFLUENCE")
        self.assertFalse(candidate["claim_of_new_vulnerability"])
        self.assertEqual(r["new_vulnerabilities_confirmed"],0)
        self.assertTrue(r["unknown_semantics"])

    def test_renaming_unrelated_function_does_not_change_hypothesis(self):
        a=propose_value_influence(SOURCE+"\ncontract Y { function doStuff() public {} }")
        b=propose_value_influence(SOURCE+"\ncontract Y { function alternative() public {} }")
        self.assertEqual(a["candidates"],b["candidates"])

    def test_overloaded_nonmatching_methods_are_not_whole_file_failure(self):
        src=SOURCE.replace("}\n",'''    function _isHealthy(uint x) public pure returns(bool) { return true; }
    function _isHealthy(address x) public pure returns(bool) { return true; }
}\n''',1)
        result=propose_value_influence(src)
        self.assertEqual(result["overloads_observed"],{"_isHealthy":2})
        self.assertEqual(len(result["candidates"]),1)

    def test_comments_cannot_invent_ratios(self):
        src='''contract Y { /* function convertToShares(uint x) {} */
                   function f() public { string memory s="totalSupply totalAssets"; } }'''
        self.assertEqual(propose_value_influence(src)["candidates"],[])

    def test_counterexamples_without_supply_ratio_or_deposit_quote(self):
        self.assertEqual(propose_value_influence(SOURCE.replace("mulDivDown","max"))["candidates"],[])
        self.assertEqual(propose_value_influence(SOURCE.replace("previewDeposit(amount); }",
            "amount; }"))["candidates"],[])

    def test_unsupported_code_and_budget_rejected(self):
        with self.assertRaisesRegex(ValueError,"source"):
            function_records("")
        with self.assertRaisesRegex(ValueError,"budget"):
            propose_value_influence(SOURCE,max_candidates=0)


if __name__=="__main__":
    unittest.main()
