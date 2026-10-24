"""Adversarial, pure-Python tests for the limited OUSD source call frontier."""
import unittest
from scripts.d24c_structural_frontier import (
    ALLOWANCE_WITNESS, extract_functions, frontier, mask_noncode,
)

SAMPLE = """
contract Minimal {
    // function bogus() { allowances[msg.sender][to] = 1; }
    function transferFrom(address _from, address _to, uint256 _value)
        external returns (bool) {
        uint256 userAllowance = allowances[_from][msg.sender];
        allowances[_from][msg.sender] = userAllowance - _value;
        _executeTransfer(_from, _to, _value);
        return true;
    }
    function _executeTransfer(address a, address b, uint x) internal {
        _adjustAccount(a, x);
    }
    function _adjustAccount(address a, uint x) internal { /* relevant */ }
    function approve(address to, uint x) external returns(bool) {
        allowances[msg.sender][to] = x;
        return true;
    }
    function allowance(address a, address b) external view returns(uint) {
        return allowances[a][b];
    }
    function irrelevant() external pure returns (uint) {
        string memory fake = "function shouldNotParse() { }";
        return 3;
    }
}
"""

SPEC = {"ALLOWANCE_DEBIT": {"roots": ("transferFrom", "approve", "allowance"),
                            "symbols": ("allowances",)}}


class FrontierGuards(unittest.TestCase):
    def test_masks_comments_and_strings_without_offset_shift(self):
        clean = mask_noncode(SAMPLE)
        self.assertEqual(len(clean), len(SAMPLE))
        self.assertNotIn("function bogus", clean)
        self.assertNotIn("function shouldNotParse", clean)
        self.assertIn("function transferFrom", clean)

    def test_function_extraction_nested_and_comment_safe(self):
        fns = extract_functions(SAMPLE)
        self.assertEqual(len(fns), 6)
        self.assertNotIn("bogus", fns)
        self.assertNotIn("shouldNotParse", fns)

    def test_real_dependency_reachable_witness(self):
        result = frontier(SAMPLE, SPEC)
        goal = result["goals"]["ALLOWANCE_DEBIT"]
        self.assertEqual(goal["selected_functions"], 5)
        self.assertEqual(goal["all_functions"], 6)
        self.assertIn("_adjustAccount", goal["function_frontier"])
        self.assertNotIn("irrelevant", goal["function_frontier"])
        self.assertTrue(result["allowance_known_witness_in_frontier"])
        self.assertTrue(goal["full_source_remains_required_for_sound_security_claim"])

    def test_negative_control_missing_witness(self):
        mutated = SAMPLE.replace(ALLOWANCE_WITNESS,
                                 "allowances[_from][msg.sender] = userAllowance;")
        self.assertIsNone(frontier(mutated, SPEC)["allowance_known_witness_in_frontier"])

    def test_external_calls_remain_unknown(self):
        text = SAMPLE.replace("_adjustAccount(a, x);", "asset.transfer(a, x);")
        record = frontier(text, SPEC)["goals"]["ALLOWANCE_DEBIT"]
        self.assertTrue(record["unknown_semantics"])
        self.assertIn("transfer", record["unresolved_member_calls"])

    def test_fail_closed_overloaded_or_missing_root(self):
        with self.assertRaisesRegex(ValueError, "overloaded"):
            extract_functions(SAMPLE + "function irrelevant(uint256 a) public {}")
        with self.assertRaisesRegex(ValueError, "missing required"):
            frontier(SAMPLE, {"X": {"roots": ("noSuchEntry",),
                                     "symbols": ("allowances",)}})

    def test_fail_closed_missing_goal_symbol(self):
        with self.assertRaisesRegex(ValueError, "no observable"):
            frontier(SAMPLE, {"X": {"roots": ("irrelevant",),
                                     "symbols": ("allowances",)}})


if __name__ == "__main__":
    unittest.main()
