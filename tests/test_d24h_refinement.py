"""D2.4H extra tests for independent grammar-based replay and Solidity candidates."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from prism.cyber_path_grammar import run_generated_path_exploration, program_independent_path_grammar
from prism.cyber_solidity_hypotheses import compile_solidity_hypotheses

STARLETTE_UNSAFE = """
import os
class StaticFiles:
    def lookup_path(self, path):
        for directory in self.all_directories:
            joined_path = os.path.join(directory, path)
            full_path = os.path.realpath(joined_path)
            directory = os.path.realpath(directory)
            if os.path.commonprefix([full_path, directory]) != directory:
                continue
            try:
                return full_path, os.stat(full_path)
            except (FileNotFoundError, NotADirectoryError):
                continue
        return "", None
"""
STARLETTE_SAFE = STARLETTE_UNSAFE.replace("os.path.commonprefix","os.path.commonpath")

SOL = """
contract Asset {
    mapping(address => uint256) internal balances;
    function transferFrom(address a, address b, uint amount) external {
        balances[a] -= amount;
        balances[b] += amount;
    }
    function admin(address user) external onlyOwner { user.call(""); }
    function unrelated() external pure returns(uint) {return 1;}
}
"""


class MetamorphicPathCases(unittest.TestCase):
    def check(self, code, limit=30):
        with TemporaryDirectory() as temp:
            p=Path(temp)/"source.py"
            p.write_text(code)
            return run_generated_path_exploration(p,max_probes=limit)

    def test_grammar_not_tied_to_original_project_or_cve(self):
        items=program_independent_path_grammar("researchroot")
        self.assertGreaterEqual(len(items),12)
        self.assertIn("../researchroot2.txt",[x.relative_input for x in items])
        self.assertTrue(all("CVE" not in x.rationale for x in items))

    def test_unsafe_source_detects_without_historical_bug_label(self):
        r=self.check(STARLETTE_UNSAFE)
        self.assertEqual(r["status"],"LOCAL_PROPERTY_WITNESS")
        self.assertTrue(any(x["family"]=="name_relation" for x in r["violations"]))
        self.assertTrue(all(x["observed"]!=x["expected"] for x in r["violations"]))
        self.assertFalse(r["new_unknown_vulnerability_confirmed"])

    def test_same_grammar_has_no_witness_on_patched_pattern(self):
        r=self.check(STARLETTE_SAFE)
        self.assertEqual(r["status"],"NO_WITNESS_NOT_SAFE")
        self.assertEqual(len(r["violations"]),0)
        self.assertFalse(r["not_exhaustive"] is False)

    def test_insufficient_budget_is_not_safe(self):
        r=self.check(STARLETTE_UNSAFE,limit=4)
        self.assertEqual(r["status"],"INCOMPLETE_UNKNOWN")
        self.assertEqual(r["budget"]["used_probes"],4)
        self.assertGreater(len(r["unexecuted_candidates"]),0)


class SolidityDiscoveryCandidates(unittest.TestCase):
    def test_solidity_three_property_families_without_known_bug(self):
        r=compile_solidity_hypotheses(SOL)
        self.assertGreaterEqual(r["families"]["asset_conservation"],1)
        self.assertGreaterEqual(r["families"]["authorization_boundary"],1)
        self.assertGreaterEqual(r["families"]["external_call_state_consistency"],1)
        self.assertEqual(r["independent_vulnerability_witnesses"],0)
        self.assertFalse(r["complete_semantics"])

    def test_unrelated_contract_no_false_violations(self):
        r=compile_solidity_hypotheses("contract C { function irrelevant() public pure returns(uint){ return 2; } }")
        self.assertEqual(r["discovered_novel_vulnerabilities"],0)
        self.assertEqual(len(r["hypotheses"]),0)


if __name__=="__main__":
    unittest.main()
