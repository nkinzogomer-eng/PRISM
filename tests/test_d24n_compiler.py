import unittest

from scripts.d24n_compiler_matrix import choose,permits


class SemverSafeResolverTests(unittest.TestCase):
    def test_cross_major_lower_bound_is_well_formed(self):
        self.assertTrue(permits(">=0.4.22 <0.9.0","0.8.33"))
        self.assertTrue(permits("^0.8.31","0.8.33"))
        self.assertFalse(permits("^0.8.31","0.8.24"))

    def test_caret_zero_minor_is_restrictive(self):
        self.assertFalse(permits("^0.7.0","0.8.24"))
        self.assertTrue(permits("^0.8.0","0.8.33"))
        self.assertFalse(permits("^0.8.34","0.8.33"))

    def test_disjunction_uses_all_bounded_clauses(self):
        self.assertTrue(permits("^0.7.0 || ^0.8.31","0.8.33"))
        with self.assertRaisesRegex(ValueError,"UNRECOGNIZED"):
            permits("^0.8.0 || malicious", "0.8.24")

    def test_native_pragma_closure_compiler_selected(self):
        selected=choose({"A.sol":b"pragma solidity ^0.8.31;",
                         "B.sol":b"pragma solidity >=0.4.22 <0.9.0;"})
        self.assertEqual(selected["compiler"],"0.8.33")
        self.assertTrue(selected["integrity_check_required"])

    def test_invalid_or_unsatisfied_closure_abstains(self):
        with self.assertRaisesRegex(ValueError,"NO_PINNED"):
            choose({"A.sol":b"pragma solidity =0.8.24;",
                    "B.sol":b"pragma solidity =0.8.33;"})
        with self.assertRaisesRegex(ValueError,"MULTIPLE"):
            choose({"A.sol":b"// pragma solidity ^0.8.0;"})


if __name__=="__main__":
    unittest.main()
