import unittest

from scripts.d24m_compiler_matrix import select_compiler


class CompilerMatrixTests(unittest.TestCase):
    def test_old_solmate_and_aave_prefer_pinned_824(self):
        x=select_compiler({"src/X.sol":b"pragma solidity ^0.8.10; contract X {}"})
        self.assertEqual(x["selected"],"0.8.24")

    def test_new_openzeppelin_831_picks_only_compatible_version(self):
        x=select_compiler({"contracts/X.sol":b"pragma solidity ^0.8.31; contract X {}",
                           "contracts/Y.sol":b"pragma solidity ^0.8.20; contract Y {}"})
        self.assertEqual(x["selected"],"0.8.31")

    def test_comment_and_string_cannot_falsify_pragmas(self):
        with self.assertRaisesRegex(ValueError,"PRAGMA"):
            select_compiler({"X.sol":b'// pragma solidity ^0.8.31;\n string constant x="pragma solidity ^0.8.24;";'})

    def test_conflicting_fixed_version_unknown_not_unsafe_fallback(self):
        with self.assertRaisesRegex(ValueError,"NO_PINNED"):
            select_compiler({"X.sol":b"pragma solidity =0.8.24;",
                             "Y.sol":b"pragma solidity =0.8.31;"})

    def test_bounded_grammar_and_comparison(self):
        with self.assertRaisesRegex(ValueError,"UNSUPPORTED"):
            select_compiler({"X.sol":b"pragma solidity >=0.8.30 <0.9.0;"})
        self.assertEqual(select_compiler({"X.sol":b"pragma solidity >=0.8.20 <0.8.32;"})
                         ["selected"],"0.8.24")


if __name__=="__main__":
    unittest.main()
