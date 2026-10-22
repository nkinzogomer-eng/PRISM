"""D2.3 falsification tests: identical ABI cannot identify behavior.

These tests intentionally distinguish the *selection of candidate properties*
from any claim to know which deployment variant violates them. Information
theory: given identical ABI bytes for two configurations with different
behavior, no ABI-only deterministic classifier can assign opposite labels.
"""
import copy
import unittest

from prism.defi_property_compiler import freeze_input
def complete():
    def abi(*signatures):
        out = []
        for signature in signatures:
            name, arguments = signature.split("(")
            args = arguments[:-1].split(",") if arguments[:-1] else []
            out.append({"type": "function", "name": name,
                        "inputs": [{"type": item, "name": f"x{i}"}
                                   for i,item in enumerate(args)],
                        "outputs": []})
        return out
    return {
        "oracle": abi("owner()", "price()", "update(uint256)"),
        "lender": abi("borrow(uint256)", "debt(address)", "deposit(uint256)",
                      "limit(address)", "locked(address)", "withdraw(uint256)",
                      "loanAsset()", "repay(uint256)"),
        "asset": abi("balanceOf(address)", "transferFrom(address,address,uint256)")
    }


class D23IndistinguishabilityTests(unittest.TestCase):
    def test_same_abi_cannot_determine_vulnerability_configuration(self):
        compiled = freeze_input(complete())
        public_surface_by_variant = {
            "safe": copy.deepcopy(complete()),
            "oracle_bug": copy.deepcopy(complete()),
            "withdraw_bug": copy.deepcopy(complete()),
            "repay_bug": copy.deepcopy(complete()),
        }
        records = {key: freeze_input(value) for key, value in public_surface_by_variant.items()}
        self.assertEqual(len({r["abi_bundle_sha256"] for r in records.values()}), 1)
        self.assertEqual(len({r["compiled_hypotheses_sha256"] for r in records.values()}), 1)
        self.assertEqual(records["safe"], compiled)
        self.assertEqual(len(compiled["hypotheses"]), 3)
        for item in compiled["hypotheses"]:
            self.assertEqual(item["decision"], "CANDIDATE_REQUIRES_DYNAMIC_VERIFICATION")

    def test_config_metadata_is_not_hidden_ground_truth(self):
        # The publicly accessible deployment manifest contains booleans which
        # expose injected mechanism controls. Its use destroys blind-holdout
        # status, even when an explicit vulnerability label is absent.
        from scripts.d23_generate_probes import _validate_variations
        manifest = {
            "schema": "prism-d23-local-deployments-v1",
            "variations": [
                {"id": "c0", "oracle_owner_only": True,
                 "withdraw_debt_check": True, "repay_transfers_asset": True},
                {"id": "c1", "oracle_owner_only": False,
                 "withdraw_debt_check": True, "repay_transfers_asset": True},
                {"id": "c2", "oracle_owner_only": True,
                 "withdraw_debt_check": False, "repay_transfers_asset": True},
                {"id": "c3", "oracle_owner_only": True,
                 "withdraw_debt_check": True, "repay_transfers_asset": False},
            ],
        }
        variations = _validate_variations(manifest)
        signatures = [tuple(v[k] for k in ("oracle_owner_only", "withdraw_debt_check",
                                         "repay_transfers_asset")) for v in variations]
        self.assertEqual(len(set(signatures)), 4)
        self.assertEqual(sum(x.count(False) for x in signatures), 3)


if __name__ == "__main__":
    unittest.main()
