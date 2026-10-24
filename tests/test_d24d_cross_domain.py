"""Cross-domain regressions: paired reachability + conservative fail-closed behavior."""
from dataclasses import dataclass, replace
from itertools import product
import unittest

from prism.cyber_kernel import Domain, Effect, audit_effects, dependency_frontier, search, verify_trace
from prism.cyber_workloads import auth_case, input_case


class KernelTests(unittest.TestCase):
    def test_auth_finite_reachability_and_safe_negative(self):
        for seed in range(5):
            for vulnerable in (True, False):
                case = auth_case(vulnerable=vulnerable, seed=seed)
                rows = [search(case, mode=mode, depth=4)
                        for mode in ("full", "slice", "quotient")]
                self.assertEqual([x.found for x in rows], [vulnerable] * 3)
                self.assertTrue(all(x.verdict != "UNKNOWN_BUDGET" for x in rows))
                for x in rows:
                    if x.found:
                        self.assertTrue(verify_trace(case, x.plan))
                    else:
                        self.assertEqual(x.verdict, "NOT_FOUND_IN_FINITE_MODEL")
                self.assertLess(rows[2].attempted, rows[0].attempted)

    def test_untrusted_input_finite_reachability(self):
        for seed in range(5):
            for vulnerable in (True, False):
                case = input_case(vulnerable=vulnerable, seed=seed)
                rows = [search(case, mode=m, depth=5)
                        for m in ("full", "slice", "quotient")]
                self.assertEqual([r.found for r in rows], [vulnerable] * 3)
                self.assertTrue(all(r.verdict != "UNKNOWN_BUDGET" for r in rows))

    def test_quotient_preserves_independent_reference_on_small_bounded_case(self):
        d = auth_case(vulnerable=True, seed=2)
        witness = None
        for n in range(4):
            for seq in product(d.actions, repeat=n):
                if verify_trace(d, seq):
                    witness = seq
                    break
            if witness is not None:
                break
        self.assertIsNotNone(witness)
        self.assertTrue(search(d, mode="quotient", depth=3).found)

    def test_unknown_not_silently_safe_when_budget_hit(self):
        d = input_case(vulnerable=True, seed=3)
        v = search(d, mode="full", depth=5, max_expanded=1)
        self.assertEqual(v.verdict, "UNKNOWN_BUDGET")
        self.assertFalse(v.found)

    def test_detect_missing_effect_write(self):
        d = auth_case(vulnerable=True, seed=3)
        e = dict(d.effects)
        e["sign_in"] = Effect(e["sign_in"].reads, frozenset({"theme"}))
        with self.assertRaisesRegex(ValueError, "undeclared effects"):
            audit_effects(replace(d, effects=e))

    def test_missing_effect_or_opaque_domain_fails_closed(self):
        d = input_case(vulnerable=True, seed=1)
        with self.assertRaisesRegex(ValueError, "missing effect"):
            dependency_frontier(replace(d, effects={"receive": d.effects["receive"]}))
        with self.assertRaisesRegex(ValueError, "dataclass"):
            search(replace(d, start=object()), mode="quotient")

    def test_dynamic_write_audit_does_not_claim_complete_reads(self):
        d = input_case(vulnerable=True, seed=1)
        witness = audit_effects(d, depth=3)
        self.assertGreater(witness["transitions_audited"], 0)
        self.assertFalse(witness["read_set_proved"])
        self.assertTrue(witness["audit_truncated"])
        self.assertFalse(witness["write_set_exhaustively_proved"])

    def test_unsupported_metadata_can_break_reduction_not_proven_sound(self):
        @dataclass(frozen=True)
        class S:
            dependency: bool = False
            exploit: bool = False

        def step(s, a):
            if a[0] == "set_dependency":
                return replace(s, dependency=True)
            if a[0] == "exploit" and s.dependency:
                return replace(s, exploit=True)
            return None

        domain = Domain("counterexample", "misdeclared_reads", S(),
                        (("set_dependency", 0), ("exploit", 0)),
                        {"set_dependency": Effect(frozenset(), frozenset({"dependency"})),
                         "exploit": Effect(frozenset({"exploit"}), frozenset({"exploit"}))},
                        frozenset({"exploit"}), step, lambda s: s.exploit)
        self.assertTrue(search(domain, mode="full", depth=2).found)
        self.assertFalse(search(domain, mode="quotient", depth=2).found)
        self.assertFalse(audit_effects(domain)["read_set_proved"])


if __name__ == "__main__":
    unittest.main()
