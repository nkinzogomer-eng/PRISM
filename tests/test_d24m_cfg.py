"""Hard adversarial controls for branch-path ordering and UNKNOWN states."""
import unittest

from prism.d24m_cfg import cfg_hypotheses
from tests.test_d24l_typed_graph import compilation, call, write, ident


def branch(true, false, src="100:8:0"):
    return {"nodeType":"IfStatement","src":src,
            "condition":ident(999,"condition"),
            "trueBody":{"nodeType":"Block","statements":true},
            "falseBody":{"nodeType":"Block","statements":false}}


def base_function(data):
    return data["sources"]["src/A.sol"]["ast"]["nodes"][0]["nodes"][1]


def for_base(graph):
    return [x for x in graph["candidates"] if x["function_id"]==61]


class BranchGraphTests(unittest.TestCase):
    def test_exclusive_branches_are_never_falsely_joined(self):
        x=compilation()
        base_function(x)["body"]["statements"]=[branch([call()],[write()])]
        out=cfg_hypotheses(x)
        self.assertEqual(for_base(out),[])
        self.assertEqual(out["functions_with_completed_bounded_paths"],4)
        self.assertEqual(out["verified_zero_days"],0)

    def test_potentially_exploitable_branch_is_retained_with_evidence(self):
        x=compilation()
        base_function(x)["body"]["statements"]=[branch([call(),write()],[write(),call()])]
        out=cfg_hypotheses(x)
        found=for_base(out)
        self.assertEqual(len(found),1)
        self.assertEqual(found[0]["branches"],["T:100:8:0"])
        self.assertTrue(found[0]["not_a_security_verdict"])

    def test_return_prevents_fictitious_post_return_violation(self):
        x=compilation()
        base_function(x)["body"]["statements"]=[
            branch([call(),{"nodeType":"Return"}],[]),write()]
        self.assertEqual(for_base(cfg_hypotheses(x)),[])

    def test_unsupported_loop_abstains_without_silently_dropping_function(self):
        x=compilation()
        base_function(x)["body"]["statements"]=[
            {"nodeType":"ForStatement","body":{"nodeType":"Block","statements":[call(),write()]}}]
        g=cfg_hypotheses(x)
        self.assertEqual(for_base(g),[])
        self.assertEqual(g["cfg_unsupported_functions"],1)
        self.assertEqual(g["function_count"],4)

    def test_max_paths_budget_abstains_no_made_up_certainty(self):
        x=compilation()
        base_function(x)["body"]["statements"]=[branch([call(),write()],[])]
        out=cfg_hypotheses(x,max_paths_per_function=1)
        self.assertEqual(for_base(out),[])
        self.assertEqual(out["cfg_unsupported_functions"],1)

    def test_effectful_condition_cannot_be_dropped(self):
        x=compilation()
        stmt=branch([write()],[write()])
        stmt["condition"]=call()["expression"]
        base_function(x)["body"]["statements"]=[stmt]
        out=cfg_hypotheses(x)
        self.assertEqual(for_base(out),[])
        row=next(r for r in out["functions"] if r["function_id"]==61)
        self.assertEqual(row["reason"],"CALL_OR_WRITE_IN_CONDITION")


if __name__=="__main__":
    unittest.main()
