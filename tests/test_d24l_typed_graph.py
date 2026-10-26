"""Compiler-identified storage/call edges and adversarial abstention tests."""
import copy
import unittest

from prism.d24l_typed_graph import typed_graph


def ident(ref, name="balances"):
    return {"nodeType":"Identifier", "name":name, "referencedDeclaration":ref}


def statement(node):
    return {"nodeType":"ExpressionStatement", "expression":node}


def call(ref=62, external=True):
    return statement({"nodeType":"FunctionCall", "src":"10:15:0",
         "expression":{"nodeType":"MemberAccess", "memberName":"call" if external else "safe",
              "referencedDeclaration":ref, "typeDescriptions":{"typeString":"function (bytes memory) external" if external else "function () internal"},
              "expression":{"nodeType":"Identifier","name":"recipient"}},
         "arguments":[]})


def write(state_id=3):
    return statement({"nodeType":"Assignment","src":"30:10:0","operator":"=",
                      "leftHandSide":{"nodeType":"IndexAccess","baseExpression":ident(state_id)},
                      "rightHandSide":{"nodeType":"Literal","value":"0"}})


def unit(events, *, fid=61, owner=1, modifiers=None, name="withdraw"):
    return {"nodeType":"FunctionDefinition", "id":fid,"name":name,"kind":"function",
            "visibility":"public", "parameters":{"parameters":[
                {"typeDescriptions":{"typeString":"uint256"}}]},
            "modifiers":modifiers or [],
            "body":{"nodeType":"Block", "statements":events}}


def compilation(*, vulnerable=True):
    a=unit([call(),write()] if vulnerable else [write(),call()])
    base={"nodeType":"ContractDefinition", "id":1,"name":"Base",
          "linearizedBaseContracts":[1], "nodes":[
              {"nodeType":"VariableDeclaration","id":3,"name":"balances","stateVariable":True},
              a,
              unit([statement({"nodeType":"FunctionCall", "expression":ident(61,"withdraw"),
                              "arguments":[]})],fid=63,name="wrapper"),
              unit([],fid=64,name="withdraw"),
          ]}
    derived={"nodeType":"ContractDefinition", "id":2,"name":"Child",
             "linearizedBaseContracts":[2,1], "nodes":[
                 unit([call(),write()],fid=80,name="execute")
             ]}
    return {"sources":{"src/A.sol":{"ast":{"nodeType":"SourceUnit","nodes":[base]}},
                       "src/B.sol":{"ast":{"nodeType":"SourceUnit","nodes":[derived]}}},
            "errors":[]}


class TypedGraphTests(unittest.TestCase):
    def test_detects_ordered_external_call_before_storage_write(self):
        graph=typed_graph(compilation())
        self.assertEqual(graph["contract_count"],2)
        self.assertEqual(graph["state_variables"],1)
        self.assertEqual(len(graph["candidates"]),2)
        self.assertEqual({c["function_id"] for c in graph["candidates"]},{61,80})
        self.assertEqual(graph["real_vulnerabilities_confirmed"],0)
        self.assertEqual(graph["zero_days_confirmed"],0)
        self.assertEqual(graph["candidates"][0]["status"],"UNVERIFIED_CONDITIONAL_OBLIGATION")

    def test_safe_update_before_external_call_is_not_reported(self):
        graph=typed_graph(compilation(vulnerable=False))
        self.assertEqual({c["function_id"] for c in graph["candidates"]},{80})

    def test_internal_edges_resolve_by_compiler_id_despite_overloads(self):
        rows={r["function_id"]:r for r in typed_graph(compilation())["functions"]}
        self.assertEqual(rows[63]["typed_internal_callees"],[61])
        self.assertEqual(rows[64]["signature"],"withdraw(uint256)")

    def test_non_external_helper_is_not_reentrancy_proof(self):
        data=compilation()
        a=data["sources"]["src/A.sol"]["ast"]["nodes"][0]["nodes"][1]
        a["body"]["statements"][0]=call(external=False)
        self.assertEqual({c["function_id"] for c in typed_graph(data)["candidates"]},{80})

    def test_actual_solidity_payable_call_options_are_unwrapped(self):
        data=compilation()
        a=data["sources"]["src/A.sol"]["ast"]["nodes"][0]["nodes"][1]
        previous=a["body"]["statements"][0]["expression"]
        previous["expression"]={"nodeType":"FunctionCallOptions",
              "expression":previous["expression"],
              "names":["value"],"options":[ident(99,"amount")]}
        graph=typed_graph(data)
        self.assertEqual({c["function_id"] for c in graph["candidates"]},{61,80})

    def test_modifier_or_unhandled_branch_causes_function_abstention(self):
        data=compilation()
        a=data["sources"]["src/A.sol"]["ast"]["nodes"][0]["nodes"][1]
        a["modifiers"]=[{"modifierName":{"name":"nonReentrant"}}]
        self.assertIn("MODIFIER_EXECUTION_ORDER_UNRESOLVED", next(
            r for r in typed_graph(data)["functions"] if r["function_id"]==61)["unknowns"])
        self.assertEqual({c["function_id"] for c in typed_graph(data)["candidates"]},{80})
        a["modifiers"]=[]
        a["body"]["statements"].insert(1,{"nodeType":"IfStatement", "condition":ident(99)})
        self.assertEqual({c["function_id"] for c in typed_graph(data)["candidates"]},{80})

    def test_rejects_broken_ast_missing_base_and_compiler_error(self):
        data=compilation()
        data["sources"]["src/B.sol"]["ast"]["nodes"][0]["linearizedBaseContracts"]=[2,999]
        with self.assertRaisesRegex(ValueError,"inheritance"):
            typed_graph(data)
        data=compilation()
        data["errors"]=[{"severity":"error","message":"broken"}]
        with self.assertRaisesRegex(ValueError,"compiler"):
            typed_graph(data)
        with self.assertRaisesRegex(ValueError,"AST"):
            typed_graph({"sources":{"A.sol":{"ast":{}}}})

    def test_budget_and_unknown_are_explicit(self):
        data=compilation()
        graph=typed_graph(data,max_candidates=1)
        self.assertEqual(graph["candidate_count_before_budget"],2)
        self.assertEqual(graph["omitted_for_budget"],1)
        with self.assertRaisesRegex(ValueError,"budget"):
            typed_graph(data,max_candidates=0)

    def test_unmodified_copy_has_identical_output_digest(self):
        data=compilation()
        self.assertEqual(typed_graph(data),typed_graph(copy.deepcopy(data)))


if __name__ == "__main__":
    unittest.main()
