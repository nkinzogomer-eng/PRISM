"""D2.4M bounded conditional execution-path evidence on real Solidity AST.

One-function intra-procedural if/else CFG enumerator with explicit UNKNOWNs.
It deliberately does not expand modifiers, calls, loops, aliasing or guards
in an SMT solver. A syntactic path is a *hypothesis*, never a confirmed flaw.
"""
from __future__ import annotations

from hashlib import sha256
import json

from prism.d24l_typed_graph import typed_graph, _statement_events


class UnsupportedPath(Exception):
    pass


def _branch_events(node: dict, state_ids: set[int]) -> list[dict]:
    return _statement_events({"nodeType":"ExpressionStatement","expression":node},state_ids)


def _sequence(node: dict | None, paths: list[dict], state_ids: set[int],
              *, cap: int, budget: list[int]) -> list[dict]:
    """Apply a Solidity statement to paths. Avoid merging exclusive branches."""
    if node is None:
        return paths
    budget[0]+=1
    if budget[0]>1000:
        raise UnsupportedPath("AST_CONTROL_FLOW_NODE_BUDGET")
    kind=node.get("nodeType")
    if kind in {"Block","UncheckedBlock"}:
        for stmt in node.get("statements",[]):
            paths=_sequence(stmt,paths,state_ids,cap=cap,budget=budget)
            if len(paths)>cap:
                raise UnsupportedPath("BRANCH_PATH_BUDGET")
        return paths
    if kind=="IfStatement":
        if _branch_events(node.get("condition",{}),state_ids):
            # A call in the guard itself may have side effects, but executing
            # it in a boolean expression has insufficient ordering semantics.
            raise UnsupportedPath("CALL_OR_WRITE_IN_CONDITION")
        left=[{**p,"pairs":p["pairs"][:],
               "decisions":p["decisions"]+["T:"+node.get("src","")]}
              for p in paths if not p["stopped"]]
        right=[{**p,"pairs":p["pairs"][:],
                "decisions":p["decisions"]+["F:"+node.get("src","")]}
               for p in paths if not p["stopped"]]
        done=[p for p in paths if p["stopped"]]
        if len(left)+len(right)+len(done)>cap:
            raise UnsupportedPath("BRANCH_PATH_BUDGET")
        yes=_sequence(node.get("trueBody"),left,state_ids,cap=cap,budget=budget)
        no=_sequence(node.get("falseBody"),right,state_ids,cap=cap,budget=budget)
        return done+yes+no
    if kind in {"ExpressionStatement","VariableDeclarationStatement","EmitStatement"}:
        occurrences=_statement_events(node,state_ids)
        for path in paths:
            if path["stopped"]:
                continue
            # Calls and writes in the SAME source statement are not ordered
            # by this abstraction. Only evidence from previous statements can
            # support a call-before-write obligation.
            prior=path["last_call"]
            for event in occurrences:
                if event["kind"]=="state_write" and prior is not None:
                    path["pairs"].append({"call":prior,"write":event,
                                         "decisions":path["decisions"][:]})
            calls=[event for event in occurrences if event["kind"]=="external_call"]
            if calls:
                path["last_call"]=calls[-1]
        return paths
    if kind=="Return":
        for path in paths:
            path["stopped"]=True
        return paths
    if kind in {"RevertStatement","Throw"}:
        for path in paths:
            path["stopped"]=True
        return paths
    raise UnsupportedPath("CONTROL_FLOW_UNSUPPORTED:"+str(kind))


def cfg_hypotheses(compiled: dict, *, max_candidates: int=64,
                   max_paths_per_function: int=64) -> dict:
    if type(max_candidates) is not int or not 1<=max_candidates<=256:
        raise ValueError("candidate budget invalid")
    if type(max_paths_per_function) is not int or not 1<=max_paths_per_function<=256:
        raise ValueError("path budget invalid")
    baseline=typed_graph(compiled,max_candidates=256)
    ast_contracts={}
    ast_functions={}
    state_owner={}
    for path,item in compiled["sources"].items():
        for contract in item["ast"].get("nodes",[]):
            if contract.get("nodeType")!="ContractDefinition":
                continue
            cid=contract["id"]
            ast_contracts[cid]=contract
            for member in contract.get("nodes",[]):
                if member.get("nodeType")=="VariableDeclaration" and member.get("stateVariable"):
                    state_owner[member["id"]]=cid
                elif member.get("nodeType")=="FunctionDefinition":
                    ast_functions[member["id"]]=member
    candidates=[]
    records=[]
    for row in baseline["functions"]:
        node=ast_functions[row["function_id"]]
        entry={"function_id":row["function_id"],"source":row["source"],
               "contract":row["contract"],"signature":row["signature"],
               "status":"UNKNOWN","reason":None,"paths_enumerated":0}
        body=node.get("body")
        if body is None:
            entry["reason"]="ABSTRACT_OR_INTERFACE_FUNCTION"
        elif node.get("modifiers"):
            entry["reason"]="UNEXPANDED_MODIFIER_ORDER"
        else:
            ids={sid for sid,owner in state_owner.items() if owner in row["base_contract_ids"]}
            try:
                explored=_sequence(body,[{"last_call":None,"pairs":[],
                       "decisions":[],"stopped":False}],ids,
                       cap=max_paths_per_function,budget=[0])
            except UnsupportedPath as exc:
                entry["reason"]=str(exc)
            else:
                entry["status"]="BOUNDED_CFG_ENUMERATION_COMPLETE"
                entry["paths_enumerated"]=len(explored)
                seen=set()
                for path in explored:
                    for pair in path["pairs"]:
                        key=(pair["call"]["source_location"],pair["write"]["source_location"],
                             tuple(pair["decisions"]))
                        if key in seen:
                            continue
                        seen.add(key)
                        candidates.append({
                            "id":"cfg-external-before-write:"+str(row["function_id"])+
                                 ":"+str(len(candidates)),
                            "source":row["source"],"contract":row["contract"],
                            "signature":row["signature"],"function_id":row["function_id"],
                            "family":"EXTERNAL_INTERACTION_BEFORE_STATE_UPDATE",
                            "branches":pair["decisions"],
                            "external_call":pair["call"],"state_write":pair["write"],
                            "status":"UNVERIFIED_CFG_PATH_HYPOTHESIS",
                            "not_a_security_verdict":True})
        records.append(entry)
    return {
        "schema":"scm.prism.d24m.bounded-typed-control-flow-v1",
        "parent_typed_graph_sha256":baseline["compiler_output_sha256"],
        "function_count":len(records),"contract_count":baseline["contract_count"],
        "baseline_unsupported_functions":baseline["unsupported_function_count"],
        "cfg_unsupported_functions":sum(r["status"]=="UNKNOWN" for r in records),
        "functions_with_completed_bounded_paths":sum(r["status"]=="BOUNDED_CFG_ENUMERATION_COMPLETE"
                                                    for r in records),
        "max_paths_per_function":max_paths_per_function,
        "functions":records,"candidates":candidates[:max_candidates],
        "candidate_count_before_budget":len(candidates),
        "omitted_for_budget":max(0,len(candidates)-max_candidates),
        "verified_vulnerabilities":0,"verified_zero_days":0,
        "limitations":["Condition feasibility unproven (syntactic CFG only)",
                       "Modifiers, loops, assembly, external calls and interprocedural effects not expanded",
                       "Unsupported functions remain UNKNOWN, never secure"],
    }
