"""D2.4L: bounded, compiler-identified Solidity state/call evidence graph.

Inputs MUST be genuine solc Standard JSON outputs, or explicitly tagged
synthetic ASTs in unit tests. This is a structural HYPOTHESIS generator, not a
sound reentrancy analysis or a vulnerability detector. Neither modifier
expansion nor complete EVM control/data flow is currently implemented.
"""
from __future__ import annotations

from hashlib import sha256
import json


SCHEMA = "scm.prism.d24l.typed-state-evidence.v1"
LOW_LEVEL = {"call", "delegatecall", "callcode", "send", "transfer"}
STATE_MUTATORS = {"push", "pop"}


def _walk(root: object):
    """Iterative traversal with no unlimited user-controlled recursion."""
    queue = [root]
    traversed = 0
    while queue:
        current = queue.pop()
        traversed += 1
        if traversed > 100_000:
            raise ValueError("AST node/element budget exceeded")
        if isinstance(current, dict):
            if "nodeType" in current:
                yield current
            queue.extend(current.values())
        elif isinstance(current, list):
            queue.extend(current)


def _refs(node: object, state_ids: set[int]) -> set[int]:
    return {child["referencedDeclaration"] for child in _walk(node)
            if child.get("nodeType") in {"Identifier", "MemberAccess"}
            and type(child.get("referencedDeclaration")) is int
            and child["referencedDeclaration"] in state_ids}


def _external_call(node: dict) -> bool:
    expr = node.get("expression", {})
    if expr.get("nodeType") != "MemberAccess":
        return False
    member = expr.get("memberName", "")
    if member in LOW_LEVEL:
        # Some built-in transfer() calls are asset-safe for a given protocol,
        # but the semantic effects are unknown until independently observed.
        return True
    typestr = expr.get("typeDescriptions", {}).get("typeString", "")
    return " external" in typestr or typestr.startswith("function external")


def _call_record(node: dict) -> dict | None:
    expr = node.get("expression", {})
    if not isinstance(expr, dict):
        return None
    if expr.get("nodeType") not in {"MemberAccess", "Identifier"}:
        return None
    reference = expr.get("referencedDeclaration")
    if type(reference) is not int:
        reference = None
    return {"kind": "external_call" if _external_call(node) else "function_call",
            "callee_declaration_id": reference,
            "member": expr.get("memberName", expr.get("name", "")),
            "source_location": node.get("src", "")}


def _statement_events(stmt: dict, state_ids: set[int]) -> list[dict]:
    """Event order within a simple statement is approximate; marked below."""
    found = []
    for node in _walk(stmt):
        kind = node.get("nodeType")
        if kind == "FunctionCall":
            call = _call_record(node)
            if call is not None:
                found.append(call)
            expr = node.get("expression", {})
            if (expr.get("nodeType") == "MemberAccess" and
                    expr.get("memberName") in STATE_MUTATORS):
                ids = _refs(expr.get("expression", {}), state_ids)
                for ident in sorted(ids):
                    found.append({"kind": "state_write", "state_declaration_id": ident,
                                  "source_location": node.get("src", "")})
        elif kind == "Assignment":
            for ident in sorted(_refs(node.get("leftHandSide", {}), state_ids)):
                found.append({"kind": "state_write", "state_declaration_id": ident,
                              "source_location": node.get("src", "")})
        elif kind == "UnaryOperation" and node.get("operator") in {"++", "--", "delete"}:
            for ident in sorted(_refs(node.get("subExpression", {}), state_ids)):
                found.append({"kind": "state_write", "state_declaration_id": ident,
                              "source_location": node.get("src", "")})
    return found


def typed_graph(compiler_output: dict, *, max_candidates: int = 64) -> dict:
    """Extract evidence by declaration ID across sources, overloads, and bases.

    The small candidate rule recognizes direct *statement-ordered* external
    interaction followed by a persistent state write. It must never be used
    to declare an exploitable flaw without a separate execution witness.
    """
    if type(max_candidates) is not int or not 1 <= max_candidates <= 256:
        raise ValueError("invalid candidate budget")
    if type(compiler_output) is not dict or type(compiler_output.get("sources")) is not dict:
        raise ValueError("compiler Standard JSON sources/AST required")
    if any(e.get("severity") == "error" for e in compiler_output.get("errors", [])):
        raise ValueError("compiler reported an error; no valid typed graph")
    source_map = compiler_output["sources"]
    if len(source_map) > 128:
        raise ValueError("source count budget exceeded")
    contract_nodes = {}
    state_vars = {}
    function_nodes = {}
    for source_name, item in sorted(source_map.items()):
        ast = item.get("ast")
        if not isinstance(ast, dict) or ast.get("nodeType") != "SourceUnit":
            raise ValueError("missing genuine compiler AST")
        for contract in ast.get("nodes", []):
            if contract.get("nodeType") != "ContractDefinition":
                continue
            cid = contract.get("id")
            if type(cid) is not int or cid in contract_nodes:
                raise ValueError("invalid or duplicated compiler contract identifier")
            contract_nodes[cid] = {"source": source_name, "node": contract}
            for child in contract.get("nodes", []):
                node_id = child.get("id")
                if type(node_id) is not int:
                    continue
                if child.get("nodeType") == "VariableDeclaration" and child.get("stateVariable"):
                    if node_id in state_vars:
                        raise ValueError("duplicated state declaration")
                    state_vars[node_id] = {"owner_id": cid, "name": child.get("name", "")}
                if child.get("nodeType") == "FunctionDefinition":
                    if node_id in function_nodes:
                        raise ValueError("duplicated function declaration")
                    function_nodes[node_id] = {"owner_id": cid, "node": child}
    if not contract_nodes or not function_nodes:
        raise ValueError("missing typed contracts/functions")

    function_rows = []
    candidates = []
    for fid, row in sorted(function_nodes.items()):
        node = row["node"]
        cid = row["owner_id"]
        owner = contract_nodes[cid]
        contract = owner["node"]
        bases = contract.get("linearizedBaseContracts", [cid])
        if type(bases) is not list or any(base not in contract_nodes for base in bases):
            raise ValueError("unresolved inheritance declaration: fail closed")
        inherited_state = {sid for sid, var in state_vars.items() if var["owner_id"] in bases}
        name = node.get("name") or node.get("kind", "<unnamed>")
        params = node.get("parameters", {}).get("parameters", [])
        signature = name + "(" + ",".join(
            p.get("typeDescriptions", {}).get("typeString", "?") for p in params) + ")"
        body = node.get("body")
        events = []
        unsupported = []
        if body is None:
            unsupported.append("ABSTRACT_OR_INTERFACE_FUNCTION")
        elif body.get("nodeType") != "Block":
            unsupported.append("NON_BLOCK_BODY")
        else:
            for stmt in body.get("statements", []):
                if stmt.get("nodeType") not in {
                    "ExpressionStatement", "VariableDeclarationStatement", "Return", "EmitStatement"
                }:
                    unsupported.append("CONTROL_FLOW_OR_STATEMENT_UNSUPPORTED")
                    # This is a barrier: do not infer call/write order across it.
                    events.append({"kind": "barrier", "statement": stmt.get("nodeType")})
                else:
                    events.extend(_statement_events(stmt, inherited_state))
        if node.get("modifiers"):
            unsupported.append("MODIFIER_EXECUTION_ORDER_UNRESOLVED")
        # Reachable *internal* typed function IDs are edges, not name guesses.
        edges = sorted({ev["callee_declaration_id"] for ev in events
                        if ev["kind"] == "function_call"
                        and ev["callee_declaration_id"] in function_nodes})
        function_rows.append({
            "function_id": fid, "contract_id": cid,
            "contract": contract.get("name", ""), "source": owner["source"],
            "signature": signature, "visibility": node.get("visibility", ""),
            "base_contract_ids": bases, "typed_internal_callees": edges,
            "events": events, "unknowns": sorted(set(unsupported)),
        })
        if unsupported:
            continue
        seen_calls = []
        for ev in events:
            if ev["kind"] == "barrier":
                seen_calls = []
            elif ev["kind"] == "external_call":
                seen_calls.append(ev)
            elif ev["kind"] == "state_write" and seen_calls:
                candidates.append({
                    "identifier": f"typed_external_before_state:{fid}:{ev['state_declaration_id']}",
                    "family": "EXTERNAL_INTERACTION_BEFORE_STATE_UPDATE",
                    "function_id": fid, "source": owner["source"],
                    "contract": contract.get("name", ""), "signature": signature,
                    "external_interaction": seen_calls[-1], "write": ev,
                    "state": state_vars[ev["state_declaration_id"]],
                    "status": "UNVERIFIED_CONDITIONAL_OBLIGATION",
                    "requires": ["external_call_reachability_and_attacker_control",
                                 "EVM_reentrant_sequence_and_value_observation",
                                 "independent_fixed_control_and_conservation"],
                    "known_family_not_novelty": True,
                })
                break
    manifest = json.dumps(compiler_output, sort_keys=True, separators=(",", ":"))
    return {
        "schema": SCHEMA, "compiler_output_sha256": sha256(manifest.encode()).hexdigest(),
        "contract_count": len(contract_nodes), "function_count": len(function_rows),
        "state_variables": len(state_vars), "functions": function_rows,
        "candidates": candidates[:max_candidates],
        "candidate_count_before_budget": len(candidates),
        "omitted_for_budget": max(0, len(candidates)-max_candidates),
        "unsupported_function_count": sum(bool(row["unknowns"]) for row in function_rows),
        "real_vulnerabilities_confirmed": 0, "zero_days_confirmed": 0,
        "limitations": ["Some Solidity statement/control-flow shapes abstain",
                        "Modifiers and interprocedural effects are not expanded",
                        "No exploitable control or economic consequence inferred from an AST",
                        "A zero-candidate program is UNKNOWN, not secure"],
    }
