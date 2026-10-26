"""D2.4I: safe, deliberately narrow semantic checks for source-derived hypotheses.

This module INTERPRETS a tiny AST subset. It never imports, evals, executes,
or invokes the code being inspected, and it never invokes a command or logger.
A modeled flow is NOT a vulnerability, proof of exploitability, or zero-day.
Unknown syntax or effects must cause an abstention, not a safety claim.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256


class UnsupportedModel(Exception):
    pass


@dataclass(frozen=True)
class _State:
    env: dict[str, str]
    speculative: bool = False


def _function(tree: ast.Module, qualified_name: str):
    parts = qualified_name.split(".")
    parent = tree.body
    if len(parts) == 2:
        cls = next((n for n in tree.body if isinstance(n, ast.ClassDef)
                    and n.name == parts[0]), None)
        if cls is None:
            return None
        parent = cls.body
    if len(parts) > 2:
        return None
    return next((n for n in parent if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == parts[-1]), None)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + "." + node.attr
    raise UnsupportedModel("dynamic callee")


def _expression(node: ast.AST, env: dict[str, str]) -> str:
    if isinstance(node, ast.Constant) and type(node.value) in (str, int, float, bool):
        return str(node.value)
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _expression(node.left, env) + _expression(node.right, env)
    if isinstance(node, ast.JoinedStr):
        return "".join(_expression(x, env) for x in node.values)
    if isinstance(node, ast.FormattedValue) and node.format_spec is None:
        return _expression(node.value, env)
    if (isinstance(node, ast.Call) and _name(node.func) == "str"
            and len(node.args) == 1 and not node.keywords):
        return _expression(node.args[0], env)
    raise UnsupportedModel("value or data-flow semantics not modeled")


def _sink_argument(stmt: ast.stmt, family: str, line: int,
                   env: dict[str, str]) -> str | None:
    if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
        raise UnsupportedModel("statement or side effect not modeled")
    call = stmt.value
    if call.lineno != line:
        raise UnsupportedModel("unmodeled call in function")
    callee = _name(call.func)
    if family == "secret_logging":
        if callee not in {"logging.info", "logging.debug", "logging.warning",
                          "logging.error", "logging.critical", "logger.info",
                          "logger.debug", "logger.warning", "logger.error", "print"}:
            raise UnsupportedModel("not an approved logging sink")
    elif family == "untrusted_execution":
        if callee not in {"os.system", "eval", "exec", "subprocess.run",
                          "subprocess.Popen", "subprocess.call", "subprocess.check_output"}:
            raise UnsupportedModel("not an approved command/evaluator sink")
        if callee.startswith("subprocess.") and not any(
            k.arg == "shell" and isinstance(k.value, ast.Constant)
            and k.value.value is True for k in call.keywords
        ):
            raise UnsupportedModel("shell execution not established")
    else:
        raise UnsupportedModel("unsupported hypothesis family")
    if not call.args:
        raise UnsupportedModel("sink argument not present")
    if family == "secret_logging" and callee != "print" and len(call.args) > 1:
        # Logging's %-style deferred formatting, not a Python source call.
        # Refuse unsupported templates instead of manufacturing a witness.
        fmt = _expression(call.args[0], env)
        try:
            return fmt % tuple(_expression(x, env) for x in call.args[1:])
        except (TypeError, ValueError, KeyError) as exc:
            raise UnsupportedModel("unsupported logging formatting") from exc
    return _expression(call.args[0], env)


def model_source_flow(source: str, hypothesis: dict, *,
                      max_statements: int = 128, max_paths: int = 16) -> dict:
    """Evaluate an independently selected candidate under a tiny *model*.

    Candidate inference is separate; this method only follows safe syntactic
    forms, injecting a harmless canary into the named source parameter(s).
    Branches with unknown tests are BOTH explored, so their witnesses are only
    potentially feasible. The real program is NEVER run.
    """
    if not (1 <= max_statements <= 2048 and 1 <= max_paths <= 128):
        raise ValueError("invalid model budget")
    tree = ast.parse(source)
    fn = _function(tree, hypothesis["function"])
    family = hypothesis["family"]
    result = {
        "schema": "scm.prism.d24i.bounded.flow-model.v1",
        "source_sha256": sha256(source.encode()).hexdigest(),
        "hypothesis": hypothesis["identifier"],
        "family": family,
        "status": "INCOMPLETE_UNKNOWN",
        "modeled_witnesses": [],
        "evaluated_statements": 0,
        "modeled_paths": 0,
        "model_is_original_runtime": False,
        "vulnerabilities_confirmed": 0,
        "limitations": "Tiny straight-line AST subset; no imports, effects, aliases, dynamic dispatch or real execution",
    }
    if fn is None or isinstance(fn, ast.AsyncFunctionDef):
        result["reason"] = "MISSING_OR_ASYNC_FUNCTION"
        return result
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    if family == "secret_logging":
        sensitive = set(hypothesis["source_signals"][1:])
        params = [a.arg for a in args if a.arg in sensitive]
    elif family == "untrusted_execution":
        params = [a.arg for a in args if a.arg not in {"self", "cls"}]
    else:
        result["reason"] = "NOT_A_FLOW_FAMILY"
        return result
    if not params:
        result["reason"] = "NO_MODELED_INPUT"
        return result
    markers = {name: "PRISM_CANARY_" + sha256(name.encode()).hexdigest()[:12]
               for name in params}
    # Explicit stack and limits: interpretation cannot loop or recurse.
    stack = [(list(fn.body), _State(dict(markers)), 0)]
    all_paths_fully_modeled = True
    while stack:
        if result["modeled_paths"] + len(stack) > max_paths:
            all_paths_fully_modeled = False
            result["reason"] = "UNKNOWN_PATH_BUDGET"
            break
        stmts, state, offset = stack.pop()
        if not stmts:
            result["modeled_paths"] += 1
            continue
        stmt = stmts[0]
        rest = stmts[1:]
        result["evaluated_statements"] += 1
        if result["evaluated_statements"] > max_statements:
            all_paths_fully_modeled = False
            result["reason"] = "UNKNOWN_STATEMENT_BUDGET"
            break
        env = dict(state.env)
        try:
            if isinstance(stmt, ast.Pass):
                stack.append((rest, state, offset + 1))
            elif isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    _expression(stmt.value, env)
                result["modeled_paths"] += 1
            elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                env[stmt.targets[0].id] = _expression(stmt.value, env)
                stack.append((rest, _State(env, state.speculative), offset + 1))
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                env[stmt.target.id] = _expression(stmt.value, env)
                stack.append((rest, _State(env, state.speculative), offset + 1))
            elif isinstance(stmt, ast.If):
                if isinstance(stmt.test, ast.Constant) and type(stmt.test.value) is bool:
                    body = stmt.body if stmt.test.value else stmt.orelse
                    stack.append((list(body) + rest, state, offset + 1))
                else:
                    # Feasibility UNKNOWN, never assert this path occurs.
                    branch_state = _State(env, True)
                    stack.append((list(stmt.body) + rest, branch_state, offset + 1))
                    stack.append((list(stmt.orelse) + rest, branch_state, offset + 1))
            else:
                seen = _sink_argument(stmt, family, hypothesis["line"], env)
                flowing = [name for name, marker in markers.items() if marker in seen]
                if flowing:
                    result["modeled_witnesses"].append({
                        "source_parameters": sorted(flowing),
                        "sink_line": hypothesis["line"],
                        "path_feasibility": "UNKNOWN" if state.speculative else "STRAIGHT_LINE_MODEL",
                        "model_scope_only": True,
                    })
                stack.append((rest, state, offset + 1))
        except UnsupportedModel:
            all_paths_fully_modeled = False
            result["reason"] = "UNKNOWN_UNMODELED_CODE_OR_EFFECT"
            result["modeled_paths"] += 1
    if result["modeled_witnesses"]:
        result["status"] = "MODEL_POSSIBLE_FLOW_NOT_VULNERABILITY"
    elif all_paths_fully_modeled:
        result["status"] = "NO_MODELED_FLOW_NOT_SAFE"
    return result
