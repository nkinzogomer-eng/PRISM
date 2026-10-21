"""Goal-directed, model-free discovery of path traversal *candidates* (CWE-22).

This deliberately incomplete abstract interpreter works backward from a small
set of filesystem sinks and forward from untrusted HTTP request sources.
An output is never a verified vulnerability: unknown imports, guards, call
semantics and reachability stay explicit. External benchmarks are scored only
in the runner after predictions have been serialized.

This is a research proposal generator, NOT a replacement for a mature SAST
engine or proof of exploitable vulnerabilities.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class DiscoveryGoal:
    property_id: str = "CWE-22"
    target_recall: float = 0.80
    max_false_positive_rate: float = 0.10
    max_seconds_per_case: float = 5.0
    require_independent_confirmation: bool = True

    def __post_init__(self) -> None:
        if self.property_id != "CWE-22":
            raise ValueError("only CWE-22 is implemented in this experimental adapter")
        if not (0 <= self.target_recall <= 1 and
                0 <= self.max_false_positive_rate <= 1 and
                self.max_seconds_per_case > 0):
            raise ValueError("invalid goal bounds")


@dataclass(frozen=True)
class Flow:
    sources: frozenset[str] = frozenset()
    uncertainties: frozenset[str] = frozenset()

    def plus(self, other: "Flow") -> "Flow":
        return Flow(self.sources | other.sources,
                    self.uncertainties | other.uncertainties)

    def unknown(self, reason: str) -> "Flow":
        return Flow(self.sources, self.uncertainties | {reason})


EMPTY = Flow()


@dataclass(frozen=True)
class Candidate:
    filename: str
    function: str
    line: int
    sink: str
    sources: tuple[str, ...]
    uncertainties: tuple[str, ...]
    status: Literal["candidate", "unknown"]
    # A finding is NOT verified until an independent environment-level replay.
    verified: bool = False


@dataclass
class Analysis:
    goal: DiscoveryGoal
    filename: str
    candidates: list[Candidate] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    explored_sinks: int = 0

    def as_record(self) -> dict:
        return {
            "filename": self.filename,
            "goal": self.goal.property_id,
            "candidate_count": sum(x.status == "candidate" for x in self.candidates),
            "unknown_count": sum(x.status == "unknown" for x in self.candidates),
            "verified_count": 0,
            "explored_sinks": self.explored_sinks,
            "unresolved": sorted(set(self.unresolved)),
            "findings": [
                {"function": x.function, "line": x.line, "sink": x.sink,
                 "sources": list(x.sources),
                 "uncertainties": list(x.uncertainties),
                 "status": x.status,
                 "verified": False}
                for x in self.candidates
            ],
        }


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        p = dotted(node.value)
        return (p + "." + node.attr) if p else node.attr
    return ""


# SOURCE whitelist: explicit supported HTTP request entry points.
HTTP_COLLECTIONS = {
    "request.args", "request.form", "request.cookies", "request.values",
    "request.headers", "request.json", "request.files",
}
TRANSPARENT_SUFFIXES = {
    "str", "bytes", "pathlib.Path", "Path",
    "urllib.parse.unquote_plus", "urllib.parse.unquote", "unquote_plus",
    "os.path.join", "os.path.abspath", "os.path.normpath",
    "decode", "encode", "strip", "lstrip", "rstrip",
    "replace", "format", "resolve", "joinpath",
}
FILESYSTEM_METHODS = {
    "read_text", "read_bytes", "write_text", "write_bytes",
    "open", "exists", "is_file", "is_dir", "unlink",
}
FILESYSTEM_CALLS = {
    "open", "codecs.open", "io.open", "os.open",
    "os.path.exists", "os.path.isfile", "os.path.isdir",
}


def _const(node: ast.AST, env: dict[str, object]) -> object:
    """Small, non-executing, bounded evaluator for branch elimination."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id, _UNKN)
    if isinstance(node, ast.UnaryOp):
        v = _const(node.operand, env)
        if v is _UNKN:
            return _UNKN
        if isinstance(node.op, ast.Not):
            return not bool(v)
        if isinstance(node.op, ast.USub) and type(v) in (int, float):
            return -v
        return _UNKN
    if isinstance(node, ast.BinOp):
        a, b = _const(node.left, env), _const(node.right, env)
        if a is _UNKN or b is _UNKN:
            return _UNKN
        if type(a) in (int, float) and type(b) in (int, float):
            if isinstance(node.op, ast.Add):
                return a + b
            if isinstance(node.op, ast.Mult):
                return a * b
        if isinstance(node.op, ast.Add) and type(a) is type(b) is str:
            return a + b
        return _UNKN
    if isinstance(node, ast.Compare) and len(node.ops) == len(node.comparators) == 1:
        a, b = _const(node.left, env), _const(node.comparators[0], env)
        if a is _UNKN or b is _UNKN:
            return _UNKN
        try:
            if isinstance(node.ops[0], ast.In):
                return a in b
            if isinstance(node.ops[0], ast.NotIn):
                return a not in b
            if isinstance(node.ops[0], ast.Gt):
                return a > b
            if isinstance(node.ops[0], ast.Lt):
                return a < b
            if isinstance(node.ops[0], ast.Eq):
                return a == b
            if isinstance(node.ops[0], ast.NotEq):
                return a != b
        except (TypeError, ValueError):
            return _UNKN
    if isinstance(node, ast.BoolOp):
        values = [_const(v, env) for v in node.values]
        if isinstance(node.op, ast.And):
            if any(v is not _UNKN and not bool(v) for v in values):
                return False
            if all(v is not _UNKN for v in values):
                return all(values)
        if isinstance(node.op, ast.Or):
            if any(v is not _UNKN and bool(v) for v in values):
                return True
            if all(v is not _UNKN for v in values):
                return any(values)
    if isinstance(node, ast.IfExp):
        truth = _const(node.test, env)
        if truth is not _UNKN:
            return _const(node.body if truth else node.orelse, env)
    return _UNKN


_UNKN = object()


class _Analyzer:
    def __init__(self, goal: DiscoveryGoal, filename: str,
                 functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]):
        self.result = Analysis(goal, filename)
        self.functions = functions
        self._seen: set[tuple[str, int, str]] = set()

    def _emit(self, function: str, node: ast.Call, sink: str,
              flow: Flow, guard: bool) -> None:
        self.result.explored_sinks += 1
        if not flow.sources:
            if flow.uncertainties:
                self.result.unresolved.append(
                    f"{function}:{node.lineno}:{sink}: unknown input provenance")
            return
        if guard:
            flow = flow.unknown("unproven_path_guard")
        # A candidate is a *hypothesis*: a conditional branch alone does
        # not prevent triage, although it requires later reachability proof.
        # Unresolved transformations, containers and guards DO prevent
        # a high-confidence candidate and remain unknown.
        blocking = flow.uncertainties - {"unknown_branch", "bounded_slice", "request_collection_element"}
        state = "unknown" if blocking else "candidate"
        key = (function, node.lineno, sink)
        if key not in self._seen:
            self._seen.add(key)
            self.result.candidates.append(
                Candidate(self.result.filename, function, node.lineno, sink,
                          tuple(sorted(flow.sources)),
                          tuple(sorted(flow.uncertainties)), state)
            )

    def expression(self, node: ast.AST, env: dict[str, Flow],
                   constants: dict[str, object], func: str,
                   depth: int = 0) -> Flow:
        if isinstance(node, ast.Constant):
            return EMPTY
        if isinstance(node, ast.Name):
            return env.get(node.id, EMPTY)
        if isinstance(node, ast.Attribute):
            return self.expression(node.value, env, constants, func, depth)
        if isinstance(node, (ast.JoinedStr, ast.List, ast.Tuple, ast.Set)):
            result = EMPTY
            for child in node.values if isinstance(node, ast.JoinedStr) else node.elts:
                result = result.plus(self.expression(child, env, constants, func, depth))
            return result
        if isinstance(node, ast.FormattedValue):
            return self.expression(node.value, env, constants, func, depth)
        if isinstance(node, ast.Dict):
            result = EMPTY
            for value in node.values:
                result = result.plus(self.expression(value, env, constants, func, depth))
            return result.unknown("dictionary_key_not_tracked") if result.sources else result
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                idx = _const(node.slice, constants)
                if idx is not _UNKN:
                    key = "@map:" + node.value.id + ":" + repr(idx)
                    if key in env:
                        return env[key]
                    items = constants.get("@list:" + node.value.id)
                    if isinstance(items, list) and type(idx) is int:
                        if -len(items) <= idx < len(items):
                            return items[idx]
            flow = self.expression(node.value, env, constants, func, depth)
            if flow.sources and isinstance(node.slice, ast.Slice):
                # Fixed slicing remains a source-dependent candidate but the
                # precise surviving bytes require independent validation.
                return flow.unknown("bounded_slice")
            if flow.sources and isinstance(node.slice, ast.Constant) and type(node.slice.value) is int:
                # A request's getlist()[i] element is still user supplied.
                # Other aggregates stay unresolved unless modeled exactly.
                if isinstance(node.value, ast.Name) and any(
                    "request." in src and "getlist" in src for src in flow.sources
                ):
                    return flow.unknown("request_collection_element")
            return flow.unknown("unresolved_container_access") if flow.sources else flow
        if isinstance(node, ast.BinOp):
            return (self.expression(node.left, env, constants, func, depth)
                    .plus(self.expression(node.right, env, constants, func, depth)))
        if isinstance(node, ast.IfExp):
            truth = _const(node.test, constants)
            if truth is not _UNKN:
                return self.expression(node.body if truth else node.orelse,
                                       env, constants, func, depth)
            a = self.expression(node.body, env, constants, func, depth)
            b = self.expression(node.orelse, env, constants, func, depth)
            return a.plus(b).unknown("unknown_branch") if a != b else a
        if isinstance(node, ast.Call):
            path = dotted(node.func)
            # Precisely model a small subset of ordinary mutable containers.
            # Unknown keys or aliasing still invalidate these summaries.
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                owner, method = node.func.value.id, node.func.attr
                values = constants.get("@list:" + owner)
                if isinstance(values, list) and method == "append" and len(node.args) == 1:
                    values.append(self.expression(node.args[0], env, constants, func, depth))
                    return EMPTY
                if isinstance(values, list) and method == "pop":
                    idx = _const(node.args[0], constants) if node.args else -1
                    if type(idx) is int and -len(values) <= idx < len(values):
                        return values.pop(idx)
                    return Flow().unknown("unknown_pop_index")
                if method == "set" and len(node.args) == 3:
                    sect, key = _const(node.args[0], constants), _const(node.args[1], constants)
                    if sect is not _UNKN and key is not _UNKN:
                        value = self.expression(node.args[2], env, constants, func, depth)
                        env["@config:" + owner + ":" + repr((sect,key))] = value
                        return EMPTY
                if method == "get" and len(node.args) >= 2:
                    sect, key = _const(node.args[0], constants), _const(node.args[1], constants)
                    synthetic = "@config:" + owner + ":" + repr((sect,key))
                    if sect is not _UNKN and key is not _UNKN and synthetic in env:
                        return env[synthetic]
                if method == "get_form_parameter" and constants.get("@requestproxy:" + owner):
                    return Flow(frozenset({f"request_wrapper.get_form_parameter@{node.lineno}"}))
            if path == "helpers.separate_request.request_wrapper":
                return EMPTY
            if path in {"request.args.get", "request.form.get",
                        "request.cookies.get", "request.values.get",
                        "request.headers.get", "request.files.get",
                        "request.get_json", "input",
                        "helpers.utils.get_parameter", "get_parameter"}:
                return Flow(frozenset({f"{path}@{node.lineno}"}))
            if path.startswith("request.") and any(
                path.startswith(x + ".") for x in HTTP_COLLECTIONS
            ):
                return Flow(frozenset({f"{path}@{node.lineno}"}))
            value = EMPTY
            for arg in node.args:
                value = value.plus(self.expression(arg, env, constants, func, depth))
            for kw in node.keywords:
                value = value.plus(self.expression(kw.value, env, constants, func, depth))
            if isinstance(node.func, ast.Attribute):
                value = value.plus(
                    self.expression(node.func.value, env, constants, func, depth))
            if path in FILESYSTEM_CALLS or (
                isinstance(node.func, ast.Attribute) and
                node.func.attr in FILESYSTEM_METHODS
            ):
                self._emit(func, node, path or "<filesystem>", value, False)
            if path in self.functions and depth < 2:
                callee = self.functions[path]
                scoped_env = {arg.arg: (self.expression(v, env, constants, func, depth)
                                        if i < len(node.args) else EMPTY)
                              for i, arg in enumerate(callee.args.args)
                              for v in ([node.args[i]] if i < len(node.args) else [ast.Constant(None)])}
                ret = self._walk(callee.body, scoped_env, {}, path, depth + 1)
                return ret
            if value.sources and path not in TRANSPARENT_SUFFIXES and (
                not isinstance(node.func, ast.Attribute)
                or node.func.attr not in TRANSPARENT_SUFFIXES
            ) and path not in FILESYSTEM_CALLS and (
                not isinstance(node.func, ast.Attribute)
                or node.func.attr not in FILESYSTEM_METHODS
            ):
                return value.unknown("unmodeled_transform:" + (path or "dynamic_call"))
            return value
        if isinstance(node, ast.UnaryOp):
            return self.expression(node.operand, env, constants, func, depth)
        if isinstance(node, ast.Compare):
            result = self.expression(node.left, env, constants, func, depth)
            for comp in node.comparators:
                result = result.plus(self.expression(comp, env, constants, func, depth))
            return result
        # Unknown syntax with a possible input source: keep uncertainty.
        flow = EMPTY
        for child in ast.iter_child_nodes(node):
            flow = flow.plus(self.expression(child, env, constants, func, depth))
        return flow.unknown("unmodeled_expression") if flow.sources else flow

    def _walk(self, statements: list[ast.stmt], env: dict[str, Flow],
              constants: dict[str, object], func: str, depth: int = 0) -> Flow:
        returned = EMPTY
        for stmt in statements:
            if isinstance(stmt, (ast.Import, ast.ImportFrom,
                                 ast.Pass, ast.Global, ast.Nonlocal)):
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                expr = stmt.value
                if expr is None:
                    continue
                flow = self.expression(expr, env, constants, func, depth)
                value = _const(expr, constants)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        # Assignment replaces the container identity and must
                        # invalidate stale key/element summaries.
                        for existing in tuple(env):
                            if existing.startswith("@map:" + name + ":") or existing.startswith("@config:" + name + ":"):
                                del env[existing]
                        constants.pop("@list:" + name, None)
                        constants.pop("@requestproxy:" + name, None)
                        env[name] = flow
                        if value is _UNKN:
                            constants.pop(name, None)
                        else:
                            constants[name] = value
                        if isinstance(expr, ast.Dict):
                            for key_ast, val_ast in zip(expr.keys, expr.values):
                                key = _const(key_ast, constants) if key_ast else _UNKN
                                if key is not _UNKN:
                                    env["@map:" + name + ":" + repr(key)] = self.expression(
                                        val_ast, env, constants, func, depth)
                        elif isinstance(expr, ast.List):
                            constants["@list:" + name] = [
                                self.expression(x, env, constants, func, depth)
                                for x in expr.elts]
                        elif isinstance(expr, ast.Call) and dotted(expr.func) == "helpers.separate_request.request_wrapper":
                            constants["@requestproxy:" + name] = True
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        name = target.value.id
                        key = _const(target.slice, constants)
                        if key is not _UNKN:
                            env["@map:" + name + ":" + repr(key)] = flow
                            env[name] = env.get(name, EMPTY).plus(flow)
                        else:
                            env[name] = env.get(name, EMPTY).plus(
                                flow.unknown("container_dynamic_key"))
            elif isinstance(stmt, ast.AugAssign):
                add = self.expression(stmt.value, env, constants, func, depth)
                if isinstance(stmt.target, ast.Name):
                    name = stmt.target.id
                    env[name] = env.get(name, EMPTY).plus(add)
                    constants.pop(name, None)
            elif isinstance(stmt, ast.Expr):
                self.expression(stmt.value, env, constants, func, depth)
            elif isinstance(stmt, ast.Return):
                if stmt.value:
                    returned = returned.plus(
                        self.expression(stmt.value, env, constants, func, depth))
                # An early return may constrain later paths. We only skip
                # remaining statements when this is an unconditional return.
                break
            elif isinstance(stmt, ast.If):
                # Condition expressions can themselves perform a filesystem
                # access (e.g. user_controlled_path.exists()). The first
                # benchmark run exposed this exact omitted-sink false negative.
                self.expression(stmt.test, env, constants, func, depth)
                truth = _const(stmt.test, constants)
                if truth is not _UNKN:
                    branch = stmt.body if truth else stmt.orelse
                    returned = returned.plus(
                        self._walk(branch, env, constants, func, depth))
                else:
                    a, b = dict(env), dict(env)
                    ac, bc = dict(constants), dict(constants)
                    ar = self._walk(stmt.body, a, ac, func, depth)
                    br = self._walk(stmt.orelse, b, bc, func, depth)
                    for name in set(a) | set(b):
                        av, bv = a.get(name, EMPTY), b.get(name, EMPTY)
                        env[name] = av.plus(bv)
                        if av != bv:
                            env[name] = env[name].unknown("unknown_branch")
                    constants.clear()
                    constants.update({key: val for key, val in ac.items()
                                      if key in bc and bc[key] == val})
                    returned = returned.plus(ar).plus(br)
                    # Control guards over a tainted path require a path-sensitive
                    # verifier, even if a test exits the function in one branch.
                    test = stmt.test
                    text = ast.unparse(test)
                    if any(token in text for token in ("'../'", '"../"', "startswith",
                                                      "is_relative_to", "commonpath")):
                        for name, flow in list(env.items()):
                            if flow.sources:
                                env[name] = flow.unknown("unproven_path_guard")
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                returned = returned.plus(
                    self._walk(stmt.body, env, constants, func, depth))
                for handler in stmt.handlers:
                    returned = returned.plus(
                        self._walk(handler.body, dict(env), dict(constants), func, depth))
                returned = returned.plus(
                    self._walk(stmt.finalbody, env, constants, func, depth))
            elif isinstance(stmt, (ast.For, ast.While, ast.With, ast.AsyncWith)):
                if isinstance(stmt, ast.While):
                    self.expression(stmt.test, env, constants, func, depth)
                # Unknown loop/mgr semantics: analyze body but do not
                # announce absence of flow as a safety guarantee.
                body = getattr(stmt, "body", ())
                env_copy = dict(env)
                if isinstance(stmt, ast.For) and isinstance(stmt.target, ast.Name):
                    iteration_flow = self.expression(stmt.iter, env, constants, func, depth)
                    if iteration_flow.sources:
                        env_copy[stmt.target.id] = iteration_flow.unknown("loop_iteration_unverified")
                returned = returned.plus(
                    self._walk(list(body), env_copy, dict(constants), func, depth))
                for name, flow in env_copy.items():
                    if flow.sources:
                        env[name] = env.get(name, EMPTY).plus(
                            flow.unknown("unmodeled_loop_or_context"))
            else:
                # Collect possible calls but record uncertainty.
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Call):
                        self.expression(node, env, constants, func, depth)
        return returned


def analyze(source: str, filename: str,
            goal: DiscoveryGoal | None = None) -> Analysis:
    goal = goal or DiscoveryGoal()
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        result = Analysis(goal, filename)
        result.unresolved.append(f"syntax_error:{exc.lineno}")
        return result
    functions = {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    engine = _Analyzer(goal, filename, functions)
    for node in functions.values():
        engine._walk(node.body, {}, {}, node.name)
    # Module-level sinks can also matter, but do not treat definition bodies
    # as executed merely because the module was parsed.
    body = [stmt for stmt in tree.body
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef))]
    engine._walk(body, {}, {}, "<module>")
    return engine.result


def summarize_goal(labelled_truth: dict[str, bool],
                   predictions: dict[str, dict], goal: DiscoveryGoal) -> dict:
    """Separate label agreement, unknowns and truly verified vulnerabilities."""
    tp = fp = tn = fn = unknown = 0
    certified = 0
    for name, truth in labelled_truth.items():
        report = predictions.get(name)
        if report is None or report.get("unresolved") or report.get("unknown_count"):
            unknown += 1
            continue
        positive = bool(report.get("candidate_count"))
        if positive and truth:
            tp += 1
        elif positive:
            fp += 1
        elif truth:
            fn += 1
        else:
            tn += 1
        certified += min(report.get("verified_count", 0), report.get("candidate_count", 0))
    total = len(labelled_truth)
    known = tp + fp + tn + fn
    recall_lower_bound = tp / (tp + fn + unknown) if tp + fn + unknown else None
    return {
        "scope": goal.property_id,
        "total": total, "evaluated": known, "unknown": unknown,
        "tp_against_labels": tp, "fp_against_labels": fp,
        "tn_against_labels": tn, "fn_against_labels": fn,
        "label_precision": tp / (tp + fp) if tp + fp else None,
        "label_recall_on_evaluated": tp / (tp + fn) if tp + fn else None,
        "recall_lower_bound_treating_unknown_as_missed": recall_lower_bound,
        "verified_vulnerabilities": certified,
        "verified_target_met": certified >= 8,
        "target_recall": goal.target_recall,
        "warning": "Label agreement is NOT a verified vulnerability; unknown "
                   "cases are never negatives; validation against OWASP v0.1 "
                   "labels is development-only and labels are not a perfect oracle.",
    }
