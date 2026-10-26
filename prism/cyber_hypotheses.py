"""D2.4H — source-first cyber hypothesis compilation.

No CVE names, patch comparison, human-supplied target property, or code
execution is needed to compile hypotheses. AST heuristics identify security
relevant operations and derive *candidate* invariants. Candidates are never
themselves findings, proofs, or evidence of new defects.

The compiler supports unknown, unsupported, or dynamic code explicitly.
This is not a sound interprocedural static analyzer.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Iterable


@dataclass(frozen=True)
class Hypothesis:
    identifier: str
    family: str
    function: str
    line: int
    source_signals: tuple[str, ...]
    property_statement: str
    priority: int
    probe_contract: str
    verification: str = "UNVERIFIED"
    scope: str = "FUNCTION_LOCAL_AST_HEURISTIC"


def _calls(node: ast.AST) -> set[str]:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            try:
                out.add(ast.unparse(n.func))
            except ValueError:
                out.add("<unsupported-call>")
    return out


def _parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    a = node.args
    params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    if a.vararg is not None:
        params.append(a.vararg)
    if a.kwarg is not None:
        params.append(a.kwarg)
    return {p.arg for p in params}


def _taint_names(expr: ast.AST, tainted: set[str]) -> bool:
    """Conservative *heuristic* data dependence on any known tainted name."""
    for n in ast.walk(expr):
        if isinstance(n, ast.Name) and n.id in tainted:
            return True
    return False


def _function_level_taint(fn: ast.AST, names: set[str]) -> set[str]:
    """Bounded source-to-local assignments, not path/alias sound."""
    tainted = set(names)
    for _ in range(12):
        additions = set()
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                expr = node.value
                if expr is None or not _taint_names(expr, tainted):
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        additions.add(target.id)
            elif isinstance(node, ast.NamedExpr) and _taint_names(node.value, tainted):
                if isinstance(node.target, ast.Name):
                    additions.add(node.target.id)
        if additions <= tainted:
            return tainted
        tainted |= additions
    return tainted


def _is_enabled_shell_call(node: ast.Call) -> bool:
    return any(k.arg == "shell" and isinstance(k.value, ast.Constant)
               and k.value.value is True for k in node.keywords)


def _callee(node: ast.Call) -> str:
    try:
        return ast.unparse(node.func)
    except ValueError:
        return "<unsupported-call>"


def _scope_functions(module: ast.Module) -> Iterable[tuple[str, ast.AST]]:
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield node.name+"."+child.name, child


def compile_python_hypotheses(source: str, *, include_unverified: bool = True) -> dict:
    """Return source-attributed candidates from *one* Python module.

    Safety: hypotheses are not verdicts. Executable oracles must be independent
    from the code under test, and detected patterns do not prove vulnerabilities.
    """
    module = ast.parse(source)
    prior = []
    for name, fn in _scope_functions(module):
        calls = _calls(fn)
        lowered = {c.lower() for c in calls}
        call_join = any("join" in c for c in lowered)
        path_norm = any(("realpath" in c or "abspath" in c or "normpath" in c)
                        for c in lowered)
        path_validation = any(("commonprefix" in c or "commonpath" in c
                            or "startswith" in c) for c in lowered)
        path_sink = any(c.endswith((".stat", ".open", ".sendfile")) for c in lowered)
        direct_path = ("safe_join" in name.lower()) and call_join
        if (call_join and (path_norm or path_validation or path_sink)) or direct_path:
            signals = tuple(sorted(c for c in calls if
                any(t in c.lower() for t in
                    ("join", "realpath", "abspath", "normpath", "stat",
                     "commonprefix", "commonpath", "startswith", "open"))))
            risk = 3 if any("commonprefix" in s.lower() for s in signals) else 2
            if path_sink or direct_path:
                prior.append(Hypothesis(
                    identifier=f"path_boundary:{name}",
                    family="path_boundary", function=name, line=fn.lineno,
                    source_signals=signals,
                    property_statement=(
                      "An untrusted relative path must not access a filesystem "
                      "resource outside the configured trusted root"),
                    priority=risk, probe_contract="LOCAL_ROOT_CONTAINMENT",
                ))
        # Detect untrusted command execution *hypotheses*. External execution is
        # never attempted by this compiler; only static candidate generation.
        arg_names = _parameter_names(fn)
        tainted = _function_level_taint(fn, arg_names)
        danger = {"os.system", "subprocess.run", "subprocess.Popen",
                  "subprocess.call", "subprocess.check_output", "eval", "exec"}
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            callee = _callee(call)
            if callee not in danger:
                continue
            input_dependent = any(_taint_names(x,tainted) for x in call.args)
            if not input_dependent:
                continue
            if callee in {"eval","exec","os.system"} or _is_enabled_shell_call(call):
                prior.append(Hypothesis(
                    identifier=f"untrusted_execution:{name}:{call.lineno}",
                    family="untrusted_execution", function=name,
                    line=call.lineno, source_signals=(callee,),
                    property_statement=(
                      "User-controlled data must not become an executable "
                      "expression or shell command without a verified boundary"),
                    priority=4, probe_contract="REQUIRES_SANDBOXED_EXECUTION_STUB",
                ))
        # Potential exfiltration via logs: only positive data flow from an
        # explicitly named sensitive input is considered. No implicit flows.
        sensitive = {n for n in arg_names if any(k in n.lower()
                       for k in ("password","secret","token","api_key","credential"))}
        if sensitive:
            sensitive_flow = _function_level_taint(fn, sensitive)
            log_methods = {"logging.info","logging.debug","logging.warning",
                           "logging.error","logging.critical",
                           "logger.info","logger.debug","logger.warning",
                           "logger.error","print"}
            for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
                sink = _callee(call)
                if sink in log_methods and any(_taint_names(a,sensitive_flow)
                                               for a in call.args):
                    prior.append(Hypothesis(
                        identifier=f"secret_logging:{name}:{call.lineno}",
                        family="secret_logging", function=name, line=call.lineno,
                        source_signals=(sink,*sorted(sensitive)),
                        property_statement=(
                          "Secret-valued inputs should not flow into observable logs"),
                        priority=3, probe_contract="INJECTED_CAPTURE_LOGGER",
                    ))
    # Deterministic ordering is essential for fixed-budget SCM work queues.
    prior.sort(key=lambda h: (-h.priority,h.line,h.identifier))
    if not include_unverified:
        prior = []
    return {
        "schema": "scm.prism.hypotheses.v1",
        "language": "python-ast",
        "source_sha256": sha256(source.encode()).hexdigest(),
        "candidates": [asdict(h) for h in prior],
        "counts_by_family": {
            family: sum(c.family==family for c in prior)
            for family in ("path_boundary","untrusted_execution","secret_logging")
        },
        "all_candidates_are_unverified": True,
        "new_vulnerabilities_confirmed": 0,
        "limitations": [
          "Function-local AST and bounded name-taint heuristics",
          "No sound alias, heap, interprocedural or implicit-flow semantics",
          "Dynamic calls, imports, decorators and framework effects unresolved",
          "Missing hypothesis never means a codebase is secure",
          "Only a separately executed, independently checked behavior can become a witness",
        ],
    }
