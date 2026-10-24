"""D2.4E post-preflight exploratory automation: derive rejection candidates.

Recognises a conventional Python if-condition containing str.startswith
literal and a direct return None. Conservative: does NOT infer sound taint
flow or that the guard is necessarily reachable under arbitrary inputs.
Each proposed seed is only a hypothesis until executed on pinned real code.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class GuardCandidate:
    function: str
    variable: str
    prefix: str
    witness: str
    line: int
    decision: str = "UNVERIFIED_SOURCE_DERIVED_TEST_CANDIDATE"


def candidates(source: str, *, only_function: str | None = None) -> list[GuardCandidate]:
    module = ast.parse(source)
    found = []
    for fn in module.body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if only_function is not None and fn.name != only_function:
            continue
        for test in ast.walk(fn):
            if not isinstance(test, ast.If):
                continue
            # Require a direct rejection on this branch; nested branches
            # could contain an unrelated return, so do not inspect children.
            rejects = any(isinstance(stmt, ast.Return)
                          and isinstance(stmt.value, ast.Constant)
                          and stmt.value.value is None for stmt in test.body)
            if not rejects:
                continue
            for child in ast.walk(test.test):
                if not isinstance(child, ast.Call):
                    continue
                method = child.func
                if not (isinstance(method, ast.Attribute)
                        and method.attr == "startswith"
                        and isinstance(method.value, ast.Name)
                        and len(child.args) == 1
                        and isinstance(child.args[0], ast.Constant)
                        and isinstance(child.args[0].value, str)):
                    continue
                prefix = child.args[0].value
                if not prefix or "\x00" in prefix:
                    continue
                # Only source literals are used. No known bug IDs, bug labels,
                # attack traces or external fixture names enter the compiler.
                found.append(GuardCandidate(fn.name, method.value.id, prefix,
                                            prefix+"d24e-probe", child.lineno))
    return sorted(set(found), key=lambda r: (r.function, r.line, r.prefix))
