"""D2.4E: source-derived, syntax-level multi-language call surfaces.

Python frontend uses stdlib ast; Solidity frontend reuses D2.4C lexical function
extractor. Both are UNSOUND for complete security semantics, so unresolved
dependencies remain explicit and never certify safety.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
from time import perf_counter

from scripts.d24c_structural_frontier import extract_functions
import re


@dataclass(frozen=True)
class Surface:
    language: str
    source_sha256: str
    functions: tuple[str, ...]
    edges: dict[str, tuple[str, ...]]
    unresolved: dict[str, tuple[str, ...]]
    parse_seconds: float
    limitations: tuple[str, ...]


def python_surface(source: str) -> Surface:
    start = perf_counter()
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if not functions:
        raise ValueError("no module-level Python functions")
    if len(functions) != len([n for n in tree.body
                              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]):
        raise ValueError("overloaded/rebound Python function name UNKNOWN")
    names = set(functions)
    edges = {}
    unresolved = {}
    for name, node in functions.items():
        calls = set()
        unknown = set()
        for expression in ast.walk(node):
            if not isinstance(expression, ast.Call):
                continue
            fn = expression.func
            if isinstance(fn, ast.Name):
                if fn.id in names:
                    calls.add(fn.id)
                else:
                    unknown.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                unknown.add(ast.unparse(fn))
            else:
                unknown.add("<dynamic-call>")
        edges[name] = tuple(sorted(calls))
        unresolved[name] = tuple(sorted(unknown))
    return Surface("python-ast-module-local", sha256(source.encode()).hexdigest(),
                   tuple(sorted(names)), edges, unresolved, perf_counter()-start,
                   ("Imports, closures, type methods and dynamic dispatch unresolved",
                    "ast is syntax, not path- or data-flow-sensitive security analysis",
                    "Any external/unknown calls imply UNKNOWN rather than SAFE"))


def solidity_surface(source: str) -> Surface:
    start = perf_counter()
    functions = extract_functions(source)
    names = set(functions)
    edges = {}
    unresolved = {}
    pattern = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    member = re.compile(r"\b[A-Za-z_]\w*\s*\.\s*([A-Za-z_]\w*)\s*\(")
    for name, (_, _, body) in functions.items():
        observed = set(pattern.findall(body))
        edges[name] = tuple(sorted(observed & names))
        unresolved[name] = tuple(sorted(set(member.findall(body))))
    return Surface("solidity-lexical-file-local", sha256(source.encode()).hexdigest(),
                   tuple(sorted(names)), edges, unresolved, perf_counter()-start,
                   ("Not a Solidity AST or compiler-validated interprocedural IR",
                    "Inherited/imported contracts, modifiers, assembly, dynamic dispatch UNKNOWN",
                    "Textual reachability is not semantic program slicing"))


def closure(surface: Surface, roots: tuple[str, ...]) -> dict:
    if not roots or len(set(roots)) != len(roots) or not set(roots) <= set(surface.functions):
        raise ValueError("root set must exist in frozen independent source")
    visited = set(roots)
    pending = list(roots)
    while pending:
        node = pending.pop()
        for call in surface.edges[node]:
            if call not in visited:
                visited.add(call)
                pending.append(call)
    unknown = sorted({item for name in visited for item in surface.unresolved[name]})
    return {
        "roots": list(roots),
        "function_frontier": sorted(visited),
        "selected": len(visited),
        "total": len(surface.functions),
        "excluded": len(surface.functions)-len(visited),
        "unresolved_calls": unknown,
        "external_semantics": "UNKNOWN",
        "certifies_security": False,
    }
