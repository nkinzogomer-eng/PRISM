"""Independent conventional Python AST graph traversal baseline.

No special SCM properties; keeps a parsed graph between queries, so PRISM
cannot claim an artificial win over a deliberately recomputing competitor.
"""
import ast
from time import perf_counter


def ast_callgraph_baseline(source: str, root_groups: dict[str, tuple[str, ...]]) -> dict:
    started = perf_counter()
    module = ast.parse(source)
    functions = {fn.name: fn for fn in module.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if len(functions) != len([fn for fn in module.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]):
        raise ValueError("duplicate/rebound top-level function UNKNOWN")
    adjacency = {}
    for name, fn in functions.items():
        adjacency[name] = {
            call.func.id for call in ast.walk(fn)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id in functions
        }
    build_time = perf_counter() - started
    results = {}
    for label, roots in root_groups.items():
        if not set(roots) <= set(functions) or not roots:
            raise ValueError("missing baseline goal")
        begin = perf_counter()
        seen = set(roots)
        queue = list(roots)
        while queue:
            for child in adjacency[queue.pop()]:
                if child not in seen:
                    seen.add(child)
                    queue.append(child)
        results[label] = {
            "closure": sorted(seen),
            "reachability_seconds": perf_counter()-begin
        }
    return {
        "baseline": "conventional AST graph + cached callgraph BFS",
        "function_count": len(functions),
        "build_seconds": build_time,
        "queries": results,
        "technical_advantage_of_scm_claimed": False,
    }
