"""Development-only alert audit and conservative decision-guided AST context.

No labels enter context selection. Context is an explanation aid, not a proof of
taint, reachability, sanitization or safety; it never suppresses an alert.
"""
import ast
import re
from urllib.parse import unquote, urlparse


def case_from_uri(uri):
    path = unquote(urlparse(uri.replace('\\', '/')).path)
    match = re.search(r'(?:^|/)(BenchmarkTest\d{5})\.py$', path)
    return match.group(1) if match else None


def cwes(values):
    if isinstance(values, (str, int)):
        values = [values]
    result = set()
    for value in values or []:
        text = str(value)
        if text.isdigit():
            result.add(int(text))
        else:
            result.update(int(x) for x in re.findall(r'CWE[-: ]*(\d+)', text, re.I))
    return result


def decision_context(source, line):
    tree = ast.parse(source)
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.lineno <= line <= n.end_lineno]
    scope = min(functions, key=lambda n: n.end_lineno - n.lineno) if functions else tree
    statements = [n for n in ast.walk(scope) if isinstance(n, ast.stmt) and n is not scope]
    selected = {n for n in statements if getattr(n, 'lineno', 0) <= line <= getattr(n, 'end_lineno', 0)}
    needed = {n.id for s in selected for n in ast.walk(s) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    # Include all earlier definitions of needed names, and their dependencies.
    # This intentionally over-approximates; no execution semantics are inferred.
    changed = True
    while changed:
        changed = False
        for stmt in statements:
            if stmt in selected or stmt.lineno > line:
                continue
            names = list(ast.walk(stmt))
            defined = {n.id for n in names if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
            if defined & needed:
                selected.add(stmt)
                needed.update(n.id for n in names if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load))
                changed = True
    return {'lines': sorted({n.lineno for n in selected}),
            'scope_statements': len(statements), 'selected_statements': len(selected),
            'certifies_safety': False}


def validate_scan(name, return_code, data):
    """Fail closed on partial scans; valid JSON is not completion evidence."""
    allowed = {0, 1} if name == 'bandit' else {0}
    problems = []
    if return_code not in allowed:
        problems.append('scanner_exit')
    if not isinstance(data, dict) or not isinstance(data.get('results'), list):
        return ['invalid_schema']
    if data.get('errors'):
        problems.append('scanner_errors')
    if name != 'bandit':
        paths = data.get('paths', {})
        if not paths.get('scanned') or paths.get('skipped'):
            problems.append('unverified_or_partial_coverage')
    return problems
