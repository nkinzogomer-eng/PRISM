"""Development prototype: dependency evidence is never a safety certificate."""
import ast
import re


def dependency_graph(source):
    """Module-local, flow-insensitive may-depend graph; no executable slicing.

    Edges include all candidate name definitions and lexical control ancestors.
    Calls, imports, attributes, subscripts and dynamic constructs are unresolved.
    Even an empty uncertainty list does not attest absence of vulnerabilities.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return {'nodes': [], 'edges': [], 'uncertainty': ['parse_failure'],
                'certifies_safety': False}
    statements = [n for n in ast.walk(tree) if isinstance(n, ast.stmt)]
    ids = {n: i for i, n in enumerate(statements)}
    definitions = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            definitions.setdefault(node.id, set()).add(node.lineno)
    edges = set()
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                for line in definitions.get(node.id, ()):
                    edges.add((stmt.lineno, line, 'may_read'))
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                edges.add((child.lineno, stmt.lineno, 'lexical_control'))
    kinds = {type(n).__name__ for n in ast.walk(tree)}
    unresolved = kinds & {'Call', 'Import', 'ImportFrom', 'Attribute', 'Subscript',
                          'ClassDef', 'FunctionDef', 'AsyncFunctionDef', 'Lambda',
                          'Global', 'Nonlocal', 'Await', 'Yield', 'Delete',
                          'With', 'AsyncWith', 'Try', 'Match'}
    # Only a deliberately tiny inert grammar can be excluded from scanning.
    inert = all(isinstance(n, (ast.Module, ast.Expr, ast.Constant, ast.Pass))
                for n in ast.walk(tree))
    if not inert:
        unresolved.add('outside_inert_grammar')
    return {'nodes': [{'id': ids[n], 'line': n.lineno,
                       'kind': type(n).__name__} for n in statements],
            'edges': sorted(edges), 'uncertainty': sorted(unresolved),
            'certifies_safety': False}


def select(source, policy):
    if policy == 'full':
        return True, None
    if policy == 'simple':
        # Deliberately weak, label-free comparator; never a production policy.
        return bool(re.search(r'\b(open|Path|execute|executemany|raw)\b', source)), None
    if policy != 'prism':
        raise ValueError(policy)
    graph = dependency_graph(source)
    return bool(graph['uncertainty']), graph
