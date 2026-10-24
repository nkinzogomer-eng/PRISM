"""D2.4E real-source evaluation with independently checkable runtime oracles.

The external Python target is Werkzeug's path join; the Solidity target is
SCFuzzBench OUSD. No vulnerability labels or exploit paths are read by the
source-graph generator. Synthetic mutations are explicitly separate controls.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import posixpath
import runpy
from time import perf_counter

from prism.cyber_source_frontends import closure, python_surface, solidity_surface

EXPECTED_WERKZEUG = "6c4c680f5392342a68065114987f39160388064c"
EXPECTED_OUSD = "299ec6b6bf5401b43efc3e9f7ee5cab3e76167c4"
MUTATION_NEEDLE = 'or part.startswith("../")'
MUTATION_REPLACEMENT = "or False  # D24E local synthetic missing parent-path check"


def independent_containment(path: str | None, base: str) -> bool:
    """External *lexical* oracle, not a symlink/filesystem safety guarantee."""
    if path is None:
        return False
    parent = posixpath.abspath(base)
    absolute = posixpath.abspath(path)
    return posixpath.commonpath((parent, absolute)) == parent


CASES = {
    "file": ("assets/logo.svg", True),
    "nested": ("images/icons/avatar.png", True),
    "normalized": ("cache/../cached.txt", True),
    "parent": ("../secret.txt", False),
    "parent_nested": ("images/../../secret.txt", False),
    "two_parents": ("../../etc/passwd", False),
    "absolute": ("/etc/passwd", False),
}


def python_checks(source: str, source_file: Path) -> dict:
    # Execute pinned third-party module in-process; no live server/file IO.
    namespace = runpy.run_path(str(source_file))
    join = namespace["safe_join"]
    base = "/srv/d24e-pinned"
    clean = []
    for key, (userpath, expected_ok) in CASES.items():
        result = join(base, userpath)
        actual = independent_containment(result, base)
        if actual != expected_ok:
            raise AssertionError(f"real Werkzeug mismatch: {key} ({result!r})")
        if not expected_ok and result is not None:
            raise AssertionError(f"real Werkzeug accepted disallowed input: {key}")
        clean.append({"case": key, "expected": expected_ok,
                      "output": result, "independent_lexical_oracle": actual})
    if source.count(MUTATION_NEEDLE) != 1:
        raise ValueError("synthetic mutation location not unique, UNKNOWN")
    mutant = source.replace(MUTATION_NEEDLE, MUTATION_REPLACEMENT, 1)
    mutated_namespace = {"__name__": "d24e_synthetic_control"}
    exec(compile(mutant, str(source_file), "exec"), mutated_namespace)
    mutated_join = mutated_namespace["safe_join"]
    witnesses = []
    for key, (untrusted, expected_ok) in CASES.items():
        if expected_ok:
            continue
        result = mutated_join(base, untrusted)
        if result is not None and not independent_containment(result, base):
            witnesses.append(key)
    if not set(witnesses) & {"parent", "parent_nested", "two_parents"}:
        raise AssertionError("injected traversal regression did not trigger")
    # No changes to the upstream file on disk.
    if sha256(source_file.read_bytes()).hexdigest() != sha256(source.encode()).hexdigest():
        raise RuntimeError("external original source was modified")
    return {
        "external_file_unmodified": True,
        "clean_cases": clean,
        "clean_expected_matched": len(clean),
        "synthetic_mutation": "REMOVE_PARENT_PREFIX_GUARD",
        "synthetic_regression_witnesses": sorted(witnesses),
        "is_real_vulnerability_discovery": False,
        "safety_scope": "POSIX lexical containment only; no symlinks, filesystem or Windows claims",
    }


def evaluate(python_path: Path, solidity_path: Path, out: Path) -> dict:
    started = perf_counter()
    py_bytes = python_path.read_bytes()
    sol_bytes = solidity_path.read_bytes()
    py = py_bytes.decode("utf-8")
    sol = sol_bytes.decode("utf-8")
    py_surface = python_surface(py)
    sol_surface = solidity_surface(sol)
    selections = {
        "python_safe_join": closure(py_surface, ("safe_join",)),
        "python_password_verification": closure(py_surface, ("check_password_hash",)),
        "solidity_token_allowances": closure(sol_surface, ("transferFrom", "approve", "allowance")),
        "solidity_supply_mutations": closure(sol_surface, ("mint", "burn", "changeSupply", "transfer")),
    }
    if "safe_join" not in selections["python_safe_join"]["function_frontier"]:
        raise AssertionError("path safety function omitted")
    if "_hash_internal" not in selections["python_password_verification"]["function_frontier"]:
        raise AssertionError("password checking dependency omitted")
    if "transferFrom" not in selections["solidity_token_allowances"]["function_frontier"]:
        raise AssertionError("Solidity allowance caller omitted")
    runtime = python_checks(py, python_path)
    result = {
        "schema": "prism-d24e-real-source-cross-language-v1",
        "status": "REAL_SOURCES_RUNTIME_AND_LEXICAL_GATES_PASSED",
        "source_refs": {
            "python": {"repo": "pallets/werkzeug", "sha": EXPECTED_WERKZEUG,
                       "path": "src/werkzeug/security.py",
                       "sha256": sha256(py_bytes).hexdigest()},
            "solidity": {"repo": "scfuzzbench/origin-dollar-scfuzzbench",
                         "sha": EXPECTED_OUSD,
                         "path": "contracts/contracts/token/OUSD.sol",
                         "sha256": sha256(sol_bytes).hexdigest()},
        },
        "surface": {
            "python": {"functions": len(py_surface.functions),
                       "parse_seconds": py_surface.parse_seconds,
                       "limitations": list(py_surface.limitations)},
            "solidity": {"functions": len(sol_surface.functions),
                         "parse_seconds": sol_surface.parse_seconds,
                         "limitations": list(sol_surface.limitations)},
        },
        "selections": selections,
        "python_runtime": runtime,
        "total_python_analysis_and_controls_seconds": perf_counter()-started,
        "superiority_over_conventional_callgraph": None,
        "new_real_third_party_vulnerabilities": None,
        "unknowns": [
            "Python AST cannot resolve imported/virtual calls or infer untrusted-input semantics",
            "Solidity source frontend is lexical, misses inherited and dynamic effects",
            "Same local-call-graph closure is available to conventional graph reachability",
            "Synthetic control deliberately injected after frozen source and is not a zero-day",
            "No performance comparison against strong source analysis or directed fuzzing",
            "Python independent oracle tests POSIX lexical containment, not filesystem safety",
        ],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    print("D24E_REAL_SOURCE", json.dumps({
        "files": list(result["source_refs"]),
        "surfaces": {k: val["functions"] for k, val in result["surface"].items()},
        "frontiers": {k: [v["selected"], v["total"]] for k, v in selections.items()},
        "python_controls": len(runtime["clean_cases"]),
        "synthetic_regression": runtime["synthetic_regression_witnesses"],
        "seconds": round(result["total_python_analysis_and_controls_seconds"], 6),
    }, sort_keys=True))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--solidity", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    evaluate(args.python, args.solidity, args.out)
