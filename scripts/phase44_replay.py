#!/usr/bin/env python3
"""Authorized, localhost-only Flask benchmark CWE-22 proof-of-behavior replay.

No arbitrary target URL, host, command or path can be supplied by callers.
The runtime uses one temporary root per benchmark case; attacker-controlled
request data points to a *synthetic sentinel file* just outside a synthetic
allowed directory but still inside that temporary root.

Results describe observed path-escape primitives in intentionally vulnerable
development code. They are NOT independently confirmed critical real-world
vulnerabilities, CWE labels, exploitability assessments or bug bounty reports.
"""
from __future__ import annotations

import argparse
import builtins
from contextlib import ExitStack
import codecs
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from unittest.mock import patch

if __package__ in ("", None):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.measure_phase43b import source_inventory

CASE_PATTERN = re.compile(r"BenchmarkTest\d{5}")


def select_routes(source_dir: Path) -> list[str]:
    """Select from route source strings ONLY, never the label CSV."""
    corpus = source_inventory(source_dir)
    out = []
    for case, src in sorted(corpus.items()):
        if b"/benchmark/pathtraver-" in src and (
            b"def " + case.encode() + b"_post" in src
        ):
            out.append(case)
    return out


def replay_one(source_dir: Path, case_id: str) -> dict:
    """Perform one sandboxed synthetic path-escape probe in a test client."""
    if not CASE_PATTERN.fullmatch(case_id):
        raise ValueError("invalid benchmark case ID")
    from flask import Flask
    import helpers.utils as helpers_utils

    module_path = (source_dir / (case_id + ".py")).resolve()
    if module_path.parent != source_dir.resolve() or not module_path.is_file():
        raise ValueError("case must be an existing direct benchmark module")
    if b"/benchmark/pathtraver-" not in module_path.read_bytes():
        raise ValueError("refuse replay outside path traversal benchmark route")
    t0 = time.perf_counter()
    result = {
        "case_id": case_id, "status": "unknown",
        "verified_outside_root": False, "operations": [],
        "runtime_seconds": None, "reason": None,
        "classification": "no finding until a fresh synthetic sandbox probe succeeds",
    }
    with tempfile.TemporaryDirectory(prefix="prism-path44-") as temporary:
        world = Path(temporary).resolve()
        allowed = world / "allowed"
        allowed.mkdir()
        name = f"SCM44_WITNESS_{case_id}.txt"
        target = world / name
        target.write_text("PRISM_GOAL_SENTINEL\n", encoding="utf-8")
        target_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        payload = "../" + name

        old_dir = helpers_utils.TESTFILES_DIR
        helpers_utils.TESTFILES_DIR = str(allowed)
        module_name = "prism_local_benchmark_" + case_id
        operations = []
        def track(path: object, operation: str, completed: bool) -> None:
            if isinstance(path, (str, os.PathLike)):
                try:
                    resolved = Path(path).resolve()
                except (OSError, ValueError, RuntimeError):
                    return
                if resolved == target:
                    operations.append({"operation": operation, "completed": bool(completed),
                                       "path": "<TEMP>/"+name,
                                       "outside_allowed": True,
                                       "inside_temporary_sandbox": True})
        old_builtin = builtins.open
        old_codecs = codecs.open
        old_exists = os.path.exists
        old_path_exists = Path.exists
        old_path_open = Path.open

        def guarded_builtin(path, *args, **kw):
            out = old_builtin(path, *args, **kw)
            track(path, "builtin_open", True)
            return out

        def guarded_codecs(path, *args, **kw):
            out = old_codecs(path, *args, **kw)
            track(path, "codecs_open", True)
            return out

        def guarded_os_exists(path):
            out = old_exists(path)
            track(path, "os_path_exists", bool(out))
            return out

        def guarded_path_exists(path):
            out = old_path_exists(path)
            track(path, "pathlib_exists", bool(out))
            return out

        def guarded_path_open(path, *args, **kw):
            out = old_path_open(path, *args, **kw)
            track(path, "pathlib_open", True)
            return out

        try:
            # Module setup and Flask routing occur with sandbox source only.
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ValueError("cannot load pinned path traversal module")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            app = Flask(module_name)
            app.testing = True
            module.init(app)
            post_name = case_id + "_post"
            rules = [r for r in app.url_map.iter_rules()
                     if r.endpoint == post_name and "POST" in r.methods]
            if len(rules) != 1:
                raise ValueError("expected exactly one POST handler")
            route = str(rules[0])
            with ExitStack() as stack:
                stack.enter_context(patch("builtins.open", guarded_builtin))
                stack.enter_context(patch("codecs.open", guarded_codecs))
                stack.enter_context(patch("os.path.exists", guarded_os_exists))
                stack.enter_context(patch.object(Path, "exists", guarded_path_exists))
                stack.enter_context(patch.object(Path, "open", guarded_path_open))
                client = app.test_client()
                # All source channels get the same inert relative path so a
                # result does not need access to labels or scanner detections.
                client.set_cookie(case_id, payload, domain="localhost")
                response = client.post(
                    route, query_string={case_id: payload},
                    data={case_id: payload},
                    headers={case_id: payload},
                    base_url="https://localhost",
                )
                response_status = response.status_code
            # Sentinel modification catches write primitives while the
            # monitored open calls record filesystem reads and metadata probes.
            now_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            if now_hash != target_hash and not operations:
                operations.append({"operation": "synthetic_sentinel_changed",
                                   "completed": True, "path": "<TEMP>/"+name,
                                   "outside_allowed": True,
                                   "inside_temporary_sandbox": True})
            verified = any(op["completed"] and op["outside_allowed"] for op in operations)
            result.update({
                "status": ("verified_sandbox_path_escape" if verified
                           else "no_escape_observed"),
                "verified_outside_root": verified,
                "operations": operations,
                "response_status": response_status,
                "reason": None,
                "classification": (
                    "replayed path escape to synthetic local-only sentinel"
                    if verified else
                    "this one probe did not observe path escape; this is NOT safety proof"),
            })
        except Exception as exc:
            result["reason"] = type(exc).__name__ + ": " + str(exc)[:300]
            result["status"] = "unknown"
            result["classification"] = "runtime error, no negative safety conclusion"
        finally:
            helpers_utils.TESTFILES_DIR = old_dir
            sys.modules.pop(module_name, None)
    result["runtime_seconds"] = time.perf_counter() - t0
    return result


def replay(source_dir: Path, limit: int | None = None) -> dict:
    benchmark_root = source_dir.resolve().parent
    if str(benchmark_root) not in sys.path:
        sys.path.insert(0, str(benchmark_root))
    routes = select_routes(source_dir)
    if limit is not None:
        if not 1 <= limit <= 168:
            raise ValueError("limit must be between 1 and 168")
        routes = routes[:limit]
    all_cases = {}
    t0 = time.perf_counter()
    for case in routes:
        all_cases[case] = replay_one(source_dir, case)
    values = list(all_cases.values())
    return {
        "schema_version": 1,
        "phase": "4.4B",
        "target": "CWE-22 actual path escaping synthetic sandbox allowed root",
        "dataset": "OWASP Python v0.1 developer corpus, no labels in selection or execution",
        "tested": len(values),
        "verified_sandbox_escapes": sum(x["verified_outside_root"] for x in values),
        "unknown": sum(x["status"] == "unknown" for x in values),
        "not_observed": sum(x["status"] == "no_escape_observed" for x in values),
        "elapsed_wall_seconds": time.perf_counter() - t0,
        "cases": all_cases,
        "limitations": [
            "Synthetic request and sentinel file in a disposable temporary directory",
            "Successful file-open/existence is evidence of this primitive only",
            "No claim of critical severity, attack reachability or real-world exploitability",
            "One payload and one route per case, not exhaustive dynamic testing",
            "HTTP application route via local in-process Flask test client only",
            "No independent holdout; source route text used for selection, labels hidden",
            "Non-observation and errors never prove absence of vulnerabilities",
            "Successful replay is not necessarily the benchmark's CWE ground truth",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    result = replay(args.source_dir, args.limit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n",
                           encoding="utf-8")
    print("CWE22 controlled execution:", result["tested"], "tested",
          result["verified_sandbox_escapes"], "observed sandbox path escape",
          result["unknown"], "runtime errors",
          result["not_observed"], "not observed",
          round(result["elapsed_wall_seconds"], 2), "wall seconds")
    print("sample cases", {
        k: result["cases"][k]["status"]
        for k in list(result["cases"])[:10]
    })


if __name__ == "__main__":
    main()
