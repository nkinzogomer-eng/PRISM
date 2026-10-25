"""D2.4F independent 2nd real-root-cause adapter: historical Starlette 0.26.1->0.27.0.

Run EXACT AST body of third-party StaticFiles.lookup_path on isolated temporary
files. No app server, remote endpoint, package installation or attacks.
Security objective is filepath containment in configured static root.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter
from types import SimpleNamespace

from prism.cyber_proof import Probe, run_revision_pair


def source_lookup_callable(path: Path):
    original = path.read_bytes()
    parsed = ast.parse(original, filename=str(path))
    matches = [fn for cls in parsed.body
               if isinstance(cls, ast.ClassDef) and cls.name == "StaticFiles"
               for fn in cls.body
               if isinstance(fn, ast.FunctionDef) and fn.name == "lookup_path"]
    if len(matches) != 1:
        raise ValueError("missing/ambiguous StaticFiles.lookup_path")
    function = matches[0]
    if function.decorator_list:
        raise ValueError("decorated method semantics unresolved")
    # Copy the original AST method without reimplementing its branch logic.
    # Future annotations remove dependency on package-local type aliases.
    future = ast.ImportFrom(module="__future__",
                            names=[ast.alias(name="annotations")], level=0)
    mini = ast.fix_missing_locations(ast.Module(
        body=[future, function], type_ignores=[]))
    scope = {"os": os}
    exec(compile(mini, str(path), "exec"), scope)
    if sha256(path.read_bytes()).hexdigest() != sha256(original).hexdigest():
        raise RuntimeError("external Starlette source changed unexpectedly")
    return scope["lookup_path"], sha256(original).hexdigest()


def derive_static_path_probes(root_name: str) -> list[Probe]:
    """Generate sibling-name attacks by combining filenames with base prefix.

    The properties and candidate synthesis do not read a security advisory
    or inspect the between-revision source diff.
    """
    suffixes = ("2.txt", "_private/secrets.txt", "_backup/log.txt")
    return [
        Probe("ordinary:file", "index.html", False, "real local static asset"),
        Probe("ordinary:nested", "images/icon.svg", False, "real local nested asset"),
        Probe("parent:outside", "../outside.txt", True,
              "general base-directory containment invariant"),
    ] + [
        Probe("sibling-prefix:"+suffix, "../"+root_name+suffix, True,
              "generic sibling prefix confusion test")
        for suffix in suffixes
    ]


def execute(before_path: Path, after_path: Path, out: Path) -> dict:
    started = perf_counter()
    before, before_digest = source_lookup_callable(before_path)
    after, after_digest = source_lookup_callable(after_path)
    with TemporaryDirectory(prefix="scm-d24f-starlette-") as tmp:
        base = Path(tmp)
        root = base / "public"
        (root / "images").mkdir(parents=True)
        (root / "index.html").write_text("public test data\n", encoding="utf-8")
        (root / "images" / "icon.svg").write_text("public icon\n", encoding="utf-8")
        (base / "outside.txt").write_text("private test data\n", encoding="utf-8")
        (base / "public2.txt").write_text("sibling data\n", encoding="utf-8")
        (base / "public_private").mkdir()
        (base / "public_private" / "secrets.txt").write_text("dummy\n", encoding="utf-8")
        (base / "public_backup").mkdir()
        (base / "public_backup" / "log.txt").write_text("dummy\n", encoding="utf-8")
        receiver = SimpleNamespace(all_directories=[str(root)], follow_symlink=False)
        probes = derive_static_path_probes(root.name)
        def observed(impl, probe: str):
            filename, stat = impl(receiver, probe)
            if stat is None:
                return None
            if not os.path.isfile(filename):
                raise AssertionError("claimed file observation did not exist")
            return filename
        record = run_revision_pair(
            probes,
            before=lambda p: observed(before, p),
            after=lambda p: observed(after, p),
        )
        hits = [r for r in record["observations"]
                if r["probe"].startswith("sibling-prefix:")]
        if len(hits) != 3 or not all(not r["before_matches"] and r["after_matches"]
                                     for r in hits):
            raise AssertionError("did not reproduce three independent local witnesses")
        if record["after_property_failures"]:
            raise AssertionError("patched third-party source violated test invariant")
        if not all(r["before_matches"] and r["after_matches"]
                   for r in record["observations"]
                   if not r["probe"].startswith("sibling-prefix:")):
            raise AssertionError("benign/outside controls not stable")
        evidence = {
            **record,
            "status": "HISTORICAL_THIRD_PARTY_REAL_FILE_BOUNDARY_REPRODUCED",
            "external_library": "Kludex/starlette",
            "revisions": {"before": "0.26.1", "after": "0.27.0"},
            "source_sha256": {"before": before_digest, "after": after_digest},
            "historical_sibling_file_regressions": len(hits),
            "method_execution": "unchanged StaticFiles.lookup_path AST on real temporary files",
            "evidence_scope": "local file lookup behavior without HTTP server",
            "historical_vulnerability_adjudication":
                "public fixed issue CVE-2023-29159, not a new discovery",
            "third_party_source_mutated": False,
            "novel_vulnerability_confirmed": False,
            "confirmed_in_live_service": False,
            "run_seconds_including_analysis": perf_counter()-started,
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=2, sort_keys=True)+"\n",
                   encoding="utf-8")
    print("D24F_STARLETTE_REAL_HISTORICAL",
          json.dumps({"probes": evidence["probe_count"],
                      "witnesses": evidence["historical_sibling_file_regressions"],
                      "min_witness": evidence["minimal_observed_witness"]["input"],
                      "sha256": evidence["deterministic_replay_sha256"],
                      "seconds": round(evidence["run_seconds_including_analysis"],4)},
                     sort_keys=True))
    return evidence


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--before", type=Path, required=True)
    p.add_argument("--after", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a=p.parse_args()
    execute(a.before, a.after, a.out)
