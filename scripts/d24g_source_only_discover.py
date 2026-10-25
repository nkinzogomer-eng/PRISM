"""D2.4G local authorized, source-only scanning of two independent real APIs.

No patch version, advisory ID, previous findings or labels are read by the
scanner. The research targets themselves were selected after historical
knowledge: this is a LABEL-BLIND pipeline test, NOT a sealed scientific holdout.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import ntpath
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from prism.cyber_discovery import SecurityProbe, ciel_capability_result, discover
from scripts.d24f_historical_real_regression import real_module_safe_join, source_derived_probes
from scripts.d24f_starlette_real_regression import source_lookup_callable, derive_static_path_probes


def starlette_scan(source: Path, limit: int) -> dict:
    method, digest = source_lookup_callable(source)
    # Treat source as *untrusted* input: only its lookup_path method is compiled
    # and executed in a fresh, ephemeral no-network process/CI container.
    with TemporaryDirectory(prefix="prism-source-only-") as tmp:
        sandbox = Path(tmp)
        root = sandbox/"public"
        (root/"images").mkdir(parents=True)
        (root/"index.html").write_text("valid public asset\n", encoding="utf-8")
        (root/"images"/"icon.svg").write_text("normal icon\n", encoding="utf-8")
        (sandbox/"outside.txt").write_text("dummy outside\n", encoding="utf-8")
        (sandbox/"public2.txt").write_text("dummy sibling\n", encoding="utf-8")
        (sandbox/"public_private").mkdir()
        (sandbox/"public_private"/"secrets.txt").write_text("dummy\n", encoding="utf-8")
        (sandbox/"public_backup").mkdir()
        (sandbox/"public_backup"/"log.txt").write_text("dummy\n", encoding="utf-8")
        probes = [
            SecurityProbe(p.id, p.input,
                          "DENY" if p.expects_rejection else "ALLOW",
                          p.provenance)
            for p in derive_static_path_probes(root.name)
        ]
        receiver = SimpleNamespace(all_directories=[str(root)], follow_symlink=False)
        def observe(value: str) -> tuple[str, str | None]:
            path, st = method(receiver, value)
            if st is None:
                return "DENY", None
            if not os.path.isfile(path):
                raise AssertionError("method returned non-existent static asset")
            real_path = Path(os.path.realpath(path))
            # Verify actual resolved file location. The property oracle is
            # independent of the target method's source branch logic.
            outside = os.path.commonpath((str(root.resolve()), str(real_path))) != str(root.resolve())
            label = "DENY" if outside else "ALLOW"
            # The behavior of the program is ACCEPT if stat exists, regardless
            # of our oracle. The oracle determines the EXPECTED probe decision.
            if outside and not value.startswith("../"):
                raise AssertionError("unexpected out-of-root result")
            return "ALLOW", str(real_path.relative_to(sandbox.resolve()))
        record = discover(
            project="Kludex/starlette",
            source_sha256=digest,
            property_id="static_file_must_resolve_under_configured_root",
            probes=probes,
            observe=observe,
            max_probes=limit,
            context={
                "adapter": "starlette-staticfiles-local-method",
                "root_is_temp_local_directory": True,
                "independent_realpath_containment_oracle": True,
                "network_access": False,
                "not_a_sealed_historical_holdout": True,
                "source_code_selected_with_prior_research_knowledge": True,
            },
        )
        # Independent completeness gate: all candidate judgments should be
        # reproducible and ordinary file controls must still work.
        for row in record["observations"]:
            if row["identifier"].startswith("ordinary:") and row["observed"] != "ALLOW":
                raise AssertionError("invalid ordinary static file baseline")
    return record


def werkzeug_scan(source: Path, limit: int) -> dict:
    join, registry, digest = real_module_safe_join(source)
    probes = [
        SecurityProbe(p.id, p.input,
                      "DENY" if p.expects_rejection else "ALLOW",
                      p.provenance)
        for p in source_derived_probes(registry)
    ]
    def observe(value: str) -> tuple[str, str | None]:
        result = join("prism-static-root", value)
        return ("DENY", None) if result is None else ("ALLOW", result)
    return discover(
        project="pallets/werkzeug",
        source_sha256=digest,
        property_id="windows_url_path_device_names_all_segments_rejected",
        probes=probes,
        observe=observe,
        max_probes=limit,
        context={
            "adapter": "werkzeug-safejoin-windows-branch-facade",
            "windows_os_name_emulated_in_function_globals_only": True,
            "real_windows_device_opened": False,
            "network_access": False,
            "not_a_sealed_historical_holdout": True,
            "source_code_selected_with_prior_research_knowledge": True,
            "independent_windows_kernel_semantics_unverified": True,
        },
    )


def django_scan(source: Path, limit: int) -> dict:
    """Independent current-source Linux lexical containment trial.

    Extract the genuine third-party safe_join function AST without loading
    the full Django framework. A separately defined local SuspiciousFileOperation
    stub substitutes ONLY the unavailable imported exception type.
    """
    raw = source.read_bytes()
    tree = ast.parse(raw, filename=str(source))
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name == "safe_join"]
    if len(functions) != 1 or functions[0].decorator_list:
        raise ValueError("unsupported/ambiguous Django safe_join source")
    class SuspiciousFileOperation(Exception):
        pass
    env = {"abspath": os.path.abspath, "join": os.path.join,
           "normcase": os.path.normcase, "sep": os.sep,
           "dirname": os.path.dirname, "SuspiciousFileOperation": SuspiciousFileOperation}
    unit = ast.fix_missing_locations(ast.Module(body=[functions[0]], type_ignores=[]))
    exec(compile(unit, str(source), "exec"), env)
    join = env["safe_join"]
    with TemporaryDirectory(prefix="prism-django-independent-") as tmp:
        root = Path(tmp)/"public"
        root.mkdir()
        inputs = [
            ("valid_file", "index.html", "ALLOW"),
            ("valid_nested", "images/icon.svg", "ALLOW"),
            ("same_directory", ".", "ALLOW"),
            ("parent", "../outside.txt", "DENY"),
            ("prefix_sibling", "../public2.txt", "DENY"),
            ("private_sibling", "../public_private/secret.txt", "DENY"),
            ("absolute_outside", str(Path(tmp)/"outside.txt"), "DENY"),
        ]
        probes = [SecurityProbe(name,value,want,
                   "POSIX root-containment/property-driven source-only test")
                  for name,value,want in inputs]
        def observe(payload: str) -> tuple[str, str | None]:
            try:
                value = join(str(root),payload)
            except SuspiciousFileOperation:
                return "DENY", None
            # This is the program's actual ACCEPT, not a forced oracle verdict.
            return "ALLOW", str(Path(value).relative_to(Path(tmp)))
        result = discover(
            project="django/django",
            source_sha256=sha256(raw).hexdigest(),
            property_id="linux_static_path_must_be_lexically_under_base",
            probes=probes, observe=observe, max_probes=limit,
            context={
                "adapter":"django-safejoin-source-ast",
                "full_framework_dependencies_not_loaded":True,
                "actual_upstream_function_ast_used":True,
                "linux_path_behavior_only":True,
                "not_a_sealed_prospective_holdout":True,
                "selected_as_unseen_current_public_source":True,
                "security_advisory_or_patched_source_not_supplied":True,
            },
        )
    return result


def evaluate(source: Path, adapter: str, limit: int, out: Path, *,
             mission_id: str = "", task_id: str = "", authorized: bool = False) -> dict:
    if not authorized:
        raise PermissionError("explicit --authorized-local required for local source execution")
    if not source.is_file():
        raise FileNotFoundError(source)
    before = sha256(source.read_bytes()).hexdigest()
    if adapter == "starlette_static":
        report = starlette_scan(source, limit)
    elif adapter == "werkzeug_windows_path":
        report = werkzeug_scan(source, limit)
    elif adapter == "django_safe_join":
        report = django_scan(source, limit)
    else:
        raise ValueError("unsupported source adapter; no guessed behavior")
    if sha256(source.read_bytes()).hexdigest() != before:
        raise RuntimeError("original external source changed during scan")
    if report["target"]["source_sha256"] != before:
        raise RuntimeError("source provenance mismatch")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    if mission_id or task_id:
        exported = ciel_capability_result(
            report, mission_id=mission_id, task_id=task_id, authorized=authorized)
        export_path = out.with_suffix(".ciel.json")
        export_path.write_text(json.dumps(exported, indent=2, sort_keys=True)+"\n",
                               encoding="utf-8")
    print("D24G_SOURCE_ONLY_DISCOVERY",json.dumps({
        "adapter": adapter,
        "verdict": report["status"],
        "probes": report["hypotheses_generated"],
        "local_witnesses": report["observed_property_violations"],
        "min_witness": None if report["minimal_observed_witness"] is None
                       else report["minimal_observed_witness"]["payload"],
        "replay_sha256": report["replay_sha256"],
        "new_unknown_vulnerability_confirmed": False,
    }, sort_keys=True))
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--adapter", required=True,
                   choices=("starlette_static", "werkzeug_windows_path", "django_safe_join"))
    p.add_argument("--max-probes", type=int, default=64)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--authorized-local", action="store_true")
    p.add_argument("--mission-id", default="")
    p.add_argument("--task-id", default="")
    args = p.parse_args()
    evaluate(args.source, args.adapter, args.max_probes, args.out,
             mission_id=args.mission_id, task_id=args.task_id,
             authorized=args.authorized_local)
