"""D2.4F: exercise actual pre-fix and patched external Python security code.

The target is the PUBLIC, ALREADY FIXED historical Windows-device-path issue
in Werkzeug. Inputs are constructed from the old module's device-name symbols
and a general nested-path threat model, not from Git patch labels. Only the
function's WINDOWS BRANCH is safely emulated on Linux: no device opened, no
HTTP server, and no Windows kernel behavior asserted.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import ntpath
import os
from pathlib import Path
import posixpath
import runpy
from time import perf_counter
from types import SimpleNamespace

from prism.cyber_proof import Probe, run_revision_pair

# Standard regular path components; not an issue-specific exploit corpus.
FOLDERS = ("assets", "docs")
BENIGN = ("assets/logo.svg", "docs/readme.txt", "images/icon.png")
EXPECTED_REJECTIONS = ("../outside", "/absolute")
DEFAULT_DEVICE_LIMIT = 8


def real_module_safe_join(filename: Path):
    """Import unchanged module and emulates Windows globals without patching os."""
    before_hash = sha256(filename.read_bytes()).hexdigest()
    # Pure stdlib module source from pinned, externally authored repository.
    namespace = runpy.run_path(str(filename))
    join = namespace["safe_join"]
    device_names = frozenset(namespace["_windows_device_files"])
    global_vars = join.__globals__
    # Do NOT assign os.name on the process-wide Python os module.
    # Only safe_join's own namespace gets an accurate Windows os façade.
    global_vars["os"] = SimpleNamespace(
        name="nt", path=ntpath, sep="\\", altsep="/",
    )
    global_vars["_os_alt_seps"] = ["\\"]
    if sha256(filename.read_bytes()).hexdigest() != before_hash:
        raise RuntimeError("third-party checkout was modified")
    return join, device_names, before_hash


def source_derived_probes(symbols: frozenset[str]) -> list[Probe]:
    """Derive candidates without accessing a CVE label or patch diff."""
    # Device names are read from old third-party source. Restrict to simple
    # alphabetic forms to avoid depending on device-specific stream behavior.
    devices = sorted(name for name in symbols
                     if name.isascii() and name.isalpha()
                     and 2 <= len(name) <= 4)[:DEFAULT_DEVICE_LIMIT]
    if len(devices) < 2:
        raise ValueError("no comparable OS-device symbols in source")
    probes: list[Probe] = []
    for filename in BENIGN:
        probes.append(Probe("benign:"+filename, filename, False,
                            "generic benign path fixture"))
    for filename in EXPECTED_REJECTIONS:
        probes.append(Probe("parent-or-absolute:"+filename, filename, True,
                            "generic path boundary threat model"))
    for item in devices:
        probes.append(Probe("top-level:"+item, item, True,
                            "OS device-name registry from pinned source"))
        for prefix in FOLDERS:
            value = f"{prefix}/{item}"
            probes.append(Probe("nested:"+value, value, True,
                                "systematic path-depth × OS-device-name expansion"))
    return probes


def execute(before_path: Path, after_path: Path, output: Path) -> dict:
    started = perf_counter()
    prior_source = before_path.read_text(encoding="utf-8")
    patched_source = after_path.read_text(encoding="utf-8")
    for content in (prior_source, patched_source):
        ast.parse(content)
        if "def safe_join(" not in content:
            raise ValueError("source does not expose declared security operation")
    before_fn, before_devices, before_hash = real_module_safe_join(before_path)
    after_fn, after_devices, after_hash = real_module_safe_join(after_path)
    if before_devices != after_devices:
        raise ValueError("OS device symbol inventory not identical across versions")
    probes = source_derived_probes(before_devices)
    base = "scm-proof-root"
    # Strictly lexical/path-string outputs, never opening the device.
    def b(path: str) -> str | None:
        return before_fn(base, path)
    def a(path: str) -> str | None:
        return after_fn(base, path)
    report = run_revision_pair(probes, before=b, after=a)
    historical = [v for v in report["observations"]
                  if v["probe"].startswith("nested:")]
    if not historical:
        raise RuntimeError("no source-derived nested probes")
    if not all(not row["before_matches"] and row["after_matches"]
               for row in historical):
        raise AssertionError("expected real historical patch behavior not confirmed")
    if report["after_property_failures"]:
        raise AssertionError("security regression in patched external source")
    if not all(x["before_matches"] and x["after_matches"]
               for x in report["observations"]
               if not x["probe"].startswith("nested:")):
        raise AssertionError("non-target benign or safety controls diverged")
    result = {
        **report,
        "status": "HISTORICAL_THIRD_PARTY_BEHAVIORAL_REGRESSION_REPRODUCED",
        "external_library": "pallets/werkzeug",
        "revisions": {"before": "3.1.5", "after": "3.1.6"},
        "immutable_source_sha256": {"before": before_hash, "after": after_hash},
        "source_derived_devices_tested": sorted({
            row["input"].split("/")[-1] for row in historical}),
        "historical_nested_regressions": len(historical),
        "historical_vulnerability_adjudication":
            "public known fixed issue, CVE-2026-27199; not independent discovery",
        "platform_emulation": (
            "Windows os.name/ntpath and alternate separators are injected only "
            "into the imported safe_join function globals on Linux; source "
            "functions genuinely execute, no Windows kernel or device file"
        ),
        "proof_scope": (
            "untrusted path acceptance/rejection on Windows-like globals, "
            "NOT demonstration of OS hang, file disclosure or network exploitation"
        ),
        "input_generation": (
            "old source device-name registry × generic path-depth model; "
            "the CVE ID and patch labels are absent from candidate generation"
        ),
        "run_seconds_including_analysis": perf_counter() - started,
        "real_exploit_confirmed": False,
        "novel_vulnerability_confirmed": False,
        "tool_general_security_supremacy": None,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print("D24F_REAL_HISTORICAL_REGRESSION",
          json.dumps({
              "source_provenance": result["revisions"],
              "probes": result["probe_count"],
              "real_regression_witnesses": result["historical_nested_regressions"],
              "min_witness": result["minimal_observed_witness"]["input"],
              "sha256": result["deterministic_replay_sha256"],
              "seconds": round(result["run_seconds_including_analysis"], 4),
          }, sort_keys=True))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    opts = parser.parse_args()
    execute(opts.before, opts.after, opts.out)
