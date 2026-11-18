"""Minimal dependency-free wheel backend for the offline reference package."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

NAME = "prism_scm"
VERSION = "0.1.0"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"


def _metadata() -> str:
    return (
        "Metadata-Version: 2.1\n"
        f"Name: prism-scm\n"
        f"Version: {VERSION}\n"
        "Summary: Dependency-free reference kernel for decision-preserving structural computation\n"
        "Requires-Python: >=3.10\n"
    )


def _wheel() -> str:
    return "Wheel-Version: 1.0\nGenerator: prism-local-backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n"


def get_requires_for_build_wheel(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    target = Path(metadata_directory) / DIST_INFO
    target.mkdir(parents=True, exist_ok=True)
    (target / "METADATA").write_text(_metadata(), encoding="utf-8")
    (target / "WHEEL").write_text(_wheel(), encoding="utf-8")
    return DIST_INFO


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    wheel_name = f"{NAME}-{VERSION}-py3-none-any.whl"
    root = Path(__file__).resolve().parents[1]
    entries: dict[str, bytes] = {}
    for source in sorted((root / "prism").glob("*.py")):
        entries[f"prism/{source.name}"] = source.read_bytes()
    entries[f"{DIST_INFO}/METADATA"] = _metadata().encode()
    entries[f"{DIST_INFO}/WHEEL"] = _wheel().encode()
    entries[f"{DIST_INFO}/entry_points.txt"] = b"[console_scripts]\nprism = prism.cli:main\n"
    records = []
    for name, data in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        records.append(f"{name},sha256={digest},{len(data)}")
    records.append(f"{DIST_INFO}/RECORD,,")
    entries[f"{DIST_INFO}/RECORD"] = ("\n".join(records) + "\n").encode()
    output = Path(wheel_directory) / wheel_name
    with ZipFile(output, "w", ZIP_DEFLATED) as wheel:
        for name, data in entries.items():
            wheel.writestr(name, data)
    return wheel_name
