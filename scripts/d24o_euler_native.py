"""Historical Euler v1 native EVM regression (not an exploit or zero-day).

Run only in an isolated *temporary clone* of the public historical version.
Two independent local-EVM tests exercise the original `donateToReserves` and a
human-restored `checkLiquidity` counterfactual. The fixture knows the historical
mechanism; it therefore cannot count as blind autonomous discovery.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from time import perf_counter

from scripts.d24o_historical_euler import HISTORICAL_COMMIT, SOURCE_PATH


SOURCE_SHA = "e16bcbe5efa32f3b0538ed3f6ec29a2d64dbbff622b9712d129191731a79cd8b"


def restored_guard(source: str) -> str:
    """A human-authored control, *not* an original Euler patched revision."""
    a, delim, rest = source.partition("function donateToReserves(")
    if not delim or rest.count("logAssetStatus(assetCache);") != 1:
        raise ValueError("pinned historical donation method not found uniquely")
    marker = "        logAssetStatus(assetCache);"
    if rest.count(marker) != 1 or "checkLiquidity(account);" in rest:
        raise ValueError("unexpected donation guard structure")
    return a + delim + rest.replace(marker,
                      "        checkLiquidity(account);\n\n" + marker, 1)


def _native_once(repo: Path, test: str, out: Path) -> dict:
    started = perf_counter()
    env = dict(os.environ)
    for sensitive in ("ETH_RPC_URL", "FOUNDRY_ETH_RPC_URL", "ALCHEMY_API_KEY",
                      "PRIVATE_KEY", "ETHERSCAN_API_KEY"):
        env.pop(sensitive, None)
    command = [str(repo/"node_modules/.bin/hardhat"), "test", f"test/{test}"]
    result = subprocess.run(command, cwd=repo, env=env, capture_output=True,
                            text=True, timeout=600, check=False)
    out.mkdir(parents=True, exist_ok=True)
    (out/(test+".stdout.txt")).write_text(result.stdout[-40_000:])
    (out/(test+".stderr.txt")).write_text(result.stderr[-30_000:])
    combined = result.stdout + result.stderr
    clean = re.sub(r"\x1b\[[0-9;]*m", "", combined)
    if (result.returncode or not re.search(r"\b1 passing\b", clean)
            or "failing" in clean):
        raise ValueError("independent original-protocol native EVM control failed: "
                         + clean[-2400:])
    return {"native_test": test, "passed": 1, "exit_code": result.returncode,
            "wall_seconds": perf_counter()-started,
            "stdout_sha256": sha256(result.stdout.encode()).hexdigest()}


def run_native(repo: Path, fixtures: Path, out: Path) -> dict:
    repo = repo.resolve(strict=True)
    fixtures = fixtures.resolve(strict=True)
    if subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                               text=True).strip() != HISTORICAL_COMMIT:
        raise ValueError("native source checkout is NOT pinned before incident")
    source_file = repo/SOURCE_PATH
    original = source_file.read_text()
    if sha256(original.encode()).hexdigest() != SOURCE_SHA:
        raise ValueError("historical native source digest does not match source trial")
    original_test = fixtures/"D24OEulerOriginal.js"
    patched_test = fixtures/"D24OEulerGuardControl.js"
    if not original_test.is_file() or not patched_test.is_file():
        raise ValueError("missing independently authored native controls")
    copied = []
    try:
        target = repo/"test"/original_test.name
        if target.exists():
            raise ValueError("unexpected preexisting fixture path")
        shutil.copyfile(original_test, target)
        copied.append(target)
        before = _native_once(repo, original_test.name, out)
        target = repo/"test"/patched_test.name
        if target.exists():
            raise ValueError("unexpected preexisting fixed control path")
        shutil.copyfile(patched_test, target)
        copied.append(target)
        changed = restored_guard(original)
        source_file.write_text(changed)
        after = _native_once(repo, patched_test.name, out)
    finally:
        source_file.write_text(original)
        for path in copied:
            path.unlink(missing_ok=True)

    result = {
        "schema": "scm.prism.d24o.euler-historical-native-health.v1",
        "historical_commit": HISTORICAL_COMMIT,
        "source_sha256": SOURCE_SHA,
        "original_historical_healthy_debt_becomes_unhealthy_after_donation": before,
        "human_authored_postcheck_rejects_same_donation": after,
        "protocol_code_original_except_counterfactual_one_guard": True,
        "entire_production_euler_drain_demonstrated": False,
        "actual_financial_profit_demonstrated": False,
        "real_historical_known_health_check_omission_observed": True,
        "blind_autonomous_vulnerability_discovery": False,
        "new_zero_days": 0,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out/"native-evidence.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    return result


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--upstream", type=Path, required=True)
    cli.add_argument("--fixtures", type=Path, required=True)
    cli.add_argument("--out", type=Path, required=True)
    args = cli.parse_args()
    result = run_native(args.upstream, args.fixtures, args.out)
    print("D24O_NATIVE_EULER", json.dumps({"tests_passed": 2,
          "historical_health_violation": result[
              "real_historical_known_health_check_omission_observed"],
          "zero_days": 0},sort_keys=True))
