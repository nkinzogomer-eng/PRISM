#!/usr/bin/env python3
"""
Full acceptance campaign for the PRISM / AETHERION cyber range.

Runs, in order:
  1. up              (fabric + 13 services + real Anvil)
  2. isolation sweep (9 x 9 active reachability, declared vs observed)
  3. attack scenarios (S1..S7), twice each, to measure reproducibility
  4. mitigations     (fix flags), then the same scenarios again
  5. reset           (destroy + rebuild), then health + data restoration
  6. metrics         (per-service RSS, disk, host load)
  7. evidence        (sealed run directories with SHA256SUMS)
  8. preservation    (no tracked file in PRISM/CIEL changed by the range)

Writes range/state/reports/campaign-<ts>.json and prints a summary table.

  python3 range/lab/campaign.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctl  # noqa: E402

ATTACKS = ["S1", "S2", "S3", "S4", "S6"]
CONTROLS = ["S5", "S7"]
FIXES = ["session_binding", "gateway_sign_only_authz", "wallet_atomic",
         "dmz_port_isolation", "gateway_debug_header"]


def call(method: str, path: str, body: dict | None = None) -> dict:
    r = ctl.request(method, path, body)
    if r["status"] >= 400:
        raise SystemExit(f"{method} {path} -> {r['status']} {r['body']}")
    return r["body"]


def short(res: dict) -> dict:
    return {"id": res.get("id"), "verdict": res.get("verdict"),
            "seconds": res.get("seconds"),
            "parts": [{"zone": p.get("zone"), "verdict": p.get("verdict")}
                      for p in res.get("parts", [])]}


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def tracked_hash() -> dict[str, str]:
    """sha256 of every tracked file, excluding the range itself."""
    files = subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True,
                           text=True).stdout.split()
    out = {}
    for f in files:
        if f.startswith("range/") or f.startswith("docs/cyber-range/"):
            continue
        h = hashlib.sha256()
        try:
            with open(os.path.join(REPO, f), "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            continue
        out[f] = h.hexdigest()
    return out


def preservation(before: dict[str, str]) -> dict:
    after = tracked_hash()
    changed = sorted(f for f in before if before[f] != after.get(f))
    removed = sorted(set(before) - set(after))
    return {"files_checked": len(before), "changed": changed, "removed": removed,
            "clean": not changed and not removed}


def main() -> int:
    report: dict = {"started": time.time(), "_hash_before": tracked_hash(),
                    "host": {"cpus": os.cpu_count()}}
    t0 = time.time()
    print("== 0. rebuild from scratch (destruction + restore)")
    report["cold_start"] = call("POST", "/v1/reset")
    print("   health:", report["cold_start"].get("health", {}).get("healthy"),
          "| chain:", report["cold_start"].get("chain", {}).get("enabled"))
    report["up"] = call("POST", "/v1/up")
    print("   up ->", report["up"].get("state"),
          "| health:", report["up"].get("health", {}).get("healthy"),
          "| chain:", report["up"].get("chain", {}).get("enabled"))

    print("== 2. isolation sweep")
    iso = call("GET", "/v1/isolation")
    report["isolation"] = {k: iso.get(k) for k in
                           ("consistent", "mismatches", "pairs_checked",
                            "links_declared", "observed")}
    print("   consistent:", iso["consistent"], "| pairs:", iso["pairs_checked"],
          "| mismatches:", len(iso["mismatches"]))

    print("== 2b. egress containment (no route to the real Internet)")
    eg = call("GET", "/v1/egress")
    report["egress"] = eg
    print("   zones probed:", eg["zones"], "| leaks:", len(eg["leaks"]),
          "| isolated:", eg["isolated"])

    print("== 3. scenarios (2 passes)")
    report["pass1"], report["pass2"] = {}, {}
    for sid in ATTACKS + CONTROLS:
        r1 = call("POST", f"/v1/scenarios/{sid}/run")
        r2 = call("POST", f"/v1/scenarios/{sid}/run")
        report["pass1"][sid] = {**short(r1), "parts_full": r1.get("parts")}
        report["pass2"][sid] = {**short(r2), "parts_full": r2.get("parts")}
        a, b = report["pass1"][sid], report["pass2"][sid]
        print(f"   {sid:3} {str(a['verdict']):16} / {str(b['verdict']):16} "
              f"{'STABLE' if a['verdict'] == b['verdict'] else 'FLAKY'}")
    report["reproducible"] = all(report["pass1"][s]["verdict"] ==
                                 report["pass2"][s]["verdict"]
                                 for s in report["pass1"])

    print("== 4. mitigations, one fix at a time (attribution matters)")
    pairs = [("S1", "session_binding"), ("S2", "gateway_sign_only_authz"),
             ("S3", "wallet_atomic"), ("S4", "dmz_port_isolation"),
             ("S6", "gateway_debug_header")]
    report["mitigations"] = {}
    for sid, fix in pairs:
        call("POST", f"/v1/fix/{fix}", {"enable": True})
        res = short(call("POST", f"/v1/scenarios/{sid}/run"))
        call("POST", f"/v1/fix/{fix}", {"enable": False})
        back = short(call("POST", f"/v1/scenarios/{sid}/run"))
        report["mitigations"][sid] = {"fix": fix, "with_fix": res["verdict"],
                                      "reverted": back["verdict"]}
        print(f"   {sid:3} fix={fix:26} -> {res['verdict']:16} "
              f"(reverted: {back['verdict']})")
    report["fixes_effective"] = all(
        v["with_fix"] == "blocked" and v["reverted"] == "attack_possible"
        for v in report["mitigations"].values())
    report["baseline_expected"] = all(
        report["pass1"][s]["verdict"] == ("protected" if s in CONTROLS
                                          else "attack_possible")
        for s in report["pass1"])

    print("== 5. reset (destruction + restore)")
    report["reset"] = call("POST", "/v1/reset")
    report["reset_health"] = report["reset"].get("health", {})
    report["after_reset"] = short(call("POST", "/v1/scenarios/S2/run"))
    chain = call("GET", "/v1/status")
    report["restored"] = {
        "health": report["reset_health"].get("healthy") == 13,
        "ephemeral_findings_cleared": [f for f in report["reset"].get("flags", {})
                                       if report["reset"]["flags"][f]] == [],
        "vulnerability_present_again": report["after_reset"]["verdict"] == "attack_possible",
    }
    print("   health after reset:", report["reset_health"].get("healthy"),
          "| S2 regressed to:", report["after_reset"]["verdict"],
          "| restored:", report["restored"])

    print("== 6. metrics")
    report["metrics"] = call("GET", "/v1/metrics")
    print("   RSS total MB:", report["metrics"]["rss_total_mb"],
          "| services alive:",
          sum(1 for s in report["metrics"]["services"] if s["alive"]))

    print("== 7. evidence")
    ev = call("GET", "/v1/evidence")
    report["evidence"] = {"runs": len(ev.get("runs", [])), "dir": ev.get("dir")}
    print("   scenario runs recorded:", report["evidence"]["runs"])

    print("== 8. preservation (tracked files untouched)")
    report["preservation"] = preservation(report["_hash_before"])
    print("   changed tracked files:", len(report["preservation"]["changed"]),
          "| clean:", report["preservation"]["clean"])

    report["seconds"] = round(time.time() - t0, 1)
    out_dir = os.path.join(ctl.STATE, "reports")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir,
                        f"campaign-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json")
    report.pop("_hash_before", None)
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"\nreport: {path}  ({report['seconds']} s)")
    ok = (report["isolation"]["consistent"] and report["egress"]["isolated"]
          and report["reproducible"] and report["fixes_effective"]
          and report["preservation"]["clean"] and report["baseline_expected"])
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
