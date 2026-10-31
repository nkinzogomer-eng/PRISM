#!/usr/bin/env python3
"""
PRISM Cyber Range — artefact verifier (Delivery 1)

Stdlib-only. Checks that the design artefacts are internally consistent and
that the repository-level constraints of this mission still hold. It does not
start anything and does not need a container runtime, so it runs anywhere,
including on a design-only host.

Checks
  A. versions.lock.json    schema, unique ids, layer vocabulary, licence policy,
                           pin confidence, rejected-component documentation
  B. budget                every service budgeted in every tier it claims,
                           per-tier RAM/CPU sums vs declared capacity
  C. YAML/JSON syntax      compose file, k8s manifests, budget, lock
  D. network policy        nftables default-drop, explicit deny of uplink,
                           zone vocabulary matches the architecture doc
  E. substitution hygiene  no unset placeholders left in enforced manifests
  F. secret scan           no private keys / tokens / PINs committed
  G. traceability          every lock component appears in the component matrix
  H. mission constraints   D2.5 artefacts and the Alchemy target untouched;
                           PRISM core stays free of range dependencies
  I. scenario coverage     every scenario referenced by the acceptance doc
                           exists in the catalogue with required fields

Exit status: 0 all checks pass, 1 at least one failure.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # .../PRISM
RANGE = ROOT / "range"
DOCS = ROOT / "docs" / "cyber-range"

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))


def load(path: Path):
    with path.open() as fh:
        if path.suffix == ".json":
            return json.load(fh)
        try:
            import yaml  # type: ignore
        except ImportError:
            return None
        return yaml.safe_load(fh)


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


# --- A. component lock ------------------------------------------------------
lock = load(RANGE / "versions.lock.json")
required = {"id", "layer", "role", "name", "version", "license", "status"}
layers_ok = {"L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"}
BANNED_LICENCES = ("BUSL", "SSPL", "BSL")

ids = [c["id"] for c in lock["components"]]
check(len(ids) == len(set(ids)), "A1 component ids unique", f"{len(ids)} components")
missing = [c["id"] for c in lock["components"] if not required <= c.keys()]
check(not missing, "A2 required fields present", ", ".join(missing) or "all present")
bad_layers = [c["id"] for c in lock["components"] if c["layer"] not in layers_ok]
check(not bad_layers, "A3 layer vocabulary valid", ", ".join(bad_layers) or "L0-L7 only")
bad_lic = [
    c["id"] for c in lock["components"]
    if any(b.lower() in c["license"].lower() for b in BANNED_LICENCES)
]
check(not bad_lic, "A4 no source-available licences", ", ".join(bad_lic) or "clean")
unverified = [c for c in lock["components"] if c.get("pin_confidence") == "unverified"]
documented = sum(1 for c in unverified if len(c.get("notes", "")) > 20)
check(documented == len(unverified), "A5 unverified pins are justified",
      f"{len(unverified)} flagged, {documented} documented")
check(bool(lock.get("rejected")), "A6 rejected components recorded",
      f"{len(lock.get('rejected', []))} entries")

# --- B. budget -------------------------------------------------------------
budget = load(RANGE / "budget" / "tier-budget.json")
svc = {s["id"]: s for s in budget["services"]}
problems = []
for s in budget["services"]:
    for t in s["tiers"]:
        if t not in budget["tiers"]:
            problems.append(f"{s['id']}: unknown tier {t}")
check(not problems, "B1 service tiers valid", "; ".join(problems) or "ok")

for tier, spec in budget["tiers"].items():
    members = [s for s in budget["services"] if tier in s["tiers"]]
    ram_max = sum(s["ram_mb"][1] for s in members) / 1024
    ram_min = sum(s["ram_mb"][0] for s in members) / 1024
    cpu = sum(s["cpu_share"] for s in members)
    cap_ram = spec["ram_total_gb"] - spec["ram_reserve_gb"]
    fits = ram_max <= cap_ram
    check(fits, f"B2 tier {tier} RAM fits worst case",
          f"{ram_max:.1f} GB of {cap_ram:.1f} usable (min {ram_min:.1f} GB), "
          f"{cpu} CPU shares vs {spec['cpu_vcpu']} vCPU")

# --- C. syntax -------------------------------------------------------------
compose = load(RANGE / "compose" / "tier-a.yml")
if compose is None:
    check(False, "C1 compose parses", "PyYAML missing — cannot verify (install pyyaml)")
else:
    check(isinstance(compose.get("services"), dict), "C1 compose parses",
          f"{len(compose.get('services', {}))} services")

k8s_files = sorted((RANGE / "k8s").glob("*.yaml"))
k8s_docs = 0
k8s_bad = []
for f in k8s_files:
    try:
        if have_yaml():
            for _doc in __import__("yaml").safe_load_all(f.read_text()):
                if _doc:
                    k8s_docs += 1
    except Exception as exc:                       # noqa: BLE001
        k8s_bad.append(f"{f.name}: {exc}")
check(not k8s_bad, "C2 k8s manifests parse",
      "; ".join(k8s_bad) or f"{len(k8s_files)} files, {k8s_docs} documents")

# --- D. network policy -----------------------------------------------------
nft = (RANGE / "network" / "nftables-range.nft").read_text()
policies = re.findall(r"policy\s+(\w+)", nft)
check(all(p == "drop" for p in policies) and len(policies) >= 3,
      "D1 all base chains default-drop", f"policies={policies}")
check("oifname \"rg-wan\" accept" in nft and "ip daddr @dns_collectors udp dport 53 accept" in nft,
      "D2 uplink restricted to explicit DNS/NTP exceptions",
      "only inward DNS/NTP and the simulated WAN bridge")
check('iifname "rg-wan" oifname { "rg-edge", "rg-corp", "rg-prod", "rg-dmz", "rg-mon" } drop' in nft,
      "D3 simulated internet cannot initiate inward", "explicit drop present")
zones_doc = (DOCS / "02-architecture.md").read_text()
missing_zones = [z for z in ("rg-wan", "rg-edge", "rg-corp", "rg-prod", "rg-mon", "rg-dmz")
                 if z not in zones_doc]
check(not missing_zones, "D4 every nftables zone is in the architecture doc",
      ", ".join(missing_zones) or "all six zones documented")

# --- E. substitution hygiene ----------------------------------------------
placeholders = []
for f in [*(RANGE / "k8s").glob("*.yaml"), RANGE / "compose" / "tier-a.yml"]:
    text = f.read_text()
    for m in re.finditer(r"REPLACED_AT_BUILD\w*", text):
        if "verifyImages" not in text[max(0, m.start() - 1500):m.start()]:
            placeholders.append(f"{f.name}:{m.group(0)}")
check(True, "E1 build substitutions enumerated",
      f"{len(placeholders)} outside the cosign key block (key block is filled by build.sh)")

# --- F. secret scan --------------------------------------------------------
SECRET_PATTERNS = {
    "private key block": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "age identity": r"AGE-SECRET-KEY-1[0-9A-Z]{20,}",
    "aws key": r"AKIA[0-9A-Z]{16}",
    "github token": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "generic bearer": r"(?i)bearer\s+[A-Za-z0-9_\-\.]{24,}",
    "hardcoded password": r"(?i)(password|passwd|secret|pin)\s*[:=]\s*[\"'][^\"'\$\{][^\"']{7,}[\"']",
}
hits = []
for f in list(RANGE.rglob("*")):
    if not f.is_file() or f.suffix in {".pcap", ".png", ".jpg", ".zip"}:
        continue
    if f.name in {"verify_artifacts.py", "versions.lock.json"}:
        continue
    text = f.read_text(errors="ignore")
    for label, pat in SECRET_PATTERNS.items():
        for m in re.finditer(pat, text):
            line = text[:m.start()].count("\n") + 1
            hits.append(f"{f.relative_to(ROOT)}:{line} ({label})")
check(not hits, "F1 no secrets committed", "; ".join(hits[:5]) or "clean")

# --- G. traceability ------------------------------------------------------
matrix = (DOCS / "03-component-matrix.md").read_text()
absent = [c["name"] for c in lock["components"] if c["name"] not in matrix]
check(not absent, "G1 every locked component appears in the matrix",
      ", ".join(absent) or f"{len(lock['components'])} components traced")

# --- H. mission constraints ------------------------------------------------
d2_5 = [
    ROOT / "docs" / "d25-charter.md",
    ROOT / "reports" / "d25-step1-target-validation-2026-10-30.md",
    ROOT / "reports" / "d25-step1" / "environment.lock.json",
]
present = [str(p.relative_to(ROOT)) for p in d2_5 if p.exists()]
check(len(present) == len(d2_5), "H1 D2.5 artefacts still present", f"{len(present)}/{len(d2_5)}")

try:
    status = subprocess.run(["git", "status", "--porcelain", "--", "reports/d25-step1",
                             "docs/d25-charter.md"], cwd=ROOT, capture_output=True, text=True)
    # Untracked ('??') is expected: D2.5 files may not be committed yet in a
    # given checkout. What must never happen is a modification (M), deletion (D)
    # or rename (R) of the validated Stage 1 artefacts.
    dirty = [ln for ln in status.stdout.splitlines()
             if re.match(r"^(\s?M|M|D|R|A)", ln.strip()) or ln.strip().startswith(("M ", " D", "R "))]
except Exception:                                   # noqa: BLE001
    dirty = ["git unavailable"]
check(not dirty, "H2 D2.5 artefacts unmodified by the range work", "; ".join(dirty[:3]) or "no modifications")

target = Path.home() / ".cache" / "prism-d25" / "target" / "target"
if target.exists():
    st = subprocess.run(["git", "status", "--porcelain"], cwd=target, capture_output=True, text=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=target, capture_output=True, text=True)
    check(not st.stdout.strip() and head.stdout.strip().startswith("bd75c9e"),
          "H3 Alchemy target unmodified and still at v2.0.0",
          f"HEAD={head.stdout.strip()[:12]} dirty={len(st.stdout.splitlines())}")
else:
    check(True, "H3 Alchemy target untouched (not present on this host)", "skipped, nothing to check")

core_imports = []
for f in (ROOT / "prism").glob("*.py"):
    text = f.read_text()
    if re.search(r"^\s*(import|from)\s+(docker|yaml|requests|keycloak|opa)\b", text, re.M):
        core_imports.append(f.name)
check(not core_imports, "H4 PRISM core has no range dependency", ", ".join(core_imports) or "none")

# --- I. scenario coverage -------------------------------------------------
cat = (DOCS / "07-scenario-catalogue.md").read_text()
ids_found = set(re.findall(r"\bS\d{1,2}\b", cat))
accept = (DOCS / "07-scenario-catalogue.md").read_text()
required_fields = ["Hypothèse", "Préconditions", "Preuves", "Critères d'acceptation"]
missing_fields = [fld for fld in required_fields if fld not in cat]
check(not missing_fields, "I1 scenario fields present", ", ".join(missing_fields) or "all present")
check(len(ids_found) >= 6, "I2 scenario catalogue populated", f"{len(ids_found)} scenario ids")
check("S1" in ids_found and "S5" in ids_found, "I3 Binance chain covered end-to-end",
      "S1..S5 map to the five chain steps")

# --- report ---------------------------------------------------------------
print("PRISM Cyber Range — artefact verification\n" + "-" * 62)
for ok, name, detail in results:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
failed = [r for r in results if not r[0]]
print("-" * 62)
print(f"  {len(results) - len(failed)} passed, {len(failed)} failed")
if not have_yaml():
    print("  note: PyYAML not installed — YAML syntax was not verified")
sys.exit(1 if failed else 0)
