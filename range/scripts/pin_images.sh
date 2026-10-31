#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PRISM Cyber Range — resolve image tags to digests
#
# A tag is not a pin. This script turns every tagged image in the compose /
# manifest set into an immutable reference and writes the digest into
# range/versions.lock.json as "image_digest". The resulting diff must be
# reviewed and committed: from then on, that diff IS the version lock.
#
# Requires a host with registry access and either:
#   * docker   (docker manifest inspect / docker pull), or
#   * skopeo   (skopeo inspect --format '{{.Digest}}')
#
# Nothing is mutated unless --write is passed.
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOCK="$ROOT/range/versions.lock.json"
WRITE=0
[ "${1:-}" = "--write" ] && WRITE=1

tool=""
if command -v skopeo >/dev/null 2>&1; then tool="skopeo"
elif command -v docker >/dev/null 2>&1; then tool="docker"
else
  echo "PINNING IMPOSSIBLE: neither skopeo nor docker is available on this host." >&2
  echo "  This is expected on a design-only host; run it on the build host (docs/cyber-range/05-installation.md §3)." >&2
  exit 3
fi
echo "using $tool"

python3 - "$LOCK" "$tool" "$WRITE" <<'PY'
import json, subprocess, sys

lock_path, tool, write = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
lock = json.load(open(lock_path))

# image references this lock cares about (component id -> image ref)
REFS = {
    "idp-keycloak":            "keycloak/keycloak:26.8.1",
    "idp-authelia":            "authelia/authelia:4.39.28",
    "pki-stepca":              "smallstep/step-ca:0.30.2",
    "secrets-openbao":         "openbao/openbao:2.7.2",
    "ci-gitea":                "gitea/gitea:28.2.0",
    "ci-woodpecker":           "woodpeckerci/woodpecker-server:3.20.1",
    "registry-docker-registry":"registry:2",
    "obs-suricata":            "jasonish/suricata:8.0.8",
    "obs-zeek":                "zeek/zeek:9.0.1",
    "obs-falco":               "falcosecurity/falco:0.85.1",
    "obs-osquery":             "osquery/osquery:5.24.0",
    "obs-loki":                "grafana/loki:3.7.9",
    "obs-grafana":             "grafana/grafana:13.3.0",
    "obs-prometheus":          "prom/prometheus:v3.15.1",
    "obs-alloy":               "grafana/alloy:v1.21.3",
    "dfir-velociraptor":       "velocidex/velociraptor:v0.77.3",
    "chain-anvil":             "ghcr.io/foundry-rs/foundry:stable",
    "chain-bundler":           "ghcr.io/pimlicolabs/alto:0.0.19",
}

def digest(ref: str) -> str | None:
    try:
        if tool == "skopeo":
            out = subprocess.run(["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{ref}"],
                                 capture_output=True, text=True, timeout=120)
        else:
            out = subprocess.run(["docker", "manifest", "inspect", "--verbose", ref],
                                 capture_output=True, text=True, timeout=120)
            if out.returncode == 0:
                data = json.loads(out.stdout)
                d = data.get("Descriptor", {}).get("digest") or (data.get("manifests") or [{}])[0].get("digest")
                return d
        d = out.stdout.strip()
        return d if d.startswith("sha256:") else None
    except Exception:
        return None

resolved, failed = {}, []
for cid, ref in REFS.items():
    d = digest(ref)
    if d:
        resolved[cid] = {"image": ref, "digest": d}
        print(f"  {cid:26s} {ref:38s} {d}")
    else:
        failed.append(f"{cid} ({ref})")
        print(f"  {cid:26s} {ref:38s} UNRESOLVED")

if failed:
    print("\nUNRESOLVED images (no digest written for them):")
    for f in failed:
        print("  -", f)
if write and resolved:
    for c in lock["components"]:
        if c["id"] in resolved:
            c["image"] = resolved[c["id"]]["image"]
            c["image_digest"] = resolved[c["id"]]["digest"]
            c.pop("pin_confidence", None)
    json.dump(lock, open(lock_path, "w"), indent=2)
    open(lock_path, "a").write("\n")
    print(f"\nwrote {len(resolved)} digests to {lock_path} — REVIEW `git diff` BEFORE COMMITTING")
elif resolved:
    print("\n(dry run: pass --write to persist digests)")
sys.exit(1 if failed else 0)
PY
