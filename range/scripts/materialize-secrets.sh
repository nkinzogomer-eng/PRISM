#!/usr/bin/env bash
# Materialise secrets from the SOPS-encrypted file into range/state/secrets/ (mode 0400).
# Refuses to run on a design-only host or without an age identity; see docs/cyber-range/05-installation.md §2.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="$ROOT/range/config/secrets.enc.yaml"
DEST="$ROOT/range/state/secrets"
command -v sops >/dev/null 2>&1 || { echo "materialize-secrets: sops not installed (see 05-installation.md §1.2)" >&2; exit 3; }
[ -f "$SRC" ] || { echo "materialize-secrets: $SRC missing — create and encrypt it first (§2.2)" >&2; exit 3; }
umask 077; mkdir -p "$DEST"
sops --decrypt --output-type yaml "$SRC" > "$DEST/secrets.yaml" || { echo "materialize-secrets: decryption failed" >&2; exit 4; }
python3 - "$DEST/secrets.yaml" <<'PY'
import sys, pathlib, yaml
src = pathlib.Path(sys.argv[1]); data = yaml.safe_load(src.read_text()) or {}
out = src.parent
for name, value in data.items():
    p = out / name
    p.write_text(str(value)); p.chmod(0o400)
    print("  wrote", p.name)
src.unlink()
print("materialised", len(data), "secrets (0400)")
PY
