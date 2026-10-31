#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PRISM Cyber Range — build entry point (scaffold with guards)
#
# This script exists now so that the guards are real and testable before any
# layer is built. It deliberately refuses to do anything clever: it validates
# the host, checks the invariants that can be checked without a runtime, and
# stops with a precise message.
#
# Usage: ./range/scripts/build.sh --tier A|B|C [--dry-run]
# ---------------------------------------------------------------------------
set -uo pipefail

TIER=""; DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) TIER="${2:-}"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RANGE="$ROOT/range"
LOG_DIR="$RANGE/state/logs"
mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$LOG_DIR/build-$STAMP.log"
exec > >(tee -a "$LOG") 2>&1

say() { printf '%s\n' "$*"; }
fail() { printf 'BUILD REFUSED: %s\n' "$*" >&2; exit 1; }

say "PRISM Cyber Range build — $(date -u +%FT%TZ)"
say "tier requested: ${TIER:-<none>}   dry-run: $DRY   log: $LOG"
case "$TIER" in A|B|C) ;; *) fail "--tier A|B|C is required" ;; esac

# --- guard 1: host capability ---------------------------------------------
say "[1/6] host capability"
set +e
"$RANGE/scripts/preflight.sh" > "$LOG_DIR/preflight-$STAMP.log" 2>&1
PRC=$?
set -e
HOST_TIER="$(sed -n 's/^RANGE_TIER=//p' "$LOG_DIR/preflight-$STAMP.log" | tail -1)"
case "$PRC" in
  0|10) say "  host supports Tier: ${HOST_TIER:-unknown}" ;;
  20)   fail "host cannot run the range (see $LOG_DIR/preflight-$STAMP.log); design-only host" ;;
  *)    fail "preflight returned unexpected status $PRC" ;;
esac
rank() { case "$1" in A) echo 1 ;; B) echo 2 ;; C) echo 3 ;; *) echo 0 ;; esac; }
[ "$(rank "$HOST_TIER")" -ge "$(rank "$TIER")" ] \
  || fail "requested Tier $TIER but this host supports Tier ${HOST_TIER:-none} only"

# --- guard 2: artefacts verified before anything runs ---------------------
say "[2/6] artefact consistency"
set +e
python3 "$RANGE/scripts/verify_artifacts.py" > "$LOG_DIR/verify-$STAMP.log" 2>&1
VRC=$?
set -e
[ "$VRC" -eq 0 ] || fail "artefact verification failed (see $LOG_DIR/verify-$STAMP.log)"
say "  artefacts consistent"

# --- guard 3: no plaintext secret in the tree ----------------------------
say "[3/6] secret hygiene"
if git -C "$ROOT" grep -qE -- 'BEGIN [A-Z ]*PRIVATE KEY|AGE-SECRET-KEY' -- range/ 2>/dev/null; then
  fail "a key material pattern is present under range/"
fi
say "  no key material found"

# --- guard 4: images must be digest-pinned ---------------------------------
say "[4/6] image pinning"
UNPINNED=$(python3 - "$RANGE/versions.lock.json" <<'PY'
import json,sys
lock=json.load(open(sys.argv[1]))
missing=[c["id"] for c in lock["components"]
         if c.get("image_digest") in (None,"")
         and c["layer"] in {"L1","L2","L3","L4","L6","L7"}
         and c["id"] not in {"hsm-softhsm2","tool-tcpdump-tshark","os-host"}]
print("\n".join(missing))
PY
)
if [ -n "$UNPINNED" ]; then
  say "  components without a resolved image digest:"
  printf '    - %s\n' $UNPINNED
  fail "run ./range/scripts/pin_images.sh on a host with registry access, review the diff of versions.lock.json, then retry"
fi
say "  all runtime images digest-pinned"

# --- guard 5: isolation applied before services ----------------------------
say "[5/6] isolation"
if [ "$(id -u)" -ne 0 ]; then
  fail "nftables must be applied as root before any service starts (invariant I2)"
fi
if [ "$DRY" -eq 1 ]; then
  say "  dry-run: would apply $RANGE/network/nftables-range.nft"
else
  nft -f "$RANGE/network/nftables-range.nft" || fail "nftables ruleset rejected"
  say "  zone policy applied"
fi

# --- guard 6: nothing implemented yet -------------------------------------
say "[6/6] layer bring-up"
fail "layer bring-up is not implemented in this delivery (see docs/cyber-range/README.md §4 for the build order)"
