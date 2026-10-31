#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PRISM Cyber Range — host capability preflight
#
# Answers one question: what is the largest range tier this host can host?
# It is read-only: nothing is installed, no packet is sent, no file outside
# /tmp is written.
#
# Tiers (defined in docs/cyber-range/04-resource-budget.md):
#   Tier A  "Analyst"   16 GB RAM / 8 vCPU / 200 GB   Compose, light SIEM
#   Tier B  "Lab"       32 GB RAM / 16 vCPU / 400 GB  + k3s, Falco, Zeek
#   Tier C  "Full"      64 GB RAM / 24 vCPU / 1 TB    + Wazuh, Velociraptor
#
# Exit codes: 0 = Tier B or better, 10 = Tier A only, 20 = cannot host a range
#             (design-only workspace), 2 = usage error.
# ---------------------------------------------------------------------------
set -uo pipefail

MIN_A=(8 16000 200)   # vcpu, MB ram, GB disk
MIN_B=(16 32000 400)
MIN_C=(24 64000 1000)

hr() { printf '%s\n' "---------------------------------------------------------------"; }
row() { printf '  %-26s %-24s %s\n' "$1" "$2" "$3"; }

VCPU=$(nproc 2>/dev/null || echo 0)
RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
DISK_GB=$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9')
: "${DISK_GB:=0}"

hr; echo "PRISM Cyber Range — preflight"; hr
echo "1. Compute"
row "vCPU" "$VCPU" ""
row "RAM" "${RAM_MB} MB" ""
row "Free disk (/)" "${DISK_GB} GB" ""
VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)
row "Virtualization" "$VIRT" ""
if [ -e /dev/kvm ]; then row "KVM" "available" "VM-per-zone is possible"; else row "KVM" "absent" "container-only layout"; fi

echo
echo "2. Container runtime"
RUNTIME=""
for c in docker podman nerdctl; do
  if command -v "$c" >/dev/null 2>&1; then
    ver=$("$c" --version 2>/dev/null | head -1)
    row "$c" "present" "$ver"
    [ -z "$RUNTIME" ] && RUNTIME="$c"
  else
    row "$c" "absent" ""
  fi
done
if [ -n "$RUNTIME" ]; then
  if "$RUNTIME" info >/dev/null 2>&1; then row "daemon/socket" "reachable" "can start containers"; else row "daemon/socket" "NOT reachable" "installed but not usable"; RUNTIME=""; fi
else
  row "usable runtime" "NONE" "layers L1+ cannot run here"
fi

echo
echo "3. Orchestration and tooling"
for t in kubectl helm k3s ansible opentofu terraform jq python3 openssl git nft iptables; do
  if command -v "$t" >/dev/null 2>&1; then row "$t" "present" "$(command -v "$t")"; else row "$t" "absent" ""; fi
done

echo
echo "4. Isolation prerequisites"
if command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1; then
  row "packet filter" "present" "egress lockdown enforceable"
else
  row "packet filter" "ABSENT" "cannot enforce the no-egress invariant"
fi
if [ "$(id -u)" -eq 0 ]; then row "privileges" "root" "can bind privileged ports"; else row "privileges" "unprivileged" "rootless or sudo required"; fi
if [ -r /etc/ssl/certs/ca-certificates.crt ]; then row "system CA bundle" "present" ""; fi

echo
echo "5. Verdict"
if [ "$VCPU" -ge "${MIN_C[0]}" ] && [ "$RAM_MB" -ge "${MIN_C[1]}" ] && [ "$DISK_GB" -ge "${MIN_C[2]}" ] && [ -n "$RUNTIME" ]; then
  TIER="C"; WHY="meets Tier C minimums and has a working runtime"
elif [ "$VCPU" -ge "${MIN_B[0]}" ] && [ "$RAM_MB" -ge "${MIN_B[1]}" ] && [ "$DISK_GB" -ge "${MIN_B[2]}" ] && [ -n "$RUNTIME" ]; then
  TIER="B"; WHY="meets Tier B minimums and has a working runtime"
elif [ "$VCPU" -ge "${MIN_A[0]}" ] && [ "$RAM_MB" -ge "${MIN_A[1]}" ] && [ "$DISK_GB" -ge "${MIN_A[2]}" ] && [ -n "$RUNTIME" ]; then
  TIER="A"; WHY="meets Tier A minimums and has a working runtime"
else
  TIER="none"
  WHY="fails at least one hard requirement"
  [ -z "$RUNTIME" ] && WHY="$WHY (no usable container runtime)"
  [ "$RAM_MB" -lt "${MIN_A[1]}" ] && WHY="$WHY (RAM ${RAM_MB} MB < ${MIN_A[1]} MB)"
  [ "$VCPU" -lt "${MIN_A[0]}" ] && WHY="$WHY (vCPU ${VCPU} < ${MIN_A[0]})"
  [ "$DISK_GB" -lt "${MIN_A[2]}" ] && WHY="$WHY (disk ${DISK_GB} GB < ${MIN_A[2]} GB)"
fi
row "supported tier" "$TIER" "$WHY"
echo "RANGE_TIER=$TIER"   # machine-readable, consumed by build.sh

case "$TIER" in
  C|B) echo "  => range build may proceed: ./range/scripts/build.sh --tier $TIER"; exit 0 ;;
  A)   echo "  => Tier A only: expect no Kubernetes findings and reduced telemetry"; exit 10 ;;
  *)   echo "  => design-only: this host cannot run layers L1-L7."
       echo "     Use it for authoring/validation of artefacts, and run the build on a Tier A+ host."
       exit 20 ;;
esac
