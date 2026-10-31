#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PRISM / AETHERION Cyber Range — lifecycle wrapper
#
#   ./range/lab/run.sh start     start the supervisor (inside a private userns)
#   ./range/lab/run.sh stop      stop the supervisor and destroy all zones
#   ./range/lab/run.sh logs      tail the supervisor log
#
# Why unshare: the lab needs its own network namespaces. This host has no
# container runtime, so the fabric is built with unprivileged user namespaces
# (`unshare -Urmn --map-root-user`), which the kernel permits here.
# ---------------------------------------------------------------------------
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RANGE_DIR="$(dirname "$HERE")"
STATE="${RANGE_STATE_DIR:-$RANGE_DIR/state}"
LOG="$STATE/labd.out"
mkdir -p "$STATE"

case "${1:-}" in
  start)
    if [ -S "$STATE/control.sock" ] && [ -f "$STATE/labd.pid" ] && kill -0 "$(cat "$STATE/labd.pid")" 2>/dev/null; then
      echo "already running (pid $(cat "$STATE/labd.pid"))"; exit 0
    fi
    rm -f "$STATE/control.sock" "$STATE/labd.pid"
    echo "starting labd ..."
    nohup unshare -Urmn --map-root-user -- bash -c \
      "cd '$RANGE_DIR' && exec python3 -m lab.labd serve" >>"$LOG" 2>&1 &
    for _ in $(seq 1 40); do
      [ -S "$STATE/control.sock" ] && { echo "labd is up"; exit 0; }
      sleep 0.25
    done
    echo "labd did not start; last output:"; tail -20 "$LOG"; exit 1
    ;;
  stop)
    if [ -f "$STATE/labd.pid" ]; then
      pid="$(cat "$STATE/labd.pid")"
      kill "$pid" 2>/dev/null && echo "sent SIGTERM to labd ($pid)"
      for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.3; done
      kill -9 "$pid" 2>/dev/null
      rm -f "$STATE/labd.pid" "$STATE/control.sock"
    fi
    # bracket trick: the pattern must not match this script's own command line
    pkill -f "python3 -m [l]ab\.services" 2>/dev/null
    pkill -f "[u]nshare -n sleep" 2>/dev/null
    pkill -f "[a]nvil --host 10.40.2.10" 2>/dev/null
    echo "lab stopped"
    ;;
  logs)
    tail -f "$LOG"
    ;;
  *)
    sed -n '2,12p' "$0"; exit 2
    ;;
esac
