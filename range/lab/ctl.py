#!/usr/bin/env python3
"""
Host-side client for the range control plane (AETHERION interface v1).

Talks to <state>/control.sock — a filesystem object, so it works even though the
lab lives in a private network namespace.

  ./ctl.py up | down | reset | status | topology | metrics | scenarios
  ./ctl.py isolation | egress | verify | evidence
  ./ctl.py run S2 | fix wallet_atomic | verify | evidence | raw GET /v1/status
"""
from __future__ import annotations

import json
import os
import socket
import sys

STATE = os.environ.get("RANGE_STATE_DIR",
                       os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "state"))
SOCK = os.path.join(os.path.abspath(STATE), "control.sock")


def request(method: str, path: str, body: dict | None = None) -> dict:
    raw = json.dumps(body or {}).encode()
    req = (f"{method} {path} HTTP/1.1\r\nHost: labd\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
           "Connection: close\r\n\r\n").encode() + raw
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(300)
    try:
        s.connect(SOCK)
    except OSError as exc:
        raise SystemExit(f"cannot reach labd at {SOCK}: {exc}\n"
                         "start it with: ./range/lab/run.sh start")
    s.sendall(req)
    chunks = []
    while True:
        b = s.recv(65536)
        if not b:
            break
        chunks.append(b)
    s.close()
    data = b"".join(chunks)
    head, _, payload = data.partition(b"\r\n\r\n")
    status = head.split(b" ")[1:2]
    try:
        return {"status": int(status[0]) if status else 0, "body": json.loads(payload or b"{}")}
    except json.JSONDecodeError:
        return {"status": 0, "body": {"raw": payload[:400].decode(errors="replace")}}


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "raw":
        r = request(argv[2], argv[3] if len(argv) > 3 else "/v1/health")
        print(json.dumps(r["body"], indent=2))
        return 0
    routes = {
        "up": ("POST", "/v1/up"), "down": ("POST", "/v1/down"),
        "reset": ("POST", "/v1/reset"), "verify": ("POST", "/v1/verify"),
        "status": ("GET", "/v1/status"), "topology": ("GET", "/v1/topology"),
        "metrics": ("GET", "/v1/metrics"), "scenarios": ("GET", "/v1/scenarios"),
        "evidence": ("GET", "/v1/evidence"), "health": ("GET", "/v1/health"),
        "isolation": ("GET", "/v1/isolation"), "egress": ("GET", "/v1/egress"),
        "notes": ("GET", "/v1/notes"),
    }
    if cmd in routes:
        method, path = routes[cmd]
        r = request(method, path)
        print(json.dumps(r["body"], indent=2, default=str))
        return 0 if r["status"] < 400 else 1
    if cmd == "run" and len(argv) > 2:
        r = request("POST", f"/v1/scenarios/{argv[2]}/run")
        body = r["body"]
        print(json.dumps(body, indent=2, default=str))
        return 0 if body.get("verdict") else 1
    if cmd == "fix" and len(argv) > 2:
        enable = not (len(argv) > 3 and argv[3] == "off")
        r = request("POST", f"/v1/fix/{argv[2]}", {"enable": enable})
        print(json.dumps(r["body"], indent=2, default=str))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
