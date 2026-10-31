# 10 — AETHERION interface contract (range control plane, v1)

Status: **implemented and exercised** on 2026-10-31 (see
`range/reports/2026-10-31-delivery2-range-operational.md`).
Implementation: `range/lab/labd.py` (server), `range/lab/ctl.py` (client).

This document is the contract between the range and an orchestrator
(AETHERION / CIEL). It is deliberately independent of CIEL and PRISM
internals: nothing here requires a change in either repository.

---

## 1. Transport

* Endpoint: UNIX stream socket at `$RANGE_STATE_DIR/control.sock`
  (default `range/state/control.sock`), mode `0600`, owned by the operator.
* Why a UNIX socket: the lab lives inside a private user + network
  namespace. A UNIX socket is a filesystem object, so the host can call it
  while the lab remains unreachable from the network — including from the
  zones themselves.
* Protocol: HTTP/1.1, `Content-Type: application/json`, one request per
  connection (`Connection: close` is honoured).
* Versioning: every path starts with `/v1`. Breaking changes require `/v2`;
  additive fields may appear in any response and must be ignored by clients.
* Errors: HTTP `4xx`/`5xx` with `{"error": "...", "detail": ...}`. An
  unreachable socket raises `cannot reach labd` in `ctl.py`.

## 2. Lifecycle

| Method | Path | Body | Effect |
| --- | --- | --- | --- |
| POST | `/v1/up` | – | build fabric, start 13 services + Anvil, wait for health |
| POST | `/v1/down` | – | destroy every namespace, stop every process |
| POST | `/v1/reset` | – | `down` + wipe runtime state (DB, evidence, secrets, flags) + `up` |
| GET | `/v1/health` | – | `{"ok": true, "api": "v1", "state": "up|down"}` |

`up` is idempotent: when the lab is already up it returns the current health
summary instead of rebuilding.

## 3. Scenarios

| Method | Path | Body | Effect |
| --- | --- | --- | --- |
| GET | `/v1/scenarios` | – | list scenarios with title, complexity, zones |
| POST | `/v1/scenarios/{id}/run` | – | restore data snapshot, execute, seal evidence |

`id` ∈ `S1 S2 S3 S4 S5 S6 S7`. Response:

```json
{
  "id": "S6", "title": "...", "complexity": "unknown-cause",
  "verdict": "attack_possible | blocked | protected | inconclusive",
  "run_id": "run-20261031T115908Z",
  "parts": [{"zone": "corp", "part": "S6", "verdict": "...",
             "steps": [...], "proofs": [...], "needs": [...]}],
  "seconds": 0.31,
  "evidence": "range/state/evidence/run-.../S6-1793447948"
}
```

Verdict semantics:

| Verdict | Meaning |
| --- | --- |
| `attack_possible` | the security property is violated; `proofs` are checkable |
| `blocked` | the attack failed (fixed, or not exploitable at all) |
| `protected` | control scenario: the protective mechanism was demonstrated |
| `inconclusive` | the scenario could not decide (state, missing tool, error) |

`parts[].role == "setup"` marks preparatory steps that are expected to
succeed and do not decide the verdict.

## 4. Observations

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/v1/status` | state, run id, uptime, component table (operational/partial/simulated/documented), scenario list, active fixes, notes, last runs |
| GET | `/v1/topology` | zones + `/32` + CIDR, declared links, declared matrix, kernel-observed reachable addresses, HSM neighbours |
| GET | `/v1/isolation` | 9×9 active sweep: declared vs observed, `mismatches`, `consistent` |
| GET | `/v1/egress` | 9 zones × 3 Internet targets; `leaks` must be empty |
| GET | `/v1/metrics` | per-service pid/alive/RSS, totals, disk usage, host load/memory |
| GET | `/v1/evidence` | runs recorded in this process, evidence root |
| GET | `/v1/notes` | supervisor warnings (e.g. "anvil not found") |

## 5. Mitigations

| Method | Path | Body | Effect |
| --- | --- | --- | --- |
| POST | `/v1/fix/{flag}` | `{"enable": true|false}` | set/clear one mitigation flag |

Flags and the scenario each one neutralises:
`session_binding` (S1), `gateway_sign_only_authz` (S2), `wallet_atomic` (S3),
`dmz_port_isolation` (S4), `gateway_debug_header` (S6),
plus `tx_internal_disabled` and `secrets_scope_per_name` for targeted probing.

Flags are runtime state: they are cleared by `reset`, and they never modify
source files. Blue-team "fixes" therefore stay reversible and attributable.

## 6. Independent verification

| Method | Path | Effect |
| --- | --- | --- |
| POST | `/v1/verify` | re-runs S2, S3, S4 twice each and compares verdicts; returns `stable: true|false` |

The verifier role is expected to use `/v1/isolation`, `/v1/egress`,
`/v1/scenarios/{id}/run` and the sealed evidence directories rather than
trusting the red team's narrative.

## 7. Evidence format

`range/state/evidence/<run_id>/<scenario>-<epoch>/` contains:

* `scenario.json` — full result: verdict, steps, proofs, needs, timing, zone;
* `alerts.jsonl` — alerts produced by the collector during the run;
* `SHA256SUMS` — integrity manifest (`sha256sum -c SHA256SUMS`).

`reset` destroys the evidence tree; export it before resetting. The
acceptance run's exports are in `range/reports/artifacts/`.

## 8. What the interface deliberately does **not** offer

* No shell, no arbitrary command execution, no file read: the only actions are
  the ones enumerated above. Free-form access is how a range escapes its
  perimeter.
* No Internet egress and no route between zones is configurable at runtime;
  topology changes require a code change and a rebuild.
* No credentials are transported: service secrets stay inside
  `range/state/secrets` (0400) and are read by the services themselves.

## 9. Client example

```python
import socket, json

def rpc(method, path, body=None):
    raw = json.dumps(body or {}).encode()
    req = (f"{method} {path} HTTP/1.1\r\nHost: labd\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n"
           "Connection: close\r\n\r\n").encode() + raw
    s = socket.socket(socket.AF_UNIX); s.connect("range/state/control.sock")
    s.sendall(req); buf = b""
    while chunk := s.recv(65536):
        buf += chunk
    s.close()
    return json.loads(buf.split(b"\r\n\r\n", 1)[1])
```

Equivalent CLI: `./range/lab/ctl.py {up|down|reset|status|topology|metrics|
scenarios|run <id>|fix <flag> [off]|verify|isolation|egress|evidence|raw}`.
