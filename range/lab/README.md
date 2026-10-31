# AETHERION Cyber Range — operational lab (`range/lab`)

A self-contained, **kernel-isolated** cyber range that hosts the AETHERION
reference chain (identity → gateway → policy → wallet → signer → HSM →
relayer → chain) and exposes a versioned control API for orchestration.

It runs **without containers, without root-owned daemons, and without
Internet access**. Isolation is built from Linux network namespaces and veth
pairs only.

```
./range/lab/run.sh start          # start the supervisor (private userns)
./range/lab/ctl.py up             # build the fabric + start 13 services + Anvil
./range/lab/ctl.py status         # components, scenarios, flags
./range/lab/ctl.py topology       # zones, links, declared matrix
./range/lab/ctl.py raw GET /v1/isolation   # 9x9 active reachability proof
./range/lab/ctl.py run S2         # execute one scenario
./range/lab/ctl.py reset          # destroy everything and rebuild
./range/lab/run.sh stop           # emergency stop / teardown
python3 range/lab/campaign.py     # full acceptance campaign (7 steps, ~20 s)
```

Everything above was executed on the host described in
`range/reports/2026-10-31-delivery2-range-operational.md`.

---

## 1. Why namespaces and not containers

The evaluation host has **no container runtime** (no Docker, no Podman, no
Kubernetes, no KVM). It does, however, allow unprivileged user namespaces.
The fabric is therefore built inside a single

```
unshare -Urmn --map-root-user
```

process tree: mount + user + **network** namespace. Inside it, each zone is an
`unshare -n sleep 86400` anchor process; `nsenter -t <pid> -n` enters it.

Consequences that matter operationally:

* `ip netns add` **does not work** here (`/run/netns` is unwritable even as
  mapped root) — anchors are used instead. Never add `ip netns` calls.
* The fabric only exists while the supervisor's `unshare` process tree lives.
  Killing the supervisor destroys every zone, interface and route: this is the
  emergency stop.
* The supervisor (`labd`) itself has **no route to any zone**. It only drives
  namespaces (`nsenter`) and answers on a UNIX socket, which is a filesystem
  object and therefore reachable from the host.

---

## 2. Layout

| Path | Role |
| --- | --- |
| `netlab.py` | zone table, allow-matrix, `Fabric` (build/spawn/destroy/routes) |
| `common.py` | log bus, HS256 JWT, RFC-6238 TOTP, SQLite schema + migrations, HTTP framework |
| `services.py` | the 13 services (`python3 -m lab.services <name>`) |
| `scenarios.py` | the 7 executable scenarios (run *inside* a zone) |
| `labd.py` | supervisor + control plane (AETHERION API v1 over UNIX socket) |
| `ctl.py` | host-side client for the control plane |
| `campaign.py` | full acceptance campaign, writes a JSON report |
| `run.sh` | lifecycle wrapper (`start` / `stop` / `logs`) |
| `tools/install-anvil.sh` | installs the pinned Anvil 1.7.1 into `range/state/tools` |

Runtime state is written under `range/state/` (git-ignored):
`lab-config.json`, `secrets/`, `lab.db`, `logs/`, `evidence/`, `reports/`,
`control.sock`, `tools/anvil`.

---

## 3. Zones and services

Canonical `/32` addresses live on `lo` inside each zone; links are `/30` veth
pairs, one per allowed direction, and each side installs **exactly one route**
to its peer's `/32`.

| Zone | Address | Services |
| --- | --- | --- |
| `wan` | 10.10.0.2 | decoy (sink for exfiltration attempts) |
| `dmz` | 10.60.0.10 | dmz proxy (facing `wan` and `corp`) |
| `edge` | 10.20.0.10 | idp:8080, secrets:8090 |
| `corp` | 10.30.0.10 | ci:8081 |
| `prod` | 10.40.0.10 | gateway:8080, tx:8081, wallet:8082, policy:8083 |
| `signer` | 10.40.3.10 | signer:8084 |
| `hsm` | 10.40.1.10 | hsm:8085 |
| `chain` | 10.40.2.10 | relayer:8086, Anvil:8545 |
| `mon` | 10.50.0.10 | collector/alerts:9090 (strict leaf) |

12 links: `wan–dmz`, `dmz–corp`, `dmz–prod`, `dmz–mon`, `corp–edge`, `corp–mon`,
`edge–prod`, `edge–mon`, `prod–signer`, `prod–chain`, `prod–mon`, `signer–hsm`.

Invariants (verified, not asserted — see `/v1/isolation`):

* `hsm` has exactly **one** neighbour (`signer`); nothing else can reach it.
* `mon` is a strict leaf: it can pull telemetry but cannot be reached from
  outside its four links.
* `wan` touches only `dmz`; there is **no default route** in any zone, so no
  packet can leave the host.

---

## 4. Scenarios

| ID | Name | Zone(s) | Complexity | Baseline |
| --- | --- | --- | --- | --- |
| S1 | Session replay across zones | corp → wan | medium | exploitable |
| S2 | Over-broad CI scope → production signature | corp → dmz → prod | high | exploitable |
| S3 | Wallet double-spend race | edge → prod | high | exploitable |
| S4 | DMZ lateral reach to internal ports | dmz → prod | medium | exploitable |
| S5 | HSM isolation + key attributes | prod, signer | control | protected |
| S6 | **Undisclosed cause**: actor spoofing via debug header | corp → dmz → prod | cause not published | exploitable |
| S7 | End-to-end chain settlement | prod → chain | control | protected |

Each scenario starts from the same data snapshot (`reset_data()`: balances,
ledger, velocity window, key revocation) so runs are comparable.

### Mitigations (one flag each, applied through `ctl.py fix <name>`)

| Fix flag | Scenario | Effect |
| --- | --- | --- |
| `session_binding` | S1 | session pinned to the zone that first used it |
| `gateway_sign_only_authz` | S2 | `/v1/sign-only` requires `sign:execute` |
| `wallet_atomic` | S3 | atomic SQL debit instead of read-check-write |
| `dmz_port_isolation` | S4 | internal endpoints accept prod-origin only |
| `gateway_debug_header` | S6 | `X-Debug-Actor` ignored and logged |

---

## 5. Deliberate fixtures

Documented, versioned weaknesses (this is a range, not a product):

| ID | Where | Weakness |
| --- | --- | --- |
| W-GW-1 | gateway `/v1/sign-only` | authenticates, never authorizes |
| W-GW-2 | gateway `/v1/transfer` | `X-Debug-Actor` overrides the authenticated actor |
| W-TX-1 | tx `/internal/transfer` | bypasses the policy engine entirely |
| W-WAL-1 | wallet `/debit` | read-check-write with a real 150 ms window |
| W-SEC-1 | secrets | one coarse `secrets:read` scope unlocks every secret |
| W-HSM-1 | hsm | `CKA_EXTRACTABLE=false` emulated in application code |

S6 is intentionally **not** described to the agents under test: only its
existence and the log evidence are published.

---

## 6. Control plane (AETHERION API v1)

UNIX socket `range/state/control.sock`, mode `0600`, JSON over HTTP/1.1.
Full contract: `docs/cyber-range/10-aetherion-interface.md`.

```
GET  /v1/health      GET  /v1/status       GET  /v1/topology
GET  /v1/metrics     GET  /v1/scenarios    GET  /v1/evidence
GET  /v1/isolation   GET  /v1/egress       GET  /v1/notes
POST /v1/up          POST /v1/down         POST /v1/reset
POST /v1/scenarios/{id}/run
POST /v1/fix/{flag}          {"enable": true|false}
POST /v1/verify              (re-runs S2/S3/S4 twice, compares verdicts)
```

---

## 7. Limits

The honest list lives in section 6 of the delivery-2 report. Short version:
no packet-level filtering (no nftables/iptables in the user namespace), no
real HSM, no Kubernetes, no SIEM correlation, single-actor scale, and the
services are purpose-built Python rather than upstream products.
