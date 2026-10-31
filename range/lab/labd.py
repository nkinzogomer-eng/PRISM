#!/usr/bin/env python3
"""
PRISM / AETHERION Cyber Range — supervisor and control plane.

Runs INSIDE `unshare -Urmn --map-root-user` (see run.sh). It owns the zone
namespaces, starts/stops the twelve services, executes scenarios, applies and
reverts mitigations, and answers the AETHERION interface over a UNIX socket.

The control socket is a filesystem object, so the host (where CIEL/PRISM run)
can talk to it even though the lab itself lives in a private network namespace.

  POST/GET  /v1/...            control plane, versioned (v1)
  sockets   <state>/control.sock
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler

from . import netlab
from .common import SECRETS, STATE, db, init_db, log_event

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
RANGE_DIR = os.path.dirname(LAB_DIR)
CFG_PATH = os.path.join(STATE, "lab-config.json")
PID_PATH = os.path.join(STATE, "labd.pid")
SOCK_PATH = os.path.join(STATE, "control.sock")

# zone placement of every service
PLACEMENT = {
    "idp": "edge", "secrets": "edge", "ci": "corp", "dmz": "dmz",
    "gateway": "prod", "tx": "prod", "wallet": "prod", "policy": "prod",
    "signer": "signer", "hsm": "hsm", "relayer": "chain",
    "mon": "mon", "decoy": "wan",
}

SCENARIO_PLAN = {
    "S1": {"title": "Session replay across zones", "complexity": "medium",
           "runs": [("corp", "S1a"), ("wan", "S1b")],
           "fix": "session_binding", "desc": "Bearer token minted in one zone accepted in another"},
    "S2": {"title": "Over-broad CI scope to production signature", "complexity": "high",
           "runs": [("corp", "S2")], "fix": "gateway_sign_only_authz",
           "desc": "Low-privilege CI identity obtains a signature with no policy decision"},
    "S3": {"title": "Wallet double spend race", "complexity": "high",
           "runs": [("edge", "S3")], "fix": "wallet_atomic",
           "desc": "Concurrent debits observe the same balance (read-check-write)"},
    "S4": {"title": "DMZ lateral reach to internal ports", "complexity": "medium",
           "runs": [("dmz", "S4")], "fix": "dmz_port_isolation",
           "desc": "DMZ host reaches transaction/sign endpoints directly"},
    "S5": {"title": "HSM isolation and key attributes", "complexity": "control", "kind": "control",
           "runs": [("prod", "S5a"), ("signer", "S5b")], "fix": None,
           "desc": "Kernel-enforced reachability plus CKA_EXTRACTABLE refusal"},
    "S6": {"title": "UNDISCLOSED: actor spoofing via debug header", "complexity": "unknown-cause",
           "runs": [("corp", "S6")], "fix": "gateway_debug_header",
           "desc": "Root cause not published: the verifier must rediscover it"},
    "S7": {"title": "End-to-end chain settlement (control)", "complexity": "control", "kind": "control",
           "runs": [("prod", "S7")], "fix": None,
           "desc": "policy -> wallet -> signer -> HSM -> relayer -> Anvil"},
}

COMPONENTS = [
    # id, layer, status, note
    ("netlab-fabric", "L0", "operational", "real Linux netns + veth, kernel-enforced matrix"),
    ("idp", "L1", "operational", "HS256 JWT, TOTP (RFC 6238), sessions, revocation"),
    ("secrets", "L1", "partial", "file-backed store with leases; no KMS/OpenBao"),
    ("ci", "L3", "partial", "real local pipeline; not Gitea/Woodpecker"),
    ("dmz", "L3", "operational", "HTTP proxy with real headers"),
    ("gateway", "L4", "operational", "JWT validation, scope checks, fixtures W-GW-1/2"),
    ("tx", "L4", "operational", "business logic, fixtures W-TX-1"),
    ("wallet", "L4", "operational", "SQLite ledger, real race window W-WAL-1"),
    ("policy", "L4", "partial", "Python re-implementation of tx.rego semantics"),
    ("signer", "L4", "operational", "ECDSA via openssl, calls HSM"),
    ("hsm", "L4", "simulated", "ECDSA key files + attribute checks; NOT PKCS#11 hardware"),
    ("relayer", "L5", "operational", "signature verify + replay dedupe + RPC submit"),
    ("anvil", "L5", "operational", "real EVM node from Foundry (npm), local only"),
    ("mon", "L6", "partial", "ingest + 9 alert rules; no SIEM correlation engine"),
    ("decoy", "L7", "simulated", "isolated sink for exfiltration attempts"),
    ("k8s/k3s", "L2", "documented", "not deployed: no runtime available on this host"),
    ("suricata/zeek", "L6", "documented", "not deployed: no packet capture, see limits"),
    ("softhsm2", "L4", "documented", "replaced by attribute-enforcing file key store"),
]


class Lab:
    def __init__(self) -> None:
        self.fabric: netlab.Fabric | None = None
        self.state = "down"
        self.started_at: float | None = None
        self.anvil: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.runs: list[dict] = []
        self.fixes: dict[str, bool] = {}
        self.notes: list[str] = []

    # --------------------------------------------------------------- config
    def cfg(self) -> dict:
        try:
            with open(CFG_PATH) as fh:
                return json.load(fh)
        except OSError:
            return {}

    def write_cfg(self, cfg: dict) -> None:
        tmp = CFG_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(cfg, fh, indent=2)
        os.replace(tmp, CFG_PATH)

    # ------------------------------------------------------------ bootstrap
    def bootstrap(self) -> dict:
        """Materialise secrets, keys, policy data and the service config."""
        for d in ("logs", "evidence", "secrets", "scenario-tmp", "ci"):
            os.makedirs(os.path.join(STATE, d), exist_ok=True)
        os.chmod(os.path.join(STATE, "secrets"), 0o700)

        def put(name: str, value: str) -> str:
            p = os.path.join(SECRETS, name)
            if not os.path.exists(p):
                with open(p, "w") as fh:
                    fh.write(value)
                os.chmod(p, 0o400)
            return p

        import secrets as pysecrets
        put("jwt.key", pysecrets.token_hex(32))
        put("ingest.token", pysecrets.token_hex(16))
        put("hsm-token", pysecrets.token_hex(24))
        put("signer-token", pysecrets.token_hex(24))
        put("db-password", pysecrets.token_hex(12))
        put("passwd-ops1", "ops1-lab-password")
        put("passwd-alice", "alice-lab-password")
        put("totp-ops1", pysecrets.token_hex(10))
        put("totp-alice", pysecrets.token_hex(10))

        urls = {
            "idp": "http://10.20.0.10:8080", "secrets": "http://10.20.0.10:8090",
            "ci": "http://10.30.0.10:8081", "dmz": "http://10.60.0.10:8080",
            "gateway": "http://10.40.0.10:8080", "tx": "http://10.40.0.10:8081",
            "wallet": "http://10.40.0.10:8082", "policy": "http://10.40.0.10:8083",
            "signer": "http://10.40.3.10:8084", "hsm": "http://10.40.1.10:8085",
            "relayer": "http://10.40.2.10:8086", "chain": "http://10.40.2.10:8545",
            "mon": "http://10.50.0.10:9090", "decoy": "http://10.10.0.2:9999",
        }
        clients = {
            "ci-runner": {"secret": pysecrets.token_hex(12),
                          "scope": "ci:run secrets:read transfer:write"},
            "tx-service": {"secret": pysecrets.token_hex(12),
                           "scope": "transfer:write chain:write"},
            "ops-console": {"secret": pysecrets.token_hex(12),
                            "scope": "read admin"},
        }
        cfg = self.cfg() or {}
        cfg.setdefault("urls", urls)
        cfg["ip_zones"] = {}
        cfg.setdefault("clients", clients)
        cfg.setdefault("session_ttl", 300)
        cfg.setdefault("lease_ttl", 120)
        cfg.setdefault("flags", {})
        cfg["run_id"] = cfg.get("run_id") or f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        self.write_cfg(cfg)

        init_db()
        conn = db()
        if not conn.execute("SELECT COUNT(*) c FROM balances").fetchone()["c"]:
            conn.execute("INSERT INTO balances(account,asset,amount) VALUES(?,?,?)",
                         ("acct-hot-1", "ETH", 100.0))
            conn.execute("INSERT INTO balances(account,asset,amount) VALUES(?,?,?)",
                         ("acct-cold-1", "ETH", 5000.0))
        conn.close()

        policy = {
            "limits": {"max_session_age_s": 600,
                       "absolute_ceiling": {"ETH": 1000, "USDT": 1000000},
                       "quorum_threshold": {"ETH": 100, "USDT": 250000},
                       "hourly_cap": {"ETH": 200, "USDT": 500000}},
            "destinations": {"ETH": [cfg.get("chain_to", "0x00000000000000000000000000000000000000aa"),
                                     "0xrace", "0xdemo-spoof", "0xchain-dest"],
                             "USDT": []},
            "revoked_keys": [],
        }
        with open(os.path.join(STATE, "policy-data.json"), "w") as fh:
            json.dump(policy, fh, indent=2)

        # key material: real EC keys on disk, 0400, registered with attributes
        kdir = os.path.join(SECRETS, "hsm")
        os.makedirs(kdir, exist_ok=True)
        keyfile = os.path.join(kdir, "signer-1.pem")
        conn = db()
        if not conn.execute("SELECT COUNT(*) c FROM keys").fetchone()["c"]:
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1",
                            "-genkey", "-noout", "-out", keyfile], check=True)
            os.chmod(keyfile, 0o400)
            conn.execute("INSERT INTO keys(key_id,path,extractable,revoked,created)"
                         " VALUES(?,?,?,?,?)", ("signer-1", keyfile, 0, 0, time.time()))
            conn.execute("INSERT INTO keys(key_id,path,extractable,revoked,created)"
                         " VALUES(?,?,?,?,?)", ("ops-key", keyfile, 0, 0, time.time()))
        conn.close()
        return {"run_id": cfg["run_id"], "urls": len(urls), "clients": len(clients)}

    # ------------------------------------------------------------------- up
    def up(self) -> dict:
        with self.lock:
            if self.state == "up":
                return {"ok": True, "state": "up", "note": "already running",
                        "chain": {"enabled": bool(self.cfg().get("chain_enabled"))},
                        "health": self.check_health_summary()}
            self.bootstrap()
            self.fabric = netlab.Fabric(state_dir=STATE)
            info = self.fabric.build()
            cfg = self.cfg()
            cfg["ip_zones"] = self.fabric.ip_zone_map()
            self.write_cfg(cfg)
            logdir = os.path.join(STATE, "logs")

            # collector first: everything else ships its log lines to it
            self.fabric.spawn("mon", "mon", [sys.executable, "-m", "lab.services", "mon"],
                              env={"RANGE_STATE_DIR": STATE}, log_path=os.path.join(logdir, "mon.out"))
            time.sleep(0.8)
            for name, zone in PLACEMENT.items():
                if name == "mon":
                    continue
                self.fabric.spawn(zone, name,
                                  [sys.executable, "-m", "lab.services", name],
                                  env={"RANGE_STATE_DIR": STATE,
                                       "RANGE_MON_URL": cfg["urls"]["mon"]},
                                  log_path=os.path.join(logdir, f"{name}.out"))
            chain = self.start_chain()

            self.state = "up"
            self.started_at = time.time()
            health = self.wait_health(seconds=25)
            return {"ok": health["healthy"] >= 8, "state": self.state,
                    "fabric": info, "chain": chain, "health": health,
                    "run_id": cfg.get("run_id")}

    def start_chain(self) -> dict:
        """Start a real Anvil node inside the chain zone and wire the relayer to it."""
        anvil = shutil.which("anvil") or os.path.join(RANGE_DIR, "state", "tools", "anvil")
        if not os.path.exists(anvil):
            self.notes.append("anvil binary not found: chain features disabled")
            return {"enabled": False, "reason": "anvil not installed"}
        anchor = self.fabric.anchors["chain"].pid
        self.anvil = subprocess.Popen(
            ["nsenter", "-t", str(anchor), "-n", "--", anvil,
             "--host", "10.40.2.10", "--port", "8545", "--chain-id", "31337",
             "--accounts", "4", "--block-time", "1"],
            stdout=open(os.path.join(STATE, "logs", "anvil.out"), "ab"),
            stderr=subprocess.STDOUT)
        time.sleep(2.5)
        code, accounts = self.chain_rpc("eth_accounts", [])
        accs = accounts.get("result") or []
        if not accs:
            return {"enabled": False, "reason": "anvil did not answer eth_accounts"}
        cfg = self.cfg()
        cfg["chain_enabled"] = True
        cfg["chain_from"] = accs[0]
        cfg["chain_to"] = accs[1]
        cfg["chain_value_wei"] = 10 ** 15
        self.write_cfg(cfg)
        policy_path = os.path.join(STATE, "policy-data.json")
        with open(policy_path) as fh:
            pol = json.load(fh)
        pol["destinations"]["ETH"] = sorted(set(pol["destinations"]["ETH"]) | {accs[1]})
        with open(policy_path, "w") as fh:
            json.dump(pol, fh, indent=2)
        return {"enabled": True, "accounts": len(accs), "from": accs[0], "to": accs[1]}

    def chain_rpc(self, method: str, params: list) -> tuple[int, dict]:
        """RPC must be issued *inside* the chain zone: labd itself has no routes
        to the zones by design (it only drives namespaces)."""
        if not self.fabric:
            return 0, {}
        anchor = self.fabric.anchors["chain"].pid
        script = (
            "import json,sys,urllib.request\n"
            "u=sys.argv[1]\n"
            "p=json.dumps({'jsonrpc':'2.0','id':1,'method':sys.argv[2],"
            "'params':json.loads(sys.argv[3])}).encode()\n"
            "r=urllib.request.urlopen(urllib.request.Request(u,p,"
            "{'Content-Type':'application/json'}),timeout=5)\n"
            "print(r.read().decode())\n")
        p = subprocess.run(["nsenter", "-t", str(anchor), "-n", "--", sys.executable,
                            "-c", script, self.cfg()["urls"]["chain"], method,
                            json.dumps(params)], capture_output=True, text=True)
        try:
            return 200, json.loads(p.stdout.strip().splitlines()[-1])
        except Exception:                              # noqa: BLE001
            return 0, {"error": (p.stderr or p.stdout)[-300:]}

    # ----------------------------------------------------------------- down
    def down(self) -> dict:
        with self.lock:
            if self.anvil and self.anvil.poll() is None:
                self.anvil.kill()
            self.anvil = None
            if self.fabric:
                self.fabric.destroy()
            self.fabric = None
            self.state = "down"
            return {"ok": True, "state": "down"}

    def reset(self) -> dict:
        """Destroy everything, wipe runtime state, rebuild from fixtures."""
        self.down()
        for name in ("lab.db", "lab.db-wal", "lab.db-shm"):
            try:
                os.remove(os.path.join(STATE, name))
            except OSError:
                pass
        for name in ("evidence", "logs", "ci", "scenario-tmp"):
            shutil.rmtree(os.path.join(STATE, name), ignore_errors=True)
        for name in ("jwt.key", "ingest.token", "hsm-token", "signer-token", "db-password"):
            try:
                os.remove(os.path.join(SECRETS, name))
            except OSError:
                pass
        shutil.rmtree(os.path.join(SECRETS, "hsm"), ignore_errors=True)
        cfg = self.cfg()
        cfg["flags"] = {}
        cfg["run_id"] = f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
        self.write_cfg(cfg)
        self.fixes.clear()
        return self.up()

    # --------------------------------------------------------------- health
    def wait_health(self, seconds: float = 20) -> dict:
        deadline = time.time() + seconds
        last: dict[str, bool] = {}
        while time.time() < deadline:
            last = self.check_health()
            if sum(last.values()) >= len(last) - 1:
                break
            time.sleep(0.7)
        return {"services": last, "healthy": sum(last.values()), "total": len(last)}

    def check_health_summary(self) -> dict:
        svc = self.check_health()
        return {"services": svc, "healthy": sum(svc.values()), "total": len(svc)}

    def check_health(self) -> dict[str, bool]:
        """Probe each service from inside its own zone namespace."""
        from . import netlab as nl
        out = {}
        cfg = self.cfg()
        for name, zone in PLACEMENT.items():
            if name == "decoy":
                health_url = cfg["urls"]["decoy"] + "/health"
            elif name == "relayer":
                health_url = cfg["urls"]["relayer"] + "/health"
            else:
                health_url = cfg["urls"][name] + "/health"
            code = self._probe(zone, health_url)
            out[name] = code == 200
        return out

    def _probe(self, zone: str, url: str) -> int:
        anchor = self.fabric.anchors[zone].pid if self.fabric else 0
        if not anchor:
            return 0
        py = ("import urllib.request,sys;"
              "r=urllib.request.urlopen(sys.argv[1],timeout=3);print(r.status)")
        p = subprocess.run(["nsenter", "-t", str(anchor), "-n", "--",
                            sys.executable, "-c", py, url],
                           capture_output=True, text=True)
        try:
            return int(p.stdout.strip().splitlines()[-1])
        except Exception:                              # noqa: BLE001
            return 0

    # ------------------------------------------------------------ scenarios
    def reset_data(self) -> dict:
        """Restore the *data* layer to its initial snapshot (balances, ledger,
        velocity window, key revocation) without touching the fabric.

        Every scenario therefore starts from the same known state — the
        equivalent of reverting a VM snapshot between experiments."""
        conn = db()
        conn.execute("DELETE FROM transfers")
        conn.execute("DELETE FROM ledger")
        conn.execute("DELETE FROM leases")
        conn.execute("UPDATE balances SET amount=100.0 WHERE account='acct-hot-1'")
        conn.execute("UPDATE balances SET amount=5000.0 WHERE account='acct-cold-1'")
        conn.execute("UPDATE keys SET revoked=0")
        conn.commit()
        conn.close()
        return {"ok": True}

    def run_scenario(self, sid: str) -> dict:
        plan = SCENARIO_PLAN.get(sid)
        if not plan:
            return {"error": "unknown scenario", "id": sid}
        if self.state != "up":
            return {"error": "lab is down", "id": sid}
        self.reset_data()
        result = {"id": sid, "title": plan["title"], "complexity": plan["complexity"],
                  "fix": plan["fix"], "run_id": self.cfg().get("run_id"),
                  "parts": [], "started": time.time()}
        for zone, part in plan["runs"]:
            result["parts"].append(self._run_part(zone, part))
        # A scenario may have setup parts (mint a token) that legitimately
        # succeed before the attack; only non-setup parts decide the verdict.
        judged = [p for p in result["parts"] if p.get("role") != "setup"] or result["parts"]
        verdicts = [p.get("verdict") for p in judged]
        if plan.get("kind") == "control":
            result["verdict"] = ("protected"
                                 if all(v in ("blocked", "control_ok") for v in verdicts)
                                 else "attack_possible")
        elif "attack_possible" in verdicts:
            result["verdict"] = "attack_possible"
        elif all(v == "blocked" for v in verdicts):
            result["verdict"] = "blocked"
        else:
            result["verdict"] = "inconclusive"
        result["seconds"] = round(time.time() - result["started"], 2)

        # evidence: one sealed directory per run
        run_dir = self._evidence_dir(result)
        result["evidence"] = run_dir
        self.runs.append({k: result[k] for k in ("id", "verdict", "seconds", "run_id")})
        return result

    def _zone_post(self, zone: str, url: str, payload: dict) -> tuple[int, dict]:
        script = ("import json,sys,urllib.request\n"
                  "r=urllib.request.urlopen(urllib.request.Request(sys.argv[1],"
                  "json.dumps(json.loads(sys.argv[2])).encode(),"
                  "{'Content-Type':'application/json'}),timeout=10)\n"
                  "print(r.read().decode())\n")
        anchor = self.fabric.anchors[zone].pid
        p = subprocess.run(["nsenter", "-t", str(anchor), "-n", "--", sys.executable,
                            "-c", script, url, json.dumps(payload)],
                           capture_output=True, text=True)
        try:
            return 200, json.loads(p.stdout.strip().splitlines()[-1])
        except Exception:                              # noqa: BLE001
            return 0, {"error": (p.stderr or p.stdout)[-200:]}

    def refill(self) -> dict:
        """Teller top-up between scenario runs (documented fixture procedure).

        Without it, funds-consuming scenarios would fail for lack of balance
        instead of for the reason under test."""
        code, r = self._zone_post("prod", self.cfg()["urls"]["wallet"] + "/credit",
                                  {"account": "acct-hot-1", "asset": "ETH",
                                   "amount": 200.0, "note": "teller refill"})
        return {"ok": code == 200, "credit": r if code == 200 else r}

    def _run_part(self, zone: str, part: str) -> dict:
        anchor = self.fabric.anchors[zone].pid
        p = subprocess.run(
            ["nsenter", "-t", str(anchor), "-n", "--", sys.executable, "-m",
             "lab.scenarios", part],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, "RANGE_STATE_DIR": STATE, "RANGE_ZONE": zone})
        line = next((ln for ln in p.stdout.splitlines()
                     if ln.startswith("SCENARIO_RESULT ")), None)
        if not line:
            return {"part": part, "zone": zone, "verdict": "inconclusive",
                    "error": (p.stderr or p.stdout)[-400:]}
        res = json.loads(line[len("SCENARIO_RESULT "):])
        res["zone"] = zone
        return res

    def _evidence_dir(self, result: dict) -> str:
        d = os.path.join(STATE, "evidence", result["run_id"],
                         f"{result['id']}-{int(result['started'])}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "scenario.json"), "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        # copy the alert tail and seal the directory
        alerts = os.path.join(STATE, "evidence", result["run_id"], "alerts.jsonl")
        if os.path.exists(alerts):
            shutil.copy(alerts, os.path.join(d, "alerts.jsonl"))
        manifest = []
        for f in sorted(os.listdir(d)):
            fp = os.path.join(d, f)
            if os.path.isfile(fp):
                out = subprocess.run(["sha256sum", f], cwd=d, capture_output=True, text=True)
                manifest.append(out.stdout.strip())
        with open(os.path.join(d, "SHA256SUMS"), "w") as fh:
            fh.write("\n".join(manifest) + "\n")
        return d

    # ------------------------------------------------------------- isolation
    def isolation_sweep(self) -> dict:
        """N x N active reachability sweep, run from inside every zone.

        A closed TCP port that is *routed* answers with RST (ECONNREFUSED);
        an unrouted destination fails with EHOSTUNREACH/ENETUNREACH or times
        out. That distinguishes "the kernel would deliver a packet" from
        "there is no path", without needing a listener in each zone.
        """
        if not self.fabric:
            return {"error": "lab is down"}
        script = (
            "import socket,sys,json\n"
            "ip=sys.argv[1]; port=int(sys.argv[2])\n"
            "s=socket.socket(); s.settimeout(1.5)\n"
            "try:\n"
            "    s.connect((ip,port)); print('open')\n"
            "except ConnectionRefusedError: print('routed')\n"
            "except OSError as e: print('unreachable:'+e.__class__.__name__)\n"
            "finally: s.close()\n")
        zones = list(netlab.ZONES)
        obs = {}
        for a in zones:
            anchor = self.fabric.anchors[a].pid
            row = {}
            for b in zones:
                if a == b:
                    row[b] = "self"
                    continue
                p = subprocess.run(["nsenter", "-t", str(anchor), "-n", "--",
                                    sys.executable, "-c", script,
                                    netlab.ZONES[b].ip, "7777"],
                                   capture_output=True, text=True, timeout=20)
                out = (p.stdout or p.stderr).strip().splitlines()
                row[b] = out[-1] if out else "unknown"
            obs[a] = row
        raw = self.fabric.allowed_matrix()
        declared: dict[str, list[str]] = {}
        for a in zones:
            v = raw.get(a, [])
            declared[a] = sorted({x for x in v if x in zones})
        mismatches = []
        for a in zones:
            for b in zones:
                if a == b:
                    continue
                want = b in declared[a]
                got = obs[a][b] in ("routed", "open")
                if want != got:
                    mismatches.append({"from": a, "to": b, "declared": want,
                                       "observed": obs[a][b]})
        return {"zones": zones, "declared": declared, "observed": obs,
                "mismatches": mismatches, "consistent": not mismatches,
                "pairs_checked": len(zones) * (len(zones) - 1),
                "links_declared": len(netlab.LINKS)}

    def egress_probe(self) -> dict:
        """No zone may reach the real Internet: there is no default route.

        Probes a few well-known addresses from every zone; a loopback-only
        fabric must fail all of them."""
        if not self.fabric:
            return {"error": "lab is down"}
        script = ("import socket,sys\n"
                  "targets=[('1.1.1.1',443),('8.8.8.8',53),('93.184.216.34',80)]\n"
                  "out={}\n"
                  "for t in targets:\n"
                  "    s=socket.socket(); s.settimeout(1.0)\n"
                  "    try:\n"
                  "        s.connect(t); out['%s:%d'%t]='CONNECTED'\n"
                  "    except OSError as e: out['%s:%d'%t]=type(e).__name__\n"
                  "    finally: s.close()\n"
                  "print(__import__('json').dumps(out))\n")
        res, leaks = {}, []
        for zone in netlab.ZONES:
            anchor = self.fabric.anchors[zone].pid
            p = subprocess.run(["nsenter", "-t", str(anchor), "-n", "--",
                                sys.executable, "-c", script],
                               capture_output=True, text=True, timeout=30)
            try:
                out = json.loads(p.stdout.strip().splitlines()[-1])
            except Exception:                          # noqa: BLE001
                out = {"error": (p.stderr or p.stdout)[-120:]}
            res[zone] = out
            leaks += [{"zone": zone, "target": t} for t, v in out.items()
                      if v == "CONNECTED"]
        return {"zones": len(res), "results": res, "leaks": leaks,
                "isolated": not leaks}

    # ---------------------------------------------------------------- fixes
    def apply_fix(self, name: str, enable: bool = True) -> dict:
        cfg = self.cfg()
        flags = cfg.setdefault("flags", {})
        mapping = {
            "wallet_atomic": {"wallet_atomic": True},
            "gateway_sign_only_authz": {"gateway_sign_only_authz": True},
            "gateway_debug_header": {"ignore_debug_header": True},
            "tx_internal_disabled": {"tx_internal_disabled": True},
            "secrets_scope_per_name": {"secrets_scope_per_name": True},
            "session_binding": {"require_mfa_zone_binding": True},
            "dmz_port_isolation": {"dmz_port_isolation": True},
        }
        if name not in mapping:
            return {"error": "unknown fix", "available": sorted(mapping)}
        for k, v in mapping[name].items():
            flags[k] = v if enable else False
        self.write_cfg(cfg)
        self.fixes[name] = enable
        log_event("labd", "fix_applied" if enable else "fix_reverted", fix=name)
        return {"ok": True, "fix": name, "enabled": enable, "flags": flags}

    # -------------------------------------------------------------- metrics
    def metrics(self) -> dict:
        rows, total = [], 0
        if self.fabric:
            for name, proc in self.fabric.services.items():
                rss = 0
                try:
                    with open(f"/proc/{proc.pid}/status") as fh:
                        for ln in fh:
                            if ln.startswith("VmRSS:"):
                                rss = int(ln.split()[1])
                except OSError:
                    pass
                total += rss
                rows.append({"service": name, "zone": PLACEMENT.get(name, "?"),
                             "pid": proc.pid, "alive": proc.poll() is None,
                             "rss_kb": rss})
        if self.anvil:
            rss = 0
            try:
                with open(f"/proc/{self.anvil.pid}/status") as fh:
                    for ln in fh:
                        if ln.startswith("VmRSS:"):
                            rss = int(ln.split()[1])
            except OSError:
                pass
            total += rss
            rows.append({"service": "anvil", "zone": "chain", "pid": self.anvil.pid,
                         "alive": self.anvil.poll() is None, "rss_kb": rss})

        def size(p: str) -> int:
            if not os.path.exists(p):
                return 0
            if os.path.isfile(p):
                return os.path.getsize(p)
            return sum(os.path.getsize(os.path.join(r, f))
                       for r, _, fs in os.walk(p) for f in fs)

        disk = {"state": size(STATE), "evidence": size(os.path.join(STATE, "evidence")),
                "logs": size(os.path.join(STATE, "logs")), "db": size(os.path.join(STATE, "lab.db"))}
        return {"services": rows, "rss_total_kb": total, "rss_total_mb": round(total / 1024, 1),
                "disk_bytes": disk, "uptime_s": round(time.time() - self.started_at, 1)
                if self.started_at else 0, "host": self._host_usage()}

    def _host_usage(self) -> dict:
        try:
            with open("/proc/loadavg") as fh:
                load = fh.read().split()[0]
            mem = {}
            with open("/proc/meminfo") as fh:
                for ln in fh:
                    k, v = ln.split(":", 1)
                    mem[k] = int(v.split()[0])
            return {"load1": float(load),
                    "mem_total_mb": round(mem["MemTotal"] / 1024),
                    "mem_available_mb": round(mem.get("MemAvailable", 0) / 1024)}
        except OSError:
            return {}

    # ------------------------------------------------------------- topology
    def topology(self) -> dict:
        if not self.fabric:
            return {"state": "down"}
        matrix = self.fabric.allowed_matrix()
        # verify with the kernel, not with the declared matrix
        observed = {z: [ip for ip in self.fabric.reachable_zone_ips(z)]
                    for z in netlab.ZONES}
        return {"state": self.state, "zones": {n: {"ip": z.ip, "cidr": z.cidr}
                                               for n, z in netlab.ZONES.items()},
                "declared_links": [f"{ln.a}<->{ln.b}" for ln in netlab.LINKS],
                "declared_matrix": matrix, "kernel_reachable_ips": observed,
                "hsm_links": [f"{ln.a}<->{ln.b}" for ln in netlab.LINKS
                              if "hsm" in (ln.a, ln.b)]}

    def status(self) -> dict:
        return {"state": self.state, "run_id": self.cfg().get("run_id"),
                "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else 0,
                "components": [{"id": c[0], "layer": c[1], "status": c[2], "note": c[3]}
                               for c in COMPONENTS],
                "scenarios": [{"id": k, **{kk: vv for kk, vv in v.items() if kk != "runs"},
                               "zones": [z for z, _ in v["runs"]]}
                              for k, v in SCENARIO_PLAN.items()],
                "fixes": self.fixes, "flags": self.cfg().get("flags", {}),
                "notes": self.notes, "runs": self.runs[-20:]}


LAB = Lab()


# --------------------------------------------------------------------- control
class ControlHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code: int, payload) -> None:
        raw = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):  # noqa: N802
        p = self.path.split("?")[0]
        routes = {
            "/v1/health": lambda: (200, {"ok": True, "api": "v1",
                                         "state": LAB.state}),
            "/v1/status": lambda: (200, LAB.status()),
            "/v1/topology": lambda: (200, LAB.topology()),
            "/v1/metrics": lambda: (200, LAB.metrics()),
            "/v1/scenarios": lambda: (200, {"scenarios": [
                {"id": k, **{kk: vv for kk, vv in v.items() if kk != "runs"},
                 "zones": [z for z, _ in v["runs"]]} for k, v in SCENARIO_PLAN.items()]}),
            "/v1/evidence": lambda: (200, {"runs": LAB.runs,
                                           "dir": os.path.join(STATE, "evidence")}),
            "/v1/notes": lambda: (200, {"notes": LAB.notes}),
            "/v1/isolation": lambda: (200, LAB.isolation_sweep()),
            "/v1/egress": lambda: (200, LAB.egress_probe()),
        }
        fn = routes.get(p)
        if fn:
            try:
                code, payload = fn()
            except Exception as exc:                    # noqa: BLE001
                return self._send(500, {"error": repr(exc), "path": p})
            return self._send(code, payload)
        return self._send(404, {"error": "not found", "path": p})

    def do_POST(self):  # noqa: N802
        p = self.path.split("?")[0]
        try:
            if p == "/v1/up":
                return self._send(200, LAB.up())
            if p == "/v1/down":
                return self._send(200, LAB.down())
            if p == "/v1/reset":
                return self._send(200, {**LAB.reset(), "reset": True})
            if p.startswith("/v1/scenarios/") and p.endswith("/run"):
                sid = p.split("/")[3]
                return self._send(200, LAB.run_scenario(sid))
            if p.startswith("/v1/fix/"):
                name = p.rsplit("/", 1)[-1]
                body = self._body()
                return self._send(200, LAB.apply_fix(name, body.get("enable", True)))
            if p == "/v1/verify":
                return self._send(200, self._verify())
        except Exception as exc:                        # noqa: BLE001
            return self._send(500, {"error": repr(exc)})
        return self._send(404, {"error": "not found", "path": p})

    def _verify(self) -> dict:
        """Independent check: re-run each scenario twice and compare verdicts."""
        out = []
        for sid in ("S2", "S3", "S4"):
            a = LAB.run_scenario(sid)
            b = LAB.run_scenario(sid)
            out.append({"scenario": sid, "run1": a.get("verdict"),
                        "run2": b.get("verdict"),
                        "stable": a.get("verdict") == b.get("verdict")})
        return {"verified": out,
                "stable": all(o["stable"] for o in out)}


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def main(argv: list[str]) -> int:
    os.makedirs(STATE, exist_ok=True)
    if os.environ.get("RANGE_CHILD") == "1":
        return 0
    if len(argv) > 1 and argv[1] == "serve":
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)
        srv = UnixServer(SOCK_PATH, ControlHandler)
        os.chmod(SOCK_PATH, 0o600)
        with open(PID_PATH, "w") as fh:
            fh.write(str(os.getpid()))
        signal.signal(signal.SIGTERM, lambda *a: (LAB.down(), sys.exit(0)))
        print(f"labd ready pid={os.getpid()} socket={SOCK_PATH}", flush=True)
        try:
            srv.serve_forever()
        finally:
            LAB.down()
            for p in (SOCK_PATH, PID_PATH):
                try:
                    os.remove(p)
                except OSError:
                    pass
        return 0
    print("usage: python3 -m lab.labd serve", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
