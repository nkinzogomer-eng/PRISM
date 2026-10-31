#!/usr/bin/env python3
"""
PRISM / AETHERION Cyber Range — services.

Twelve HTTP services implementing the reference chain:
  workstation -> public API -> gateway -> transaction -> policy/wallet
              -> signer -> HSM -> relayer -> chain

Each service is a real process, bound to the canonical address of its zone,
speaking HTTP/1.1, with state in SQLite and structured logs shipped to the
collector. No mock library, no in-process stubs: a service that is down is
actually unreachable.

Deliberate weaknesses are configuration-level and documented:
  * gateway `/v1/sign-only` authenticates but does not authorize (fixture W-GW-1);
  * transaction `/internal/transfer` skips policy (fixture W-TX-1);
  * wallet debit is a read-check-write with a real sleep window (fixture W-WAL-1);
  * secrets service has coarse scopes: one read scope for every secret (W-SEC-1);
  * the HSM accepts the signer token from a file that the secrets store exposes.

Run: python3 -m lab.services <service-name>
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid

from .common import (INGEST_TOKEN_FILE, SECRETS, STATE, call, db, init_db,
                     jwt_decode, jwt_encode, log_event, serve, totp_verify, _read)

CFG_PATH = os.path.join(STATE, "lab-config.json")


def cfg() -> dict:
    try:
        with open(CFG_PATH) as fh:
            return json.load(fh)
    except OSError:
        return {}


def url(name: str) -> str:
    return cfg()["urls"][name]


def flag(name: str, default: bool = False) -> bool:
    return bool(cfg().get("flags", {}).get(name, default))


ZONE_IPS = {"10.10.0.2": "wan", "10.60.0.10": "dmz", "10.20.0.10": "edge",
            "10.30.0.10": "corp", "10.40.0.10": "prod", "10.40.3.10": "signer",
            "10.40.1.10": "hsm", "10.40.2.10": "chain", "10.50.0.10": "mon"}


def zone_of(ip: str) -> str:
    """Zone that owns an address, including veth transit addresses."""
    table = cfg().get("ip_zones") or ZONE_IPS
    return table.get(ip) or ZONE_IPS.get(ip, "unknown")


def origin_ip(h) -> str:
    """Original client address, as forwarded by the DMZ when it proxies."""
    return h.headers.get("X-Real-IP") or h.client_address[0]


def origin_zone(h) -> str:
    return zone_of(origin_ip(h))


def session_binding_ok(h) -> tuple[bool, dict]:
    """Mitigation M1 (flag require_mfa_zone_binding): pin a session to the zone
    that first used it, so a stolen bearer token is useless from elsewhere."""
    if not flag("require_mfa_zone_binding"):
        return True, {"binding": "not enforced"}
    zone = origin_zone(h)
    code, r = call(f"{url('idp')}/introspect", {"token": h.bearer(), "zone": zone})
    if code == 200 and r.get("active"):
        return True, {"binding": "ok", "bound_zone": r.get("bound_zone")}
    return False, {"binding": "rejected", "reason": r.get("reason", "inactive"),
                   "seen_zone": zone, **r}


def prod_origin_only(h) -> bool:
    """Mitigation M4 (flag dmz_port_isolation): only the gateway host may call
    internal endpoints, which is what a network policy would enforce."""
    if not flag("dmz_port_isolation"):
        return True
    return zone_of(h.client_address[0]) == "prod"


def read(name: str) -> str:
    """Read a materialised secret (0400)."""
    return _read(os.path.join(SECRETS, name))


def audit(service: str, action: str, actor: str = "-", **detail) -> None:
    conn = db()
    conn.execute("INSERT INTO audit(ts,service,action,actor,detail) VALUES(?,?,?,?,?)",
                 (time.time(), service, action, actor, json.dumps(detail)[:2000]))
    conn.close()


# =============================================================== 1. identity
def _idp_token(h):
    body = h.body_json()
    grant = body.get("grant_type", "client_credentials")
    clients = cfg().get("clients", {})
    ttl = cfg().get("session_ttl", 300)
    scope, sub, mfa = "", "", "none"

    if grant == "client_credentials":
        cid, secret = body.get("client_id"), body.get("client_secret")
        c = clients.get(cid or "")
        if not c or c["secret"] != secret:
            log_event("idp", "login_failed", level="warn", grant=grant,
                      client=cid, ip=h.client_address[0])
            return 401, {"error": "invalid_client"}
        scope, sub, mfa = c["scope"], f"service:{cid}", "client_secret"
    elif grant == "password":
        user = body.get("username", "")
        passwd = read("passwd-" + user)
        seed = read("totp-" + user).encode()
        if not passwd or body.get("password") != passwd:
            log_event("idp", "login_failed", level="warn", grant=grant, user=user,
                      ip=h.client_address[0])
            return 401, {"error": "invalid_grant"}
        if not seed or not totp_verify(seed, str(body.get("totp", ""))):
            log_event("idp", "mfa_failed", level="warn", user=user, ip=h.client_address[0])
            return 401, {"error": "mfa_required"}
        scope, sub, mfa = body.get("scope", "read"), f"user:{user}", "totp"
    else:
        return 400, {"error": "unsupported_grant"}

    jti = uuid.uuid4().hex
    now = time.time()
    claims = {"sub": sub, "scope": scope, "jti": jti, "iat": int(now),
              "exp": int(now + ttl), "aud": "prism-range", "mfa": mfa, "zone": "edge"}
    tok = jwt_encode(claims)
    conn = db()
    conn.execute("INSERT INTO sessions(jti,subject,scope,mfa,issued,expires,client_ip)"
                 " VALUES(?,?,?,?,?,?,?)",
                 (jti, sub, scope, mfa, now, now + ttl,
                  zone_of(h.client_address[0]) or h.client_address[0]))
    conn.close()
    log_event("idp", "token_issued", subject=sub, scope=scope, mfa=mfa, jti=jti,
              ttl=ttl, ip=h.client_address[0])
    return 200, {"access_token": tok, "token_type": "Bearer", "expires_in": ttl,
                 "jti": jti, "scope": scope, "mfa": mfa}


def _idp_introspect(h):
    body = h.body_json() or {}
    tok = body.get("token", "")
    try:
        cl = jwt_decode(tok, verify_exp=False)
    except Exception:                                  # noqa: BLE001
        return 200, {"active": False}
    conn = db()
    row = conn.execute("SELECT revoked,expires,client_ip FROM sessions WHERE jti=?",
                       (cl.get("jti"),)).fetchone()
    if not row:
        conn.close()
        return 200, {"active": False}
    active = not row["revoked"] and row["expires"] > time.time()
    bound = row["client_ip"]
    origin = body.get("zone")
    # Blue-team mitigation M1: a session is pinned to the origin that first used it.
    if active and flag("require_mfa_zone_binding") and origin:
        if not bound:
            conn.execute("UPDATE sessions SET client_ip=? WHERE jti=?",
                         (origin, cl.get("jti")))
            conn.commit()
            bound = origin
        elif bound != origin:
            conn.close()
            log_event("idp", "session_zone_mismatch", level="warn",
                      sub=cl.get("sub"), bound=bound, seen=origin)
            return 200, {"active": False, "reason": "session bound to another zone",
                         "bound_zone": bound, "seen_zone": origin}
    conn.close()
    return 200, {"active": active, "sub": cl.get("sub"), "scope": cl.get("scope"),
                 "exp": cl.get("exp"), "revoked": bool(row["revoked"]),
                 "bound_zone": bound}


def _idp_revoke(h):
    tok = (h.body_json() or {}).get("token", "")
    try:
        cl = jwt_decode(tok, verify_exp=False)
    except Exception:                                  # noqa: BLE001
        return 400, {"error": "invalid_token"}
    conn = db()
    conn.execute("UPDATE sessions SET revoked=1 WHERE jti=?", (cl.get("jti"),))
    conn.close()
    log_event("idp", "token_revoked", subject=cl.get("sub"), jti=cl.get("jti"))
    return 200, {"revoked": True, "jti": cl.get("jti")}


def _idp_sessions(h):
    if not h.claims("admin"):
        return 403, {"error": "forbidden"}
    conn = db()
    rows = [dict(r) for r in conn.execute(
        "SELECT jti,subject,scope,mfa,issued,expires,revoked,client_ip FROM sessions"
        " ORDER BY issued DESC LIMIT 50")]
    conn.close()
    return 200, {"sessions": rows}


def _health(h):
    return 200, {"status": "ok", "service": h.service_name,
                 "zone": os.environ.get("RANGE_ZONE", "unset"),
                 "ts": round(time.time(), 3)}


def run_idp():
    serve("idp", 8080, {
        ("GET", "/health"): _health,
        ("GET", "/.well-known/openid-configuration"): lambda h: (
            200, {"issuer": f"http://{url('idp')}", "token_endpoint": f"http://{url('idp')}/token",
                  "grant_types_supported": ["client_credentials", "password"],
                  "id_token_signing_alg_values_supported": ["HS256"],
                  "note": "symmetric HS256, deviation from production RS256 — see realism limits"}),
        ("POST", "/token"): _idp_token,
        ("POST", "/introspect"): _idp_introspect,
        ("POST", "/revoke"): _idp_revoke,
        ("GET", "/sessions"): _idp_sessions,
    })


# ================================================================ 2. secrets
def _sec_get(h):
    cl = h.claims("secrets:read")
    if not cl:
        return 403, {"error": "forbidden", "reason": "scope secrets:read required"}
    name = h.path.rsplit("/", 1)[-1].split("?")[0]
    ttl = cfg().get("lease_ttl", 120)
    value = read(name)
    if not value:
        return 404, {"error": "unknown_secret", "name": name}
    lid = uuid.uuid4().hex
    now = time.time()
    conn = db()
    conn.execute("INSERT INTO leases(id,name,value,issued,expires) VALUES(?,?,?,?,?)",
                 (lid, name, value, now, now + ttl))
    conn.close()
    # Fixture W-SEC-1: one coarse read scope grants every secret. The name of the
    # secret is logged, which is what makes the abuse detectable after the fact.
    log_event("secrets", "secret_read", subject=cl.get("sub"), secret=name,
              lease=lid, scope=cl.get("scope"))
    audit("secrets", "secret_read", cl.get("sub"), secret=name, lease=lid)
    return 200, {"name": name, "value": value, "lease": lid, "ttl": ttl}


def _sec_revoke(h):
    cl = h.claims("secrets:read")
    if not cl:
        return 403, {"error": "forbidden"}
    lid = h.body_json().get("lease")
    conn = db()
    conn.execute("UPDATE leases SET revoked=1 WHERE id=?", (lid,))
    conn.close()
    log_event("secrets", "lease_revoked", lease=lid, by=cl.get("sub"))
    return 200, {"revoked": True, "lease": lid}


def _sec_leases(h):
    conn = db()
    rows = [dict(r) for r in conn.execute(
        "SELECT id,name,issued,expires,revoked FROM leases ORDER BY issued DESC LIMIT 50")]
    conn.close()
    return 200, {"leases": rows}


def run_secrets():
    serve("secrets", 8090, {
        ("GET", "/health"): _health,
        ("GET", "/leases"): _sec_leases,
        ("POST", "/lease/revoke"): _sec_revoke,
        ("GET", "/secret/signer-token"): _sec_get,
        ("GET", "/secret/hsm-token"): _sec_get,
        ("GET", "/secret/db-password"): _sec_get,
        ("GET", "/secret/signer-token-prod"): _sec_get,
    })


# ===================================================================== 3. CI
def _ci_pipeline(h):
    cl = h.claims("ci:run")
    if not cl:
        return 403, {"error": "forbidden"}
    branch = h.body_json().get("branch", "main")
    rid = uuid.uuid4().hex[:8]
    work = os.path.join(STATE, "ci", rid)
    os.makedirs(work, exist_ok=True)
    steps = []
    # Real pipeline: real subprocesses, real exit codes.
    steps.append(("git-init", subprocess.run(["git", "init", "-q", work],
                                             capture_output=True, text=True).returncode))
    artefact = os.path.join(work, "release.txt")
    with open(artefact, "w") as fh:
        fh.write(f"build {rid} branch {branch}\n")
    steps.append(("build", 0))
    test = subprocess.run(["python3", "-c", "assert 2+2 == 4"], capture_output=True)
    steps.append(("test", test.returncode))

    # The CI runner fetches its deployment credentials from the secrets service
    # with the same coarse read scope it uses for everything else (W-SEC-1).
    tok = h.bearer()
    code, sec = call(f"{url('secrets')}/secret/signer-token", token=tok)
    leaked = sec.get("value", "") if code == 200 else ""
    steps.append(("secrets", 0 if leaked else 1))

    deploy = {"status": "skipped"}
    if leaked:
        # deploy step: present the release to the public API
        code, r = call(f"{url('dmz')}/v1/release", {"release": rid, "branch": branch},
                       token=tok)
        deploy = {"status": code, "detail": r}

    conn = db()
    conn.execute("INSERT INTO audit(ts,service,action,actor,detail) VALUES(?,?,?,?,?)",
                 (time.time(), "ci", "pipeline_run", cl.get("sub"),
                  json.dumps({"run": rid, "steps": steps})[:2000]))
    conn.close()
    log_event("ci", "pipeline_run", run=rid, branch=branch, steps=steps,
              secret_fetched=bool(leaked), deploy=deploy)
    return 200, {"run": rid, "steps": steps, "deploy": deploy,
                 "artefact": artefact,
                 "note": "build log is world-readable inside corp, as configured"}


def _ci_logs(h):
    logs = []
    for f in sorted(os.listdir(os.path.join(STATE, "logs"))):
        if f.endswith(".jsonl"):
            logs.append(f)
    return 200, {"log_files": logs}


def run_ci():
    serve("ci", 8081, {
        ("GET", "/health"): _health,
        ("POST", "/pipeline/run"): _ci_pipeline,
        ("GET", "/logs"): _ci_logs,
    })


# ============================================================ 4. public API
def _dmz_release(h):
    # The DMZ forwards to the gateway. It adds its proxy headers, which the
    # gateway is expected to validate — fixture W-GW-2 shows it only partially does.
    tok = h.bearer()
    code, r = call(f"{url('gateway')}/v1/release", h.body_json(), token=tok,
                   headers={"X-Forwarded-By": "dmz", "X-Real-IP": h.client_address[0]})
    return code, {"upstream": "gateway", "status": code, "payload": r}


def _dmz_transfer(h):
    tok = h.bearer()
    hdrs = {"X-Forwarded-By": "dmz", "X-Real-IP": h.client_address[0]}
    # An optional debug actor header is forwarded verbatim (W-GW-2).
    if h.headers.get("X-Debug-Actor"):
        hdrs["X-Debug-Actor"] = h.headers["X-Debug-Actor"]
    code, r = call(f"{url('gateway')}/v1/transfer", h.body_json(), token=tok, headers=hdrs)
    return code, {"upstream": "gateway", "status": code, "payload": r}


def _dmz_sign_only(h):
    """Partner-facing signing API. The DMZ forwards it to the gateway; this is
    the only way a non-prod zone can reach a signing path."""
    tok = h.bearer()
    code, r = call(f"{url('gateway')}/v1/sign-only", h.body_json(), token=tok,
                   headers={"X-Forwarded-By": "dmz"})
    log_event("dmz", "sign_only_proxied", status=code)
    return code, {"upstream": "gateway", "status": code, "payload": r}


def run_dmz():
    serve("dmz", 8080, {
        ("GET", "/health"): _health,
        ("POST", "/v1/transfer"): _dmz_transfer,
        ("POST", "/v1/release"): _dmz_release,
        ("POST", "/v1/sign-only"): _dmz_sign_only,
    })


# ================================================================ 5. gateway
def _gw_transfer(h):
    cl = h.claims("transfer:write")
    if not cl:
        return 403, {"error": "forbidden", "reason": "scope transfer:write required"}
    ok, why = session_binding_ok(h)
    if not ok:
        return 401, {"error": "unauthorized", "detail": why}
    actor = cl.get("sub")
    # W-GW-2: the debug header overrides the authenticated actor and waives MFA.
    # Left in "to help support during incidents"; never removed.
    debug_actor = h.headers.get("X-Debug-Actor")
    if debug_actor and not flag("ignore_debug_header"):
        actor = debug_actor
    elif debug_actor:
        log_event("gateway", "debug_header_ignored", level="warn",
                  claimed=debug_actor, authenticated=cl.get("sub"))
    code, r = call(f"{url('tx')}/transfer", {**h.body_json(), "actor": actor},
                   headers={"X-Gateway": "1"})
    log_event("gateway", "transfer_forwarded", actor=actor, status=code,
              debug_header=bool(debug_actor))
    return code, r


def _gw_sign_only(h):
    # W-GW-1: authentication is required, authorization is not checked.
    cl = h.claims()                       # any valid token passes
    if not cl:
        return 401, {"error": "unauthorized"}
    ok, why = session_binding_ok(h)
    if not ok:
        return 401, {"error": "unauthorized", "detail": why}
    if flag("gateway_sign_only_authz") and \
            "sign:execute" not in (cl.get("scope") or "").split():
        log_event("gateway", "authz_reject", level="warn",
                  need="sign:execute", have=cl.get("scope"), path="/v1/sign-only")
        return 403, {"error": "forbidden", "reason": "scope sign:execute required"}
    code, r = call(f"{url('tx')}/sign-only", h.body_json(),
                   headers={"X-Gateway": "1"})
    log_event("gateway", "sign_only_forwarded", subject=cl.get("sub"),
              scope=cl.get("scope"), status=code)
    return code, r


def _gw_release(h):
    cl = h.claims()
    if not cl:
        return 401, {"error": "unauthorized"}
    ok, why = session_binding_ok(h)
    if not ok:
        return 401, {"error": "unauthorized", "detail": why}
    log_event("gateway", "release_registered", subject=cl.get("sub"),
              body=h.body_json())
    return 200, {"registered": True}


def run_gateway():
    serve("gateway", 8080, {
        ("GET", "/health"): _health,
        ("POST", "/v1/transfer"): _gw_transfer,
        ("POST", "/v1/sign-only"): _gw_sign_only,
        ("POST", "/v1/release"): _gw_release,
    })


# ============================================================ 6. transaction
def _tx_transfer(h):
    body = h.body_json()
    req = {
        "account_id": body.get("account", "acct-hot-1"),
        "asset": body.get("asset", "ETH"),
        "amount": str(body.get("amount", "0")),
        "destination": body.get("destination", ""),
        "approvals": body.get("approvals", []),
        "actor": body.get("actor", "-"),
        "session": {"actor": body.get("actor", "-"), "mfa": "totp",
                    "age_s": int(body.get("session_age_s", 10))},
        "signer": {"key_id": body.get("key_id", "signer-1")},
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    code, dec = call(f"{url('policy')}/decide", {"request": req})
    if code != 200 or not dec.get("allow"):
        log_event("tx", "transfer_denied", level="warn", actor=req["actor"],
                  reasons=dec.get("reasons"), amount=req["amount"])
        return 403 if code == 200 else 502, {"status": "denied", "decision": dec}

    account, asset, amount = req["account_id"], req["asset"], float(req["amount"])
    code, bal = call(f"{url('wallet')}/debit", {"account": account, "asset": asset,
                                                "amount": amount,
                                                "dest": req["destination"],
                                                "actor": req["actor"],
                                                "tx_ref": "-"})
    if code != 200 or not bal.get("ok"):
        log_event("tx", "debit_failed", level="warn", actor=req["actor"],
                  detail=bal, amount=amount)
        return 409, {"status": "insufficient_funds", "detail": bal}

    payload = json.dumps({"account": account, "asset": asset, "amount": req["amount"],
                          "destination": req["destination"], "nonce": uuid.uuid4().hex},
                         sort_keys=True)
    code, sig = call(f"{url('signer')}/sign", {"key_id": req["signer"]["key_id"],
                                               "payload": payload})
    if code != 200:
        call(f"{url('wallet')}/credit", {"account": account, "asset": asset,
                                         "amount": amount, "note": "rollback"})
        return 502, {"status": "sign_failed", "detail": sig}
    code, sub = call(f"{url('relayer')}/submit", {"payload": payload,
                                                  "signature": sig.get("signature"),
                                                  "pubkey": sig.get("pubkey"),
                                                  "kind": "transfer"}, timeout=15)
    tid = uuid.uuid4().hex[:12]
    conn = db()
    conn.execute("INSERT INTO transfers(id,ts,account,asset,amount,destination,actor,"
                 "status,decision,signature,chain_tx) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (tid, time.time(), account, asset, amount, req["destination"],
                  req["actor"], "submitted", json.dumps(dec.get("reasons", [])),
                  sig.get("signature", "")[:64], sub.get("chain_tx", "")))
    conn.close()
    log_event("tx", "transfer_submitted", transfer=tid, actor=req["actor"],
              amount=req["amount"], destination=req["destination"],
              chain_tx=sub.get("chain_tx"), path="policy")
    return 200, {"status": "submitted", "transfer": tid, "decision": dec,
                 "signature": (sig.get("signature") or "")[:32] + "...",
                 "chain": sub}


def _tx_internal(h):
    # W-TX-1: the legacy internal path never calls the policy engine.
    if not prod_origin_only(h):
        log_event("tx", "origin_rejected", level="warn", path="/internal/transfer",
                  src=h.client_address[0], zone=ZONE_IPS.get(h.client_address[0]))
        return 403, {"error": "forbidden", "reason": "internal endpoint: origin not allowed"}
    if flag("tx_internal_disabled"):
        # Mitigation M5: the legacy path is switched off entirely.
        return 410, {"error": "gone", "reason": "legacy internal path retired"}
    body = h.body_json()
    account = body.get("account", "acct-hot-1")
    asset = body.get("asset", "ETH")
    amount = float(body.get("amount", 0))
    code, bal = call(f"{url('wallet')}/debit", {"account": account, "asset": asset,
                                                "amount": amount,
                                                "dest": body.get("destination", ""),
                                                "actor": body.get("actor", "-"),
                                                "tx_ref": "internal"})
    log_event("tx", "internal_transfer", level="warn", actor=body.get("actor"),
              amount=amount, policy_checked=False, debit=bal)
    return (200 if code == 200 else 409), {"status": "accepted_internal",
                                           "policy_checked": False, "debit": bal}


def _tx_sign_only(h):
    if not prod_origin_only(h):
        log_event("tx", "origin_rejected", level="warn", path="/sign-only",
                  src=h.client_address[0], zone=ZONE_IPS.get(h.client_address[0]))
        return 403, {"error": "forbidden", "reason": "signing endpoint: origin not allowed"}
    body = h.body_json()
    payload = json.dumps(body.get("payload", body), sort_keys=True)
    code, sig = call(f"{url('signer')}/sign", {"key_id": body.get("key_id", "signer-1"),
                                               "payload": payload})
    log_event("tx", "sign_only", level="warn", policy_checked=False,
              key_id=body.get("key_id", "signer-1"), status=code)
    return code, {"signature": sig.get("signature"), "pubkey": sig.get("pubkey"),
                  "policy_checked": False}


def _tx_list(h):
    conn = db()
    rows = [dict(r) for r in conn.execute(
        "SELECT id,ts,account,asset,amount,destination,actor,status,chain_tx"
        " FROM transfers ORDER BY ts DESC LIMIT 50")]
    conn.close()
    return 200, {"transfers": rows}


def run_tx():
    serve("tx", 8081, {
        ("GET", "/health"): _health,
        ("GET", "/transfers"): _tx_list,
        ("POST", "/transfer"): _tx_transfer,
        ("POST", "/internal/transfer"): _tx_internal,
        ("POST", "/sign-only"): _tx_sign_only,
    })


# ================================================================ 7. wallet
def _wall_balance(h):
    account = (h.path.split("account=")[1].split("&")[0]) if "account=" in h.path else "acct-hot-1"
    conn = db()
    row = conn.execute("SELECT asset,amount FROM balances WHERE account=?", (account,)).fetchone()
    conn.close()
    if not row:
        return 404, {"error": "unknown_account", "account": account}
    return 200, {"account": account, "asset": row["asset"], "amount": row["amount"]}


def _wall_debit(h):
    b = h.body_json()
    account, amount = b.get("account", "acct-hot-1"), float(b.get("amount", 0))
    conn = db()
    row = conn.execute("SELECT amount,asset FROM balances WHERE account=?", (account,)).fetchone()
    if not row:
        conn.close()
        return 404, {"error": "unknown_account"}
    if flag("wallet_atomic"):
        cur = conn.execute(
            "UPDATE balances SET amount = amount - ? WHERE account=? AND amount >= ?",
            (amount, account, amount))
        if cur.rowcount == 0:
            conn.close()
            log_event("wallet", "debit_rejected_atomic", level="warn", account=account,
                      amount=amount)
            return 409, {"ok": False, "reason": "insufficient_funds_atomic"}
        conn.close()
        return 200, {"ok": True, "mode": "atomic"}

    # W-WAL-1: read, hold, write. The window is real (150 ms), which is why two
    # concurrent requests can both observe the same balance and both succeed.
    observed = row["amount"]
    time.sleep(0.15)
    if observed < amount:
        conn.close()
        log_event("wallet", "debit_rejected", level="warn", account=account,
                  observed=observed, amount=amount)
        return 409, {"ok": False, "reason": "insufficient_funds", "observed": observed}
    new = observed - amount
    conn.execute("UPDATE balances SET amount=? WHERE account=?", (new, account))
    conn.execute("INSERT INTO ledger(ts,account,asset,delta,dest,tx_ref,actor,note)"
                 " VALUES(?,?,?,?,?,?,?,?)",
                 (time.time(), account, row["asset"], -amount, b.get("dest", ""),
                  b.get("tx_ref", ""), b.get("actor", "-"), "debit"))
    conn.close()
    if new < 0:
        log_event("wallet", "negative_balance", level="critical", account=account,
                  balance=new, amount=amount)
    return 200, {"ok": True, "mode": "racy", "balance": new, "observed": observed}


def _wall_credit(h):
    b = h.body_json()
    account, amount = b.get("account", "acct-hot-1"), float(b.get("amount", 0))
    conn = db()
    row = conn.execute("SELECT asset FROM balances WHERE account=?", (account,)).fetchone()
    asset = row["asset"] if row else b.get("asset", "ETH")
    conn.execute("INSERT INTO balances(account,asset,amount) VALUES(?,?,?)"
                 " ON CONFLICT(account) DO UPDATE SET amount = amount + ?",
                 (account, asset, amount, amount))
    conn.execute("INSERT INTO ledger(ts,account,asset,delta,dest,tx_ref,actor,note)"
                 " VALUES(?,?,?,?,?,?,?,?)",
                 (time.time(), account, asset, amount, "", "", b.get("actor", "-"),
                  b.get("note", "credit")))
    conn.close()
    return 200, {"ok": True}


def _wall_ledger(h):
    conn = db()
    rows = [dict(r) for r in conn.execute(
        "SELECT id,ts,account,asset,delta,dest,actor,note FROM ledger ORDER BY id DESC LIMIT 100")]
    conn.close()
    return 200, {"ledger": rows}


def run_wallet():
    serve("wallet", 8082, {
        ("GET", "/health"): _health,
        ("GET", "/balance"): _wall_balance,
        ("GET", "/ledger"): _wall_ledger,
        ("POST", "/debit"): _wall_debit,
        ("POST", "/credit"): _wall_credit,
    })


# ================================================================ 8. policy
def _policy_data() -> dict:
    try:
        with open(os.path.join(STATE, "policy-data.json")) as fh:
            return json.load(fh)
    except OSError:
        return {"limits": {}, "destinations": {}, "revoked_keys": []}


def _policy_decide(h):
    req = (h.body_json() or {}).get("request", {})
    data = _policy_data()
    reasons: list[str] = []
    asset = req.get("asset", "ETH")
    try:
        amount = float(req.get("amount", 0))
    except (TypeError, ValueError):
        amount = 0.0
    lim, dest = data.get("limits", {}), data.get("destinations", {})
    signer = req.get("signer", {}) or {}
    session = req.get("session", {}) or {}

    if signer.get("key_id") in data.get("revoked_keys", []):
        reasons.append("signer key is revoked")
    if req.get("destination") not in dest.get(asset, []):
        reasons.append("destination not allowlisted for asset")
    if amount > lim.get("absolute_ceiling", {}).get(asset, 1e18):
        reasons.append("amount above absolute ceiling")
    if int(session.get("age_s", 0)) > lim.get("max_session_age_s", 3600):
        reasons.append("session older than step-up window")
    if session.get("mfa") in ("none", None, ""):
        reasons.append("session lacks MFA")

    # velocity computed from the real ledger, not from a static file
    conn = db()
    hour_ago = time.time() - 3600
    row = conn.execute("SELECT COALESCE(SUM(-delta),0) AS s FROM ledger"
                       " WHERE account=? AND asset=? AND ts>? AND delta<0",
                       (req.get("account_id"), asset, hour_ago)).fetchone()
    conn.close()
    window_sum = float(row["s"] or 0)
    cap = lim.get("hourly_cap", {}).get(asset, 1e18)
    if window_sum + amount > cap:
        reasons.append("hourly velocity cap exceeded")

    threshold = lim.get("quorum_threshold", {}).get(asset, 1e18)
    approvals = req.get("approvals") or []
    if amount > threshold and len({a.get("actor") for a in approvals}) < 2:
        reasons.append("quorum not met for large transfer")
    if any(a.get("actor") == session.get("actor") for a in approvals):
        reasons.append("approver is the requester")

    decision = {"allow": not reasons, "reasons": reasons,
                "account_id": req.get("account_id"), "asset": asset, "amount": amount,
                "velocity_window": round(window_sum, 4),
                "destination": req.get("destination"),
                "time_utc": req.get("time_utc")}
    log_event("policy", "decision", allow=decision["allow"], reasons=reasons,
              actor=session.get("actor"), amount=amount)
    return 200, decision


def run_policy():
    serve("policy", 8083, {
        ("GET", "/health"): _health,
        ("GET", "/rules"): lambda h: (200, _policy_data()),
        ("POST", "/decide"): _policy_decide,
    })


# ================================================================ 9. signer
def _signer_sign(h):
    b = h.body_json()
    key_id = b.get("key_id", "signer-1")
    payload = b.get("payload", "")
    code, r = call(f"{url('hsm')}/sign", {"key_id": key_id, "payload": payload},
                   headers={"X-HSM-Token": read("hsm-token")})
    if code != 200:
        log_event("signer", "sign_failed", level="error", key_id=key_id,
                  status=code, detail=r)
        return 502, {"error": "hsm_refused", "detail": r}
    log_event("signer", "signed", key_id=key_id, digest=r.get("digest"))
    return 200, {"signature": r.get("signature"), "pubkey": r.get("pubkey"),
                 "digest": r.get("digest"), "key_id": key_id}


def run_signer():
    serve("signer", 8084, {
        ("GET", "/health"): _health,
        ("POST", "/sign"): _signer_sign,
    })


# =================================================================== 10. HSM
def _hsm_sign(h):
    tok = h.headers.get("X-HSM-Token", "")
    expected = read("hsm-token")
    if not hmac_cmp(tok, expected):
        log_event("hsm", "auth_reject", level="warn", ip=h.client_address[0],
                  reason="bad HSM token")
        return 403, {"error": "forbidden", "reason": "invalid HSM token"}
    b = h.body_json()
    key_id = b.get("key_id", "signer-1")
    payload = b.get("payload", "")
    conn = db()
    row = conn.execute("SELECT path,extractable,revoked FROM keys WHERE key_id=?",
                       (key_id,)).fetchone()
    conn.close()
    if not row:
        return 404, {"error": "unknown_key"}
    if row["revoked"]:
        log_event("hsm", "revoked_key_use", level="critical", key_id=key_id)
        return 403, {"error": "key_revoked"}
    digest = subprocess.run(["openssl", "dgst", "-sha256", "-binary"],
                            input=payload.encode(), capture_output=True).stdout
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", row["path"]],
                         input=payload.encode(), capture_output=True)
    if sig.returncode != 0:
        return 500, {"error": "sign_failed", "detail": sig.stderr.decode()[:200]}
    pub = subprocess.run(["openssl", "ec", "-in", row["path"], "-pubout"],
                         capture_output=True, text=True).stdout
    log_event("hsm", "key_used", key_id=key_id, digest=digest.hex()[:32],
              extractable=bool(row["extractable"]))
    return 200, {"signature": sig.stdout.hex(), "pubkey": pub,
                 "digest": digest.hex()}


def _hsm_export(h):
    """Export is the operation that must fail: the key is marked non-extractable."""
    tok = h.headers.get("X-HSM-Token", "")
    if not hmac_cmp(tok, read("hsm-token")):
        log_event("hsm", "auth_reject", level="warn", op="export")
        return 403, {"error": "forbidden"}
    key_id = h.body_json().get("key_id", "signer-1")
    conn = db()
    row = conn.execute("SELECT path,extractable FROM keys WHERE key_id=?", (key_id,)).fetchone()
    conn.close()
    if not row:
        return 404, {"error": "unknown_key"}
    if not row["extractable"]:
        log_event("hsm", "export_denied", level="critical", key_id=key_id,
                  attribute="CKA_EXTRACTABLE=false")
        return 403, {"error": "key_not_extractable",
                     "reason": "CKA_EXTRACTABLE=false",
                     "note": "simulated PKCS#11 attribute enforcement"}
    with open(row["path"]) as fh:
        log_event("hsm", "export_allowed", level="critical", key_id=key_id)
        return 200, {"key_id": key_id, "pem": fh.read()}


def hmac_cmp(a: str, b: str) -> bool:
    import hmac as _h
    return _h.compare_digest(a.encode(), b.encode())


def _hsm_keys(h):
    conn = db()
    rows = [dict(r) for r in conn.execute(
        "SELECT key_id,extractable,revoked,created FROM keys")]
    conn.close()
    return 200, {"keys": rows}


def _hsm_revoke(h):
    if not hmac_cmp(h.headers.get("X-HSM-Token", ""), read("hsm-token")):
        return 403, {"error": "forbidden"}
    key_id = h.body_json().get("key_id", "signer-1")
    conn = db()
    conn.execute("UPDATE keys SET revoked=1 WHERE key_id=?", (key_id,))
    conn.close()
    log_event("hsm", "key_revoked", level="warn", key_id=key_id)
    return 200, {"revoked": True, "key_id": key_id}


def run_hsm():
    serve("hsm", 8085, {
        ("GET", "/health"): _health,
        ("GET", "/keys"): _hsm_keys,
        ("POST", "/sign"): _hsm_sign,
        ("POST", "/export"): _hsm_export,
        ("POST", "/revoke"): _hsm_revoke,
    })


# =============================================================== 11. relayer
def _relay_submit(h):
    b = h.body_json()
    payload, signature, pubkey = b.get("payload", ""), b.get("signature", ""), b.get("pubkey", "")
    # Replay protection: the digest of an already-submitted payload is refused.
    import hashlib
    digest = hashlib.sha256(payload.encode()).hexdigest()
    conn = db()
    seen = conn.execute("SELECT 1 FROM audit WHERE service='relayer' AND action='submit'"
                        " AND detail LIKE ?", (f"%{digest}%",)).fetchone()
    conn.close()
    if seen:
        log_event("relayer", "replay_rejected", level="warn", digest=digest[:16])
        return 409, {"error": "replay", "digest": digest[:16]}
    if pubkey and signature:
        try:
            sig_bytes = bytes.fromhex(signature)
        except ValueError:
            sig_bytes = b""
        with open(os.path.join(STATE, "verify.pem"), "w") as fh:
            fh.write(pubkey)
        p = subprocess.run(["openssl", "dgst", "-sha256", "-verify",
                            os.path.join(STATE, "verify.pem"),
                            "-signature", "/dev/stdin"],
                           input=sig_bytes, capture_output=True)
        if p.returncode != 0:
            # /dev/stdin signature input is unreliable; verify via temp files instead
            sp = os.path.join(STATE, "sig.tmp")
            with open(sp, "wb") as fh:
                fh.write(sig_bytes)
            p = subprocess.run(["openssl", "dgst", "-sha256", "-verify",
                                os.path.join(STATE, "verify.pem"), "-signature", sp],
                               input=payload.encode(), capture_output=True)
        if p.returncode != 0:
            log_event("relayer", "bad_signature", level="warn", digest=digest[:16])
            return 400, {"error": "bad_signature"}
    tx = None
    if cfg().get("chain_enabled"):
        code, r = call(f"{url('chain')}", {
            "jsonrpc": "2.0", "id": 1, "method": "eth_sendTransaction",
            "params": [{"from": cfg().get("chain_from"),
                        "to": cfg().get("chain_to"),
                        "value": hex(int(cfg().get("chain_value_wei", 10**15)))}]},
            timeout=10)
        if isinstance(r, dict) and r.get("result"):
            tx = r["result"]
    audit("relayer", "submit", b.get("kind", "-"), digest=digest, tx=tx)
    log_event("relayer", "submitted", digest=digest[:16], chain_tx=tx,
              kind=b.get("kind"))
    return 200, {"submitted": True, "digest": digest[:16], "chain_tx": tx}


def run_relayer():
    serve("relayer", 8086, {
        ("GET", "/health"): _health,
        ("POST", "/submit"): _relay_submit,
    })


# ============================================================ 12. collector
RULES = [
    ("revoked_key_used", "critical", "hsm", "revoked_key_use"),
    ("hsm_export_attempt", "critical", "hsm", "export_denied"),
    ("policy_bypass", "high", "tx", "internal_transfer"),
    ("sign_without_policy", "high", "tx", "sign_only"),
    ("coarse_secret_read", "medium", "secrets", "secret_read"),
    ("negative_balance", "critical", "wallet", "negative_balance"),
    ("authz_reject", "low", None, "authz_reject"),
    ("replay_attempt", "high", "relayer", "replay_rejected"),
    ("exfil_attempt", "high", "decoy", "exfil_attempt"),
]


def _mon_ingest(h):
    if not hmac_cmp(h.headers.get("X-Ingest-Token", ""), _read(INGEST_TOKEN_FILE)):
        return 403, {"error": "forbidden"}
    n = int(h.headers.get("Content-Length") or 0)
    raw = h.rfile.read(n) if n else b"{}"
    try:
        rec = json.loads(raw)
    except json.JSONDecodeError:
        return 400, {"error": "bad json"}
    d = os.path.join(STATE, "evidence", cfg().get("run_id", "manual"), "ingested")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "events.jsonl"), "a") as fh:
        fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    for rid, sev, svc, ev in RULES:
        if rec.get("event") == ev and (svc is None or rec.get("service") == svc):
            alert = {"rule": rid, "severity": sev, "service": rec.get("service"),
                     "event": ev, "ts": time.time(),
                     "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "detail": {k: rec.get(k) for k in
                                ("actor", "subject", "digest", "key_id", "path")
                                if k in rec}}
            ad = os.path.join(STATE, "evidence", cfg().get("run_id", "manual"))
            os.makedirs(ad, exist_ok=True)
            with open(os.path.join(ad, "alerts.jsonl"), "a") as fh:
                fh.write(json.dumps(alert, separators=(",", ":")) + "\n")
    return 200, {"ingested": True}


def _mon_alerts(h):
    run = cfg().get("run_id", "manual")
    p = os.path.join(STATE, "evidence", run, "alerts.jsonl")
    if not os.path.exists(p):
        return 200, {"alerts": [], "run": run}
    with open(p) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]
    return 200, {"alerts": rows[-200:], "count": len(rows), "run": run}


def _mon_rules(h):
    return 200, {"rules": [{"id": r[0], "severity": r[1], "event": r[3]} for r in RULES]}


def run_mon():
    serve("mon", 9090, {
        ("GET", "/health"): _health,
        ("GET", "/alerts"): _mon_alerts,
        ("GET", "/rules"): _mon_rules,
        ("POST", "/ingest"): _mon_ingest,
    })


# ================================================================== 13. wan
def _decoy(h):
    n = int(h.headers.get("Content-Length") or 0)
    body = h.rfile.read(n)[:2000].decode(errors="replace") if n else ""
    log_event("decoy", "exfil_attempt", level="warn", path=h.path,
              bytes=len(body), preview=body[:120], ip=h.client_address[0])
    return 200, {"received": True, "note": "isolated sink — nothing leaves the lab"}


def run_decoy():
    serve("decoy", 9999, {
        ("GET", "/health"): _health,
        ("GET", "/collect"): _decoy,
        ("POST", "/collect"): _decoy,
    })


SERVICES = {
    "idp": run_idp, "secrets": run_secrets, "ci": run_ci, "dmz": run_dmz,
    "gateway": run_gateway, "tx": run_tx, "wallet": run_wallet,
    "policy": run_policy, "signer": run_signer, "hsm": run_hsm,
    "relayer": run_relayer, "mon": run_mon, "decoy": run_decoy,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in SERVICES:
        print(f"usage: python3 -m lab.services {{{'|'.join(SERVICES)}}}", flush=True)
        return 2
    init_db()
    SERVICES[argv[1]]()
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv))
