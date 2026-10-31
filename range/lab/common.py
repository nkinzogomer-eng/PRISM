"""
Shared plumbing for the range services: HTTP routing, logging bus, JWT, TOTP.

Everything here is real: HTTP/1.1 over TCP, HMAC-SHA256 JWT (RFC 7519 shape),
TOTP (RFC 6238), SQLite with WAL. No external dependency, no mock library.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = os.environ.get("RANGE_STATE_DIR", os.path.join(os.path.dirname(__file__), "..", "state"))
STATE = os.path.abspath(STATE)
SECRETS = os.path.join(STATE, "secrets")
DB_PATH = os.path.join(STATE, "lab.db")
MON_URL = os.environ.get("RANGE_MON_URL", "")          # http://10.50.0.10:9090
INGEST_TOKEN_FILE = os.path.join(SECRETS, "ingest.token")
ZONE = os.environ.get("RANGE_ZONE", "unknown")


# ---------------------------------------------------------------- logging bus
def _read(path: str, default: str = "") -> str:
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return default


def log_event(service: str, event: str, level: str = "info", **fields) -> dict:
    """Emit a structured event. Local file first (never lost), then ship to mon."""
    rec = {
        "ts": round(time.time(), 3),
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service": service,
        "zone": ZONE,
        "event": event,
        "level": level,
        **fields,
    }
    line = json.dumps(rec, separators=(",", ":"))
    d = os.path.join(STATE, "logs")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"{service}.jsonl"), "a") as fh:
        fh.write(line + "\n")
    if MON_URL:
        try:
            req = urllib.request.Request(
                MON_URL.rstrip("/") + "/ingest",
                data=line.encode(),
                headers={"Content-Type": "application/json",
                         "X-Ingest-Token": _read(INGEST_TOKEN_FILE)},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=1.5).read()
        except Exception:                     # telemetry failure must not break the service
            pass
    return rec


# ------------------------------------------------------------------------ JWT
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def _key() -> bytes:
    return _read(os.path.join(SECRETS, "jwt.key")).encode()


def jwt_encode(payload: dict, key: bytes | None = None) -> str:
    key = key or _key()
    head = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64e(sig)}"


class JWTError(Exception):
    pass


def jwt_decode(token: str, key: bytes | None = None, verify_exp: bool = True) -> dict:
    key = key or _key()
    try:
        head, body, sig = token.split(".")
    except ValueError as exc:
        raise JWTError("malformed token") from exc
    expect = _b64e(hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expect, sig):
        raise JWTError("bad signature")
    claims = json.loads(_b64d(body))
    if verify_exp and claims.get("exp", 0) < time.time():
        raise JWTError("token expired")
    return claims


# ----------------------------------------------------------------------- TOTP
def totp_now(seed: bytes, step: int = 30, digits: int = 6, at: float | None = None) -> str:
    counter = int((at if at is not None else time.time()) // step)
    mac = hmac.new(seed, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp_verify(seed: bytes, code: str, window: int = 1, step: int = 30) -> bool:
    now = time.time()
    return any(hmac.compare_digest(totp_now(seed, step=step, at=now + i * step), code)
               for i in range(-window, window + 1))


# -------------------------------------------------------------------- storage
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  jti TEXT PRIMARY KEY, subject TEXT, scope TEXT, mfa TEXT,
  issued REAL, expires REAL, revoked INTEGER DEFAULT 0, client_ip TEXT);
CREATE TABLE IF NOT EXISTS balances(
  account TEXT PRIMARY KEY, asset TEXT, amount REAL);
CREATE TABLE IF NOT EXISTS ledger(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, account TEXT, asset TEXT,
  delta REAL, dest TEXT, tx_ref TEXT, actor TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS transfers(
  id TEXT PRIMARY KEY, ts REAL, account TEXT, asset TEXT, amount REAL,
  destination TEXT, actor TEXT, status TEXT, decision TEXT, signature TEXT,
  chain_tx TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS leases(
  id TEXT PRIMARY KEY, name TEXT, value TEXT, issued REAL, expires REAL, revoked INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS keys(
  key_id TEXT PRIMARY KEY, path TEXT, extractable INTEGER, revoked INTEGER DEFAULT 0, created REAL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, service TEXT, action TEXT, actor TEXT, detail TEXT);
"""


def init_db() -> None:
    os.makedirs(STATE, exist_ok=True)
    conn = db()
    conn.executescript(SCHEMA)
    conn.close()


# ----------------------------------------------------------------- HTTP layer
class RangeHandler(BaseHTTPRequestHandler):
    service_name = "service"
    server_version = "prism-range/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):      # keep stdout clean; we log structurally
        pass

    # -- helpers ---------------------------------------------------------
    def body_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def reply(self, code: int, payload: dict | list) -> None:
        raw = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def bearer(self) -> str | None:
        hdr = self.headers.get("Authorization") or ""
        return hdr[7:].strip() if hdr.lower().startswith("bearer ") else None

    def claims(self, required_scope: str | None = None) -> dict | None:
        tok = self.bearer()
        if not tok:
            return None
        try:
            cl = jwt_decode(tok)
        except JWTError as exc:
            log_event(self.service_name, "auth_reject", level="warn", reason=str(exc),
                      path=self.path, ip=self.client_address[0])
            return None
        if required_scope and required_scope not in (cl.get("scope") or "").split():
            log_event(self.service_name, "authz_reject", level="warn",
                      reason="missing scope", need=required_scope,
                      have=cl.get("scope"), path=self.path)
            return None
        return cl

    def route(self, table: dict, methods=("GET", "POST")):
        """Dispatch on exact path; return True if handled."""
        fn = table.get((self.command, self.path.split("?")[0]))
        if fn is None:
            return False
        if self.command not in methods:
            self.reply(405, {"error": "method not allowed"})
            return True
        try:
            code, payload = fn(self)
        except Exception as exc:                       # noqa: BLE001
            log_event(self.service_name, "handler_error", level="error",
                      path=self.path, error=repr(exc))
            code, payload = 500, {"error": "internal", "detail": repr(exc)}
        self.reply(code, payload)
        return True

    def do_GET(self):  # noqa: N802
        if not self.route(self.ROUTES, ("GET",)):      # type: ignore[attr-defined]
            self.reply(404, {"error": "not found", "path": self.path})

    def do_POST(self):  # noqa: N802
        if not self.route(self.ROUTES, ("POST",)):     # type: ignore[attr-defined]
            self.reply(404, {"error": "not found", "path": self.path})


def serve(service_name: str, port: int, routes: dict, host: str = "0.0.0.0") -> None:
    handler = type(f"H_{service_name}", (RangeHandler,),
                   {"service_name": service_name, "ROUTES": routes})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    log_event(service_name, "service_start", port=port)
    httpd.serve_forever()


# ----------------------------------------------------------------- remote call
def call(url: str, payload: dict | None = None, token: str | None = None,
         timeout: float = 5.0, headers: dict | None = None) -> tuple[int, dict]:
    data = None if payload is None else json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method="GET" if payload is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:                              # noqa: BLE001
            return exc.code, {"error": "http_error"}
    except Exception as exc:                           # noqa: BLE001
        return 0, {"error": "unreachable", "detail": repr(exc), "url": url}
