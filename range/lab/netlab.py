#!/usr/bin/env python3
"""
PRISM / AETHERION Cyber Range — network fabric.

Real, kernel-enforced zone segmentation without any container runtime.

How it works
------------
The supervisor runs inside one unprivileged user+mount+network namespace
(`unshare -Urmn --map-root-user`). Inside it:

  * every zone is its own network namespace (a child `unshare -n` anchor);
  * every zone owns a canonical /32 address installed on its own loopback;
  * a link between two zones is a veth pair with a /30 transit subnet and one
    static /32 route on each side pointing at the peer;
  * a zone with no link to another zone has no route to it. The kernel drops
    the packet at the first hop: there is nowhere to send it.

So the allow-matrix in `docs/cyber-range/02-architecture.md` is not enforced by
a policy engine that could be misconfigured — it is enforced by topology. To
reach a zone you were not given a link to, you would need CAP_NET_ADMIN in the
supervisor's namespace, i.e. you would have to be the supervisor.

Limits (documented, not hidden)
-------------------------------
  * All zones share one kernel: this is L3 isolation, not a hypervisor boundary.
  * Loopback-hosted /32 addresses cannot be filtered by interface, so a future
    per-port policy would need nftables (absent here) or application auth.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Zone:
    name: str
    ip: str            # canonical /32 service address hosted on lo
    cidr: str          # documentation CIDR from the architecture doc


@dataclass
class Link:
    a: str
    b: str
    transit_a: str
    transit_b: str
    note: str = ""


ZONES: dict[str, Zone] = {
    "wan":    Zone("wan",    "10.10.0.2",    "10.10.0.0/24"),
    "dmz":    Zone("dmz",    "10.60.0.10",   "10.60.0.0/24"),
    "edge":   Zone("edge",   "10.20.0.10",   "10.20.0.0/24"),
    "corp":   Zone("corp",   "10.30.0.10",   "10.30.0.0/24"),
    "prod":   Zone("prod",   "10.40.0.10",   "10.40.0.0/24"),
    "signer": Zone("signer", "10.40.3.10",   "10.40.3.0/24"),
    "hsm":    Zone("hsm",    "10.40.1.10",   "10.40.1.0/24"),
    "chain":  Zone("chain",  "10.40.2.10",   "10.40.2.0/24"),
    "mon":    Zone("mon",    "10.50.0.10",   "10.50.0.0/24"),
}

# The allow-matrix. This is the single source of truth used to build links and
# it must agree with docs/cyber-range/02-architecture.md.
LINKS: list[Link] = [
    Link("corp", "edge",   "10.99.1.1",  "10.99.1.2",  "SSO / PKI"),
    Link("corp", "dmz",    "10.99.2.1",  "10.99.2.2",  "public API from workstations"),
    Link("dmz",  "prod",   "10.99.3.1",  "10.99.3.2",  "public API -> gateway"),
    Link("edge", "prod",   "10.99.4.1",  "10.99.4.2",  "token validation, secrets"),
    Link("signer", "prod", "10.99.5.1",  "10.99.5.2",  "transaction -> signer"),
    Link("signer", "hsm",  "10.99.6.1",  "10.99.6.2",  "ONLY permitted path to the HSM"),
    Link("chain", "prod",  "10.99.7.1",  "10.99.7.2",  "relayer -> chain"),
    Link("mon",  "prod",   "10.99.8.1",  "10.99.8.2",  "telemetry pull"),
    Link("mon",  "edge",   "10.99.9.1",  "10.99.9.2",  "telemetry pull"),
    Link("mon",  "corp",   "10.99.10.1", "10.99.10.2", "telemetry pull"),
    Link("mon",  "dmz",    "10.99.11.1", "10.99.11.2", "telemetry pull"),
    Link("wan",  "dmz",    "10.99.12.1", "10.99.12.2", "simulated internet -> public API"),
]


class FabricError(RuntimeError):
    pass


@dataclass
class Fabric:
    state_dir: str
    anchors: dict[str, subprocess.Popen] = field(default_factory=dict)
    services: dict[str, subprocess.Popen] = field(default_factory=dict)
    links_built: list[str] = field(default_factory=list)

    # ---- shell helpers ---------------------------------------------------
    @staticmethod
    def sh(*argv: str, check: bool = True) -> subprocess.CompletedProcess:
        p = subprocess.run(argv, capture_output=True, text=True)
        if check and p.returncode != 0:
            raise FabricError(f"{' '.join(argv)} failed: {p.stderr.strip() or p.stdout.strip()}")
        return p

    def _in(self, zone: str, *argv: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.sh("nsenter", "-t", str(self.anchors[zone].pid), "-n", *argv, check=check)

    # ---- lifecycle -------------------------------------------------------
    def build(self) -> dict:
        """Create zone namespaces, addresses, and the links of the allow-matrix."""
        started = time.time()
        for name in ZONES:
            self.anchors[name] = subprocess.Popen(
                ["unshare", "-n", "sleep", "86400"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        time.sleep(0.4)
        for name, zone in ZONES.items():
            pid = self.anchors[name]
            if pid.poll() is not None:
                raise FabricError(f"zone {name}: namespace anchor died")
            self._in(name, "ip", "link", "set", "lo", "up")
            self._in(name, "ip", "addr", "add", f"{zone.ip}/32", "dev", "lo")
            # explicit loopback route so the /32 is reachable locally
            self._in(name, "ip", "route", "add", f"{zone.ip}/32", "dev", "lo", check=False)

        for i, link in enumerate(LINKS):
            va, vb = f"vx{i}a", f"vx{i}b"
            self.sh("ip", "link", "add", va, "type", "veth", "peer", "name", vb)
            self.sh("ip", "link", "set", va, "netns", str(self.anchors[link.a].pid))
            self.sh("ip", "link", "set", vb, "netns", str(self.anchors[link.b].pid))
            self._in(link.a, "ip", "addr", "add", f"{link.transit_a}/30", "dev", va)
            self._in(link.a, "ip", "link", "set", va, "up")
            self._in(link.b, "ip", "addr", "add", f"{link.transit_b}/30", "dev", vb)
            self._in(link.b, "ip", "link", "set", vb, "up")
            # each side learns exactly one /32: the peer's canonical address
            self._in(link.a, "ip", "route", "add", f"{ZONES[link.b].ip}/32",
                     "via", link.transit_b, "dev", va)
            self._in(link.b, "ip", "route", "add", f"{ZONES[link.a].ip}/32",
                     "via", link.transit_a, "dev", vb)
            self.links_built.append(f"{link.a}<->{link.b}")

        return {
            "zones": len(ZONES),
            "links": len(self.links_built),
            "ip_pairs": sum(1 for _ in LINKS),
            "build_seconds": round(time.time() - started, 2),
        }

    # ---- service execution ----------------------------------------------
    def spawn(self, zone: str, name: str, argv: list[str], env: dict | None = None,
              log_path: str | None = None) -> subprocess.Popen:
        """Run a command inside a zone namespace, logging to a file."""
        e = dict(os.environ)
        e.update(env or {})
        e["RANGE_ZONE"] = zone
        e["PYTHONUNBUFFERED"] = "1"
        out = open(log_path, "wb") if log_path else subprocess.DEVNULL
        proc = subprocess.Popen(
            ["nsenter", "-t", str(self.anchors[zone].pid), "-n",
             f"--wd={os.getcwd()}", "--", *argv],
            stdout=out, stderr=subprocess.STDOUT, env=e,
        )
        self.services[name] = proc
        return proc

    def destroy(self) -> None:
        for name, proc in list(self.services.items()):
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        deadline = time.time() + 8
        for proc in list(self.services.values()):
            try:
                proc.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                proc.kill()
        self.services.clear()
        # killing the anchor destroys the namespace and everything in it
        for proc in self.anchors.values():
            if proc.poll() is None:
                proc.kill()
        for proc in self.anchors.values():
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self.anchors.clear()
        self.links_built.clear()

    # ---- topology introspection -----------------------------------------
    def routes(self, zone: str) -> list[str]:
        p = self._in(zone, "ip", "route", "show", check=False)
        return [ln for ln in p.stdout.splitlines() if ln.strip()]

    def ip_zone_map(self) -> dict[str, str]:
        """Every address that can appear as a source in the fabric -> its zone.

        Traffic originating in a zone leaves through the veth of the link in
        use, so the observed source is a transit /30 address, not the
        canonical /32. Anything that reasons about "where did this come from"
        needs this map."""
        m = {z.ip: n for n, z in ZONES.items()}
        for link in LINKS:
            m[link.transit_a] = link.a
            m[link.transit_b] = link.b
        return m

    def reachable_zone_ips(self, zone: str) -> list[str]:
        """Which canonical zone addresses this zone has a route to."""
        table = " ".join(self.routes(zone))
        return [z.ip for n, z in ZONES.items()
                if n != zone and z.ip in table]

    def allowed_matrix(self) -> dict[str, list[str]]:
        m: dict[str, set[str]] = {n: set() for n in ZONES}
        for ln in LINKS:
            m[ln.a].add(ln.b)
            m[ln.b].add(ln.a)
        return {k: sorted(v) for k, v in m.items()}
