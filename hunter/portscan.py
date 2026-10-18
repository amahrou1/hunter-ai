"""Built-in TCP connect port scan for IP and CIDR scope entries.

No root, no libpcap, no extra binary: a plain TCP connect per (address, port),
paced by the program's rate limit. Only addresses the scope allows are ever
touched; out-of-scope and operator-avoided addresses are removed before the
first packet. Large ranges are scanned with fewer ports so one /16 cannot
take days (the reduction is reported, never silent).
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field

# Ports in priority order: web first (they feed the HTTP phases), then
# services whose exposure is itself a finding.
WEB_PORTS = [443, 80, 8443, 8080, 8000, 8008, 8081, 8888, 9443, 9000, 9090, 3000, 5000, 7001,
             7443, 8090, 8181, 8880, 10443, 4443, 8001, 8088, 9001, 9091, 4848, 5601, 15672]
SERVICE_PORTS = [22, 21, 23, 25, 53, 110, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 1521,
                 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 5985, 6379, 6443, 8500, 9200,
                 9300, 10250, 11211, 27017, 50000]
PORTS = WEB_PORTS + SERVICE_PORTS
# Exposed to the internet, these are worth a lead on their own.
SENSITIVE_PORTS = {2375: "Docker API", 2376: "Docker API (TLS)", 6379: "Redis", 9200: "Elasticsearch",
                   9300: "Elasticsearch transport", 11211: "Memcached", 27017: "MongoDB",
                   5432: "PostgreSQL", 3306: "MySQL", 1433: "MS SQL", 1521: "Oracle DB",
                   5984: "CouchDB", 8500: "Consul", 10250: "Kubelet", 6443: "Kubernetes API",
                   2049: "NFS", 445: "SMB", 3389: "RDP", 5900: "VNC", 23: "Telnet",
                   5985: "WinRM", 50000: "SAP/Jenkins agent"}


@dataclass
class Plan:
    addresses: list[str]
    ports: list[int]
    reduced: str = ""          # why fewer ports than the full list, if so
    skipped: list[str] = field(default_factory=list)


def plan(scope, extra_ips: list[str] = (), max_probes: int = 2_000_000, max_addresses: int = 1 << 20,
         ports: list[int] | None = None) -> Plan:
    """Addresses (from in-scope IP and CIDR entries plus extra seeds) and
    ports to scan, with every address checked against the scope."""
    networks = []
    for asset in scope.network_assets():
        if asset.kind in ("ip", "cidr"):
            try:
                networks.append(ipaddress.ip_network(asset.host, strict=False))
            except ValueError:
                continue
    addresses: list[str] = []
    seen: set[str] = set()
    skipped: list[str] = []
    total = sum(n.num_addresses for n in networks)
    if total > max_addresses:
        skipped.append(f"{total} addresses in the IP ranges is more than the limit of {max_addresses}; "
                       "only the first ones are scanned")
    for net in networks:
        hosts = [net.network_address] if net.num_addresses == 1 else net.hosts()
        for ip in hosts:
            if len(addresses) >= max_addresses:
                break
            text = str(ip)
            if text not in seen and scope.decide(text).allowed:
                seen.add(text)
                addresses.append(text)
    for raw in extra_ips:
        try:
            text = str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            continue
        if text not in seen and scope.decide(text).allowed:
            seen.add(text)
            addresses.append(text)
    ports = list(ports or PORTS)
    reduced = ""
    if addresses and len(addresses) * len(ports) > max_probes:
        keep = max(3, max_probes // len(addresses))
        full = len(ports)
        ports = ports[:keep]
        reduced = (f"{len(addresses)} addresses is a large range: scanning the top {keep} ports "
                   f"instead of {full}")
    return Plan(addresses, ports, reduced, skipped)


async def _scan(targets: list[tuple[str, int]], rate: float, timeout: float, concurrency: int,
                on_open, on_progress=None) -> int:
    interval = 1.0 / max(rate, 0.1)
    sem = asyncio.Semaphore(concurrency)
    next_slot = time.monotonic()
    opened = 0

    async def probe(address: str, port: int) -> None:
        nonlocal opened
        async with sem:
            try:
                _reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
            except (OSError, asyncio.TimeoutError):
                return
            opened += 1
            on_open(address, port)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (OSError, asyncio.TimeoutError):
                pass

    tasks = []
    for sent, (address, port) in enumerate(targets):
        if on_progress is not None and sent % 1000 == 0:
            on_progress(sent)
        now = time.monotonic()
        if next_slot > now:
            await asyncio.sleep(next_slot - now)
        next_slot = max(next_slot, time.monotonic()) + interval
        tasks.append(asyncio.create_task(probe(address, port)))
        if len(tasks) >= concurrency * 4:
            tasks = [t for t in tasks if not t.done()]
    if tasks:
        await asyncio.gather(*tasks)
    return opened


def scan(addresses: list[str], ports: list[int], rate: float, *, timeout: float = 3.0,
         concurrency: int = 200, on_open=lambda _a, _p: None, on_progress=None) -> dict[str, list[int]]:
    """Connect scan; returns {address: [open ports]}. Ports are tried in
    priority order for every address before moving to the next port, so a
    run cut short still covers the most useful ports everywhere."""
    found: dict[str, list[int]] = {}

    def record(address: str, port: int) -> None:
        found.setdefault(address, []).append(port)
        on_open(address, port)

    targets = [(a, p) for p in ports for a in addresses]
    asyncio.run(_scan(targets, rate, timeout, concurrency, record, on_progress))
    return {a: sorted(p) for a, p in found.items()}


# --------------------------------------------------------------------------
# Telling real services from "everything is open"
# --------------------------------------------------------------------------

# Many firewalls, load balancers and DDoS shields complete the TCP handshake on
# every port, whatever is behind them. A connect scan alone cannot tell, so an
# address that "has" most ports open is treated as answering everything.
ACCEPTS_ALL_MIN_PORTS = 15
ACCEPTS_ALL_RATIO = 0.4


def accepts_everything(open_ports: list[int], scanned: int) -> bool:
    return len(open_ports) >= ACCEPTS_ALL_MIN_PORTS and len(open_ports) >= ACCEPTS_ALL_RATIO * scanned


def _exchange(address: str, port: int, payload: bytes | None, timeout: float = 4.0) -> bytes:
    import socket
    with socket.create_connection((address, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        chunks, size = [], 0
        while size < 4096:
            try:
                data = sock.recv(4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
            size += len(data)
            if payload and size:
                break
        return b"".join(chunks)


def _http(address: str, path: str, user_agent: str) -> bytes:
    return (f"GET {path} HTTP/1.0\r\nHost: {address}\r\nUser-Agent: {user_agent}\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n").encode()


def verify(address: str, port: int, user_agent: str = "Mozilla/5.0") -> str | None:
    """One harmless protocol exchange that only the real service answers
    correctly. Returns evidence, or None if the service did not identify
    itself (or there is no check for this port). Never logs in, never reads
    data."""
    checks = {
        6379: (b"PING\r\n", lambda r: "Redis answers PING without a password" if r.startswith(b"+PONG")
               else "Redis is reachable (asks for a password)" if b"NOAUTH" in r or b"-DENIED" in r else None),
        11211: (b"version\r\n", lambda r: "Memcached answers: " + r[:40].decode("ascii", "replace").strip()
                if r.startswith(b"VERSION") else None),
        9200: (_http(address, "/", user_agent), lambda r: "Elasticsearch cluster info returned"
               if b'"cluster_name"' in r or b"You Know, for Search" in r else None),
        2375: (_http(address, "/version", user_agent), lambda r: "Docker API answers /version"
               if b'"ApiVersion"' in r else None),
        8500: (_http(address, "/v1/agent/self", user_agent), lambda r: "Consul agent API answers"
               if b'"Config"' in r or b'"Member"' in r else None),
        5984: (_http(address, "/", user_agent), lambda r: "CouchDB answers" if b'"couchdb"' in r.lower() else None),
        3306: (None, lambda r: "MySQL greeting: " + _printable(r[5:40]) if len(r) > 5 and r[4] in (9, 10)
               else None),
        23: (None, lambda r: "Telnet banner" + (": " + _printable(r) if _printable(r) else "")
             if r[:1] == b"\xff" or b"login" in r.lower() else None),
    }
    if port not in checks:
        return None
    payload, test = checks[port]
    try:
        reply = _exchange(address, port, payload)
    except OSError:
        return None
    return test(reply) if reply else None


def _printable(data: bytes) -> str:
    return "".join(chr(b) for b in data if 32 <= b < 127).strip()[:60]
