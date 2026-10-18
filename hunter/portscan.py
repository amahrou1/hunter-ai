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
                on_open) -> int:
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
    for address, port in targets:
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
         concurrency: int = 200, on_open=lambda _a, _p: None) -> dict[str, list[int]]:
    """Connect scan; returns {address: [open ports]}. Ports are tried in
    priority order for every address before moving to the next port, so a
    run cut short still covers the most useful ports everywhere."""
    found: dict[str, list[int]] = {}

    def record(address: str, port: int) -> None:
        found.setdefault(address, []).append(port)
        on_open(address, port)

    targets = [(a, p) for p in ports for a in addresses]
    asyncio.run(_scan(targets, rate, timeout, concurrency, record))
    return {a: sorted(p) for a, p in found.items()}
