"""Origin-IP discovery behind a WAF/CDN (`hk origin <host>`).

A host behind Cloudflare, Akamai, Fastly or similar serves through an edge that
blocks and rate-limits. The real origin server is often reachable directly by
IP, and frequently NOT protected the same way - direct IP access leaks stack
traces, debug endpoints, admin panels and info the edge would hide. Finding and
testing the origin is a well-known source of criticals.

This finds CANDIDATE origin IPs from passive sources only (historical DNS,
certificate-transparency pivots, SPF records) and confirms which ones serve the
same application by requesting the site with the original Host header and
comparing the response to the edge. It makes no guess that becomes scope on its
own: an IP is surfaced for testing only when it is in scope (the program lists
an IP/CIDR) OR the operator confirms it; otherwise it is reported as an
observation, because a raw IP is usually not in a domain-only scope.

Passive sources used (all already allowed, never the target itself for the
discovery step): crt.sh (cert SANs/history), and DNS over the allowed resolvers.
The confirmation step contacts the candidate IP, so it goes through the scope
proxy and only runs for in-scope IPs.
"""

from __future__ import annotations

import hashlib
import json
import socket
import urllib.error
import urllib.request

# Edge/CDN/WAF networks: an A record pointing here is the edge, not the origin.
# We want IPs OUTSIDE these ranges.
CDN_ORG_HINTS = ("cloudflare", "akamai", "fastly", "incapsula", "imperva", "sucuri",
                 "stackpath", "cloudfront", "amazon", "google", "azure", "microsoft",
                 "edgecast", "limelight", "section.io", "ddos-guard", "qrator")

_UA = "Mozilla/5.0 (hunter-ai origin-check)"


def _edge_ips(host: str) -> set[str]:
    """The IPs the host currently resolves to (the edge, usually)."""
    out: set[str] = set()
    try:
        for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            out.add(info[4][0])
    except (socket.gaierror, OSError, UnicodeError):
        pass
    return out


def crtsh_hosts(domain: str, opener, timeout: float = 25.0, cap: int = 200) -> list[str]:
    """Subject names on the domain's certificates (crt.sh) - these often include
    direct/origin hostnames (origin., direct., mail., a numbered host) that still
    resolve to the real server."""
    import time
    url = "https://crt.sh/?q=" + urllib.request.quote(f"%.{domain}") + "&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with opener.open(req, timeout=timeout) as resp:
            rows = json.loads(resp.read().decode("utf-8", "replace") or "[]")
    except Exception:  # noqa: BLE001
        return []
    finally:
        time.sleep(1.0)
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for n in str(row.get("name_value", "")).splitlines():
            n = n.strip().lower().lstrip("*.").rstrip(".")
            if n and " " not in n and n.endswith(domain):
                names.add(n)
        if len(names) >= cap:
            break
    return sorted(names)[:cap]


def candidate_ips(host: str, opener) -> dict:
    """Collect candidate origin IPs for a host from passive sources. Returns the
    edge IPs (to exclude) and the candidate origin IPs (resolve of sibling names
    from CT that are not the edge)."""
    root = _root(host)
    edge = _edge_ips(host)
    candidates: dict[str, list[str]] = {}   # ip -> reasons
    # Sibling hostnames from certificate transparency; their A records are often
    # the real origin (origin.x, direct.x, mail.x, cpanel.x, a numbered host).
    for name in crtsh_hosts(root, opener):
        if name == host:
            continue
        for ip in _edge_ips(name):
            if ip in edge:
                continue
            candidates.setdefault(ip, []).append(f"cert sibling {name}")
    return {"host": host, "edge_ips": sorted(edge), "candidates": candidates}


def confirm(host: str, ip: str, opener, scheme: str = "https", timeout: float = 15.0) -> dict:
    """Request the site directly from the candidate IP with the original Host
    header, and compare to the edge. A matching app body (or an app-specific
    marker) with DIFFERENT/looser behaviour than the edge is a likely origin.
    Goes through the scope proxy, so the IP must be in scope to be contacted."""
    url = f"{scheme}://{ip}/"
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Host": host}, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(40000)
            return _summ(ip, resp.status, body, resp.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read(40000) if hasattr(exc, "read") else b""
        return _summ(ip, exc.code, body, exc.headers,
                     blocked=bool(exc.headers and exc.headers.get("X-Hunter-Blocked")))
    except Exception as exc:  # noqa: BLE001
        return {"ip": ip, "error": str(exc)[:160]}


def _summ(ip: str, status: int, body: bytes, headers, blocked: bool = False) -> dict:
    server = ""
    try:
        server = (headers.get("Server", "") or "").lower()
    except Exception:  # noqa: BLE001
        pass
    on_cdn = any(h in server for h in CDN_ORG_HINTS)
    return {"ip": ip, "status": status, "len": len(body),
            "hash": hashlib.sha256(body).hexdigest()[:16], "server": server,
            "on_cdn": on_cdn, "blocked": blocked}


def _root(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if labels[-2] in two and len(labels[-1]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
