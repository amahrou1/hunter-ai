"""Virtual-host enumeration (`hk vhost <ip>`).

Many internal or staging apps answer only to a specific Host header on an IP
that otherwise shows a default page - they are not in DNS, so subdomain
enumeration misses them. This sends the SAME request to an IP with different
Host headers and reports the ones whose response differs from a random-Host
baseline: those are distinct virtual hosts worth testing.

Everything goes through the scope proxy (so the IP must be reachable in scope),
and only candidate names that are themselves in scope are tried - a vhost we
surface is one we are allowed to test. Read-only GETs.
"""

from __future__ import annotations

import hashlib
import secrets as _secrets
import urllib.error
import urllib.request


def _get(opener, ip_url: str, host_header: str) -> dict:
    req = urllib.request.Request(ip_url, headers={"Host": host_header}, method="GET")
    try:
        with opener.open(req, timeout=15) as resp:
            body = resp.read(20000)
            return {"status": resp.status, "len": len(body),
                    "hash": hashlib.sha256(body).hexdigest()[:16]}
    except urllib.error.HTTPError as exc:
        body = exc.read(20000) if hasattr(exc, "read") else b""
        return {"status": exc.code, "len": len(body),
                "hash": hashlib.sha256(body).hexdigest()[:16],
                "blocked": bool(exc.headers and exc.headers.get("X-Hunter-Blocked"))}
    except Exception as exc:  # noqa: BLE001 - a probe failure is data
        return {"error": str(exc)[:120]}


def _signature(r: dict) -> tuple:
    return (r.get("status"), r.get("hash"))


def probe(ip_url: str, candidates: list[str], opener) -> dict:
    """ip_url: http(s)://<ip>[:port]/ . candidates: in-scope host names to try.
    Returns the baseline and any candidate whose response differs from it."""
    # Two random baselines so a host-insensitive server (same answer to anything)
    # is detected and we do not flag everything.
    b1 = _get(opener, ip_url, f"{_secrets.token_hex(6)}.invalid")
    b2 = _get(opener, ip_url, f"{_secrets.token_hex(6)}.invalid")
    result = {"ip_url": ip_url, "baseline": b1, "vhosts": [], "tried": 0}
    if "error" in b1 or b1.get("blocked"):
        result["note"] = b1.get("error") or "baseline blocked by scope proxy"
        return result
    host_sensitive = _signature(b1) == _signature(b2)
    if not host_sensitive:
        # Random hosts already differ from each other: the server is noisy, a
        # diff would be meaningless. Bail rather than emit false vhosts.
        result["note"] = "server returns inconsistent responses to random Host; vhost diff unreliable"
        return result
    base_sig = _signature(b1)
    for name in candidates:
        res = _get(opener, ip_url, name)
        result["tried"] += 1
        if "error" in res or res.get("blocked"):
            continue
        if _signature(res) != base_sig and res.get("len", 0) > 0:
            result["vhosts"].append({"host": name, "status": res.get("status"),
                                     "len": res.get("len")})
    return result
