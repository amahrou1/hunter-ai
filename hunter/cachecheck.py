"""Web-cache poisoning / deception probe (`hk cache <url>`).

Two read-only checks, both detect-only (they never try to actually poison a
shared cache or amplify a DoS):

1. Unkeyed-header reflection: add a header a cache is unlikely to key on
   (X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Proto, X-Host) with a
   unique marker and see whether the marker is reflected into a cacheable
   response (X-Cache/CF-Cache-Status HIT, or an Age header). Reflected + cached
   = a poisoning candidate. A per-request cache-buster query keeps the probe on
   its OWN cache key, so a real shared cache is never poisoned.

2. Cache deception: request the SAME path with a static-looking suffix
   (/path.css, /path/x.js, /path;%2e.css). If the response is the dynamic page
   AND it becomes cacheable because of the extension, a shared cache may store a
   per-user page under a public URL - deception. Detected via the same cache
   headers; no credentials are sent here (that is the operator's confirmation).

It records nothing itself; the caller decides lead vs finding. Everything goes
through the scope proxy.
"""

from __future__ import annotations

import hashlib
import secrets as _secrets
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

_CACHE_HINT_HEADERS = ("x-cache", "cf-cache-status", "x-cache-hits", "age",
                       "x-served-by", "x-cache-status")
_UNKEYED_HEADERS = ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
                    "X-Host", "X-Forwarded-Server")
_DECEPTION_SUFFIXES = (".css", ".js", "/x.css", "/x.js", ";%2e.css", "%0A.css")


def _req(opener, url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=15) as resp:
            body = resp.read(20000)
            return _shape(resp.status, dict(resp.headers), body)
    except urllib.error.HTTPError as exc:
        body = exc.read(20000) if hasattr(exc, "read") else b""
        hdrs = dict(exc.headers) if exc.headers else {}
        out = _shape(exc.code, hdrs, body)
        out["blocked"] = bool(exc.headers and exc.headers.get("X-Hunter-Blocked"))
        return out
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:120]}


def _shape(status: int, headers: dict, body: bytes) -> dict:
    low = {k.lower(): v for k, v in headers.items()}
    cache_hdrs = {h: low[h] for h in _CACHE_HINT_HEADERS if h in low}
    return {"status": status, "len": len(body),
            "hash": hashlib.sha256(body).hexdigest()[:16],
            "ctype": low.get("content-type", ""),
            "cache_headers": cache_hdrs,
            "cacheable": _is_cacheable(low),
            "body_text": body[:20000].decode("utf-8", "replace")}


def _is_cacheable(low: dict) -> bool:
    cc = low.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return False
    xc = (low.get("x-cache", "") + low.get("cf-cache-status", "")).lower()
    return "hit" in xc or "age" in low or "public" in cc or "max-age" in cc


def _buster(url: str) -> str:
    parts = urlsplit(url)
    q = (parts.query + "&" if parts.query else "") + f"cb={_secrets.token_hex(4)}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, q, parts.fragment))


def _with_suffix(url: str, suffix: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path + suffix, parts.query, parts.fragment))


def probe(url: str, opener) -> dict:
    result = {"url": url, "poisoning": [], "deception": []}

    # --- 1. Unkeyed-header reflection (on our own cache-busted key) ---
    for header in _UNKEYED_HEADERS:
        marker = f"{_secrets.token_hex(6)}.hunter.invalid"
        busted = _buster(url)
        res = _req(opener, busted, {header: marker})
        if "error" in res or res.get("blocked"):
            continue
        reflected = marker in res["body_text"]
        if reflected:
            result["poisoning"].append({
                "header": header, "marker_reflected": True,
                "cacheable": res["cacheable"], "cache_headers": res["cache_headers"],
                "note": "unkeyed header reflected" + (" into a cacheable response"
                        if res["cacheable"] else " (confirm the cache keys on it)"),
            })

    # --- 2. Cache deception (static-extension suffix) ---
    base = _req(opener, _buster(url), {})
    if "error" not in base and not base.get("blocked"):
        for suffix in _DECEPTION_SUFFIXES:
            res = _req(opener, _buster(_with_suffix(url, suffix)), {})
            if "error" in res or res.get("blocked"):
                continue
            # Same dynamic page served under a static-looking URL AND cacheable.
            same_page = res["hash"] == base["hash"] and res["status"] == base["status"]
            if same_page and res["cacheable"]:
                result["deception"].append({
                    "suffix": suffix, "status": res["status"],
                    "cache_headers": res["cache_headers"],
                    "note": "dynamic page served and cacheable under a static-looking URL",
                })
    return result
