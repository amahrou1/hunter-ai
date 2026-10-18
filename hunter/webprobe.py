"""Shared web-probe helpers: fetch a URL through the scope proxy, classify a
host's 'not found' answer (so later fuzzing can tell real pages from catch-all
responses), and build per-service baselines. Used by `hk` and any phase."""

from __future__ import annotations

import hashlib
import json
import secrets
import ssl
import urllib.error
import urllib.request


def opener_through(proxy_url: str, ca_file: str | None):
    handlers = [urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})]
    if ca_file:
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url: str, limit: int = 20000) -> dict:
    try:
        with opener.open(url, timeout=20) as resp:
            body = resp.read(limit)
            return {"status": resp.status, "len": len(body),
                    "hash": hashlib.sha256(body).hexdigest()[:16],
                    "ctype": resp.headers.get("content-type", "")}
    except urllib.error.HTTPError as exc:
        body = exc.read(limit) if hasattr(exc, "read") else b""
        return {"status": exc.code, "len": len(body),
                "hash": hashlib.sha256(body).hexdigest()[:16],
                "ctype": exc.headers.get("content-type", "") if exc.headers else "",
                "blocked": bool(exc.headers and exc.headers.get("X-Hunter-Blocked"))}
    except Exception as exc:  # noqa: BLE001 - a probe failure is data, not a crash
        return {"error": str(exc)[:120]}


def classify(root: dict, samples: list[dict]) -> dict:
    statuses = {s.get("status") for s in samples if "status" in s}
    hashes = {s.get("hash") for s in samples if "hash" in s}
    if any(s.get("blocked") for s in samples):
        kind = "blocked"
    elif not statuses:
        kind = "unknown"
    elif statuses == {404} and len(hashes) <= 1:
        kind = "hard_404"
    elif statuses & {401, 403}:
        kind = "uniform_gate"
    elif len(hashes) == 1 and root.get("hash") in hashes:
        kind = "soft_404_like_root"
    elif len(hashes) == 1:
        kind = "soft_404"
    else:
        kind = "unstable"
    return {"kind": kind, "not_found_status": sorted(s for s in statuses if s),
            "sample": samples[0] if samples else {}, "root_status": root.get("status")}


def build_baselines(store, scope, opener, progress=lambda *_a: None) -> int:
    """Record each in-scope service's 'not found' answer; skip ones already
    baselined (an 'unknown' baseline, where every probe failed, is retried)."""
    done = 0
    services = store.services()
    for index, svc in enumerate(services):
        if index % 10 == 0:
            progress(index, len(services))
        if not scope.host_in_scope(svc["host"]):
            continue
        if svc["baseline"] and json.loads(svc["baseline"]).get("kind") != "unknown":
            continue
        base = svc["url"].rstrip("/")
        samples = [fetch(opener, f"{base}/hunter-{secrets.token_hex(8)}/does-not-exist") for _ in range(2)]
        store.set_baseline(svc["id"], classify(fetch(opener, base + "/"), samples))
        done += 1
    return done
