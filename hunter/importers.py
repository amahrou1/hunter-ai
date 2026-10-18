"""Turn tool output into inventory rows, with a scope check on every row.

Used by `hk import <tool> <file>` (the AI runs a tool, then imports its
output) so parsing and storage are the same tested code whoever drives the
tool. Every importer returns a small dict of counts for the agent to read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from . import assets as A
from . import scope as sc

INTERESTING = ("admin", "api", "dev", "staging", "test", "internal", "portal", "dashboard",
               "auth", "login", "vpn", "git", "jenkins", "gateway", "graphql", "console")


def _records(path: Path) -> Iterator[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.strip()
    if stripped.startswith("{") and "\n{" not in stripped:
        try:
            data = json.loads(stripped)          # one JSON document (ffuf -o file)
            for key in ("results", "data"):
                if isinstance(data.get(key), list):
                    yield from (r for r in data[key] if isinstance(r, dict))
                    return
            yield data
            return
        except ValueError:
            pass
    if stripped.startswith("["):
        try:
            yield from (r for r in json.loads(stripped) if isinstance(r, dict))
            return
        except ValueError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except ValueError:
                continue
        elif line and " " not in line:
            yield {"host": line}                  # plain list of names


def subfinder(store: A.Assets, scope: sc.Scope, path: Path, source: str = "subfinder") -> dict:
    added = out = 0
    for record in _records(path):
        host = str(record.get("host") or record.get("input") or "").strip().lower().rstrip(".")
        if not host or "*" in host:
            continue
        allowed = scope.decide(host).allowed
        out += not allowed
        if store.add_host(host, A.IN if allowed else A.OUT, source):
            added += 1
    return {"new_hosts": added, "out_of_scope": out}


def dnsx(store: A.Assets, scope: sc.Scope, path: Path) -> dict:
    resolved = 0
    for record in _records(path):
        host = str(record.get("host", "")).strip().lower()
        if not host:
            continue
        if not scope.decide(host).allowed:
            store.add_host(host, A.OUT, "dnsx")
            continue
        store.add_host(host, A.IN, "dnsx")
        addresses = list(record.get("a") or []) + list(record.get("aaaa") or [])
        cnames = record.get("cname") or []
        cname = cnames[0] if isinstance(cnames, list) and cnames else (cnames if isinstance(cnames, str) else "")
        store.set_resolution(host, addresses, cname)
        resolved += 1
    counts = store.host_counts()
    return {"resolved": resolved, "third_party": counts.get(A.THIRD_PARTY, 0),
            "takeover_candidates": len(store.takeover_candidates())}


def priority(host: str, status: int | None, tech: list | str, focus=lambda _h: False) -> int:
    if focus(host):
        return 100
    score = 50
    if any(token in host for token in INTERESTING):
        score += 20
    if status in (401, 403):
        score += 15
    if status and 200 <= status < 300:
        score += 5
    blob = json.dumps(tech).lower()
    if any(t in blob for t in ("graphql", "swagger", "openapi", "jenkins", "gitlab", "grafana")):
        score += 15
    return min(score, 100)


def httpx(store: A.Assets, scope: sc.Scope, path: Path, focus=lambda _h: False) -> dict:
    services = skipped = 0
    probed = set()
    for record in _records(path):
        url = str(record.get("url") or "")
        host = str(record.get("input") or record.get("host") or "").split(":")[0].lower()
        if not url or not host:
            continue
        if not scope.decide_url(url).allowed:
            skipped += 1
            continue
        port = int(record.get("port") or (443 if url.startswith("https") else 80))
        scheme = "https" if url.startswith("https") else "http"
        tech = record.get("tech") or record.get("technologies") or []
        status = record.get("status_code") or record.get("status-code")
        store.add_host(host, A.IN, "httpx")
        store.upsert_service(
            host, port, scheme, url=url, status=status,
            title=(record.get("title") or "")[:300],
            server=(record.get("webserver") or record.get("web-server") or "")[:120],
            tech=json.dumps(tech) if tech else "",
            content_type=(record.get("content_type") or record.get("content-type") or "")[:120],
            content_length=record.get("content_length") or record.get("content-length"),
            body_hash=record.get("hash", {}).get("body_sha256") if isinstance(record.get("hash"), dict)
            else record.get("hash"),
            priority=priority(host, status, tech, focus))
        probed.add(host)
        services += 1
    store.mark_probed(probed)
    return {"services": services, "hosts_with_services": len(probed), "out_of_scope_skipped": skipped}


def katana(store: A.Assets, scope: sc.Scope, path: Path) -> dict:
    new = out = forms = 0
    for record in _records(path):
        request = record.get("request") or {}
        response = record.get("response") or {}
        url = str(request.get("endpoint") or record.get("url") or "")
        if not url:
            continue
        if not scope.decide_url(url).allowed:
            out += 1
            continue
        headers = response.get("headers") or {}
        tag = str(request.get("tag") or "")
        source = "js" if tag == "script" or str(request.get("source") or "").endswith(".js") else "crawl"
        if store.add_endpoint(str(request.get("method") or "GET"), url, source,
                              status=response.get("status_code"), content_type=headers.get("content-type", ""),
                              length=response.get("content_length")):
            new += 1
        for form in response.get("forms") or []:
            action = str(form.get("action") or url)
            if not scope.decide_url(action).allowed:
                out += 1
                continue
            body = "&".join(f"{p}=" for p in form.get("parameters") or [])
            if store.add_endpoint(str(form.get("method") or "GET"), action, "form", body=body):
                new += 1
                forms += 1
    return {"new_endpoints": new, "forms": forms, "out_of_scope_ignored": out}


def ffuf(store: A.Assets, scope: sc.Scope, path: Path, ignore: set[tuple] = frozenset()) -> dict:
    """ignore: (status, length) pairs known to be noise for these hosts."""
    new = skipped = noise = 0
    hits = []
    for record in _records(path):
        url = str(record.get("url") or "")
        status, length = record.get("status"), record.get("length")
        if not url or not scope.decide_url(url).allowed:
            skipped += 1
            continue
        if (status, length) in ignore:
            noise += 1
            continue
        if store.add_endpoint("GET", url, "discover", status=status,
                              content_type=record.get("content-type") or "", length=length):
            new += 1
        hits.append({"url": url, "status": status, "length": length})
    return {"new_endpoints": new, "noise_ignored": noise, "out_of_scope_skipped": skipped, "hits": hits}


IMPORTERS = {"subfinder": subfinder, "dnsx": dnsx, "httpx": httpx, "katana": katana, "ffuf": ffuf}
