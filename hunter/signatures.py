"""Content signatures: given a URL path and the start of its body, decide
whether a sensitive file really contains what its name suggests (a .git/HEAD
that is actually a git HEAD, a .env with KEY=value lines, a real OpenAPI doc).
Turns a bare 200 into a confirmed lead, and keeps false positives out.
Secret values are never returned, only their names."""

from __future__ import annotations

import re


def _text(body: bytes) -> str:
    return body[:4000].decode("utf-8", errors="replace")


def _env_keys(body: bytes) -> str | None:
    text = _text(body)
    if "<html" in text.lower():
        return None
    keys = re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=", text)
    return ", ".join(sorted(set(keys))[:30]) if len(set(keys)) >= 2 else None


# (lead kind, path test, content test returning evidence or None)
SIGNATURES = [
    ("exposed-git", lambda p: p.endswith(".git/head"),
     lambda b: "git HEAD: " + _text(b).strip()[:60] if re.match(rb"\s*(ref: refs/|[0-9a-f]{40})", b) else None),
    ("exposed-git", lambda p: p.endswith(".git/config"),
     lambda b: "git config with [core] section" if b"[core]" in b[:4000] else None),
    ("exposed-svn", lambda p: p.endswith(".svn/entries") or p.endswith(".svn/wc.db"),
     lambda b: "svn metadata" if b[:20].strip().isdigit() or b.startswith(b"SQLite format 3") else None),
    ("env-file", lambda p: "/.env" in p or p.endswith(".env"),
     lambda b: ("variables: " + k) if (k := _env_keys(b)) else None),
    ("ds-store", lambda p: p.endswith(".ds_store"),
     lambda b: "macOS .DS_Store (lists folder contents)" if b.startswith(b"\x00\x00\x00\x01Bud1") else None),
    ("api-docs", lambda p: any(x in p for x in ("swagger", "openapi", "api-docs")),
     lambda b: "OpenAPI/Swagger document" if re.search(rb'"(swagger|openapi)"\s*:', b[:20000])
     or b"swagger-ui" in b[:20000].lower() else None),
    ("debug-endpoint", lambda p: "actuator" in p,
     lambda b: "Spring Boot actuator" if b'"_links"' in b[:20000] or b'"propertySources"' in b[:20000]
     or b'"status"' in b[:200] else None),
    ("debug-endpoint", lambda p: p.endswith("server-status") or p.endswith("server-info"),
     lambda b: "Apache server status page" if b"Apache Server" in b[:20000] else None),
    ("debug-endpoint", lambda p: "phpinfo" in p or p.endswith("info.php"),
     lambda b: "phpinfo() output" if b"phpinfo()" in b[:20000] or b"PHP Version" in b[:20000] else None),
    ("backup-file", lambda p: p.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")),
     lambda b: "archive file" if b.startswith((b"PK\x03\x04", b"\x1f\x8b")) or b[257:262] == b"ustar" else None),
    ("backup-file", lambda p: p.endswith(".sql"),
     lambda b: "SQL dump" if re.search(rb"(CREATE TABLE|INSERT INTO|DROP TABLE)", b[:20000], re.I) else None),
    ("log-file", lambda p: p.endswith(".log") or p.endswith("_history"),
     lambda b: "log or shell history" if b and b"<html" not in b[:2000].lower() else None),
    ("graphql", lambda p: p.endswith("graphql") or p.endswith("graphiql") or p.endswith("playground"),
     lambda b: "GraphQL endpoint" if re.search(rb"(graphql|graphiql|must provide|query)", b[:5000], re.I) else None),
]


def check(path: str, body: bytes) -> list[tuple[str, str]]:
    """[(lead_kind, evidence)] for every signature whose path and content match."""
    path = path.lower()
    out = []
    for kind, path_test, content_test in SIGNATURES:
        if path_test(path):
            evidence = content_test(body)
            if evidence:
                out.append((kind, evidence))
    return out
