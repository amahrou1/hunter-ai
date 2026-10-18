"""Phase 05: content discovery. Look for files and paths that are not linked
anywhere: admin panels, API documentation, debug endpoints, version-control
folders, configuration and backup files.

- ffuf runs through the scope guard with a curated built-in wordlist (or the
  operator's own list, settings: discover.wordlist), one site at a time,
  highest priority first. Its auto-calibration plus the per-site baselines
  from phase 03 drop catch-all "not found" pages.
- A hit on a sensitive name is checked by content (a .git/HEAD must look like
  a git HEAD, a .env must contain KEY=value lines, ...). Only then it becomes
  a lead "signature-match"; otherwise it stays a plain endpoint. Leads are
  not findings: phase 11 validates them. Secret values are never copied into
  notifications or logs (for .env only the variable names are kept).
- Progress is saved per site; a stopped run continues where it left off.
"""

from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

from .. import state as st
from ..toolchain import tool_path
from .base import Context, Phase, PhaseResult

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "discover.txt"
MATCH_CODES = "200,201,204,301,302,307,308,401,403,405,500"


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


class DiscoverPhase(Phase):
    id = "05-discover"
    name = "Content and parameter discovery"
    version = "1.0"
    build_step = 4
    requires = ("00-intake", "03-probe")

    def run(self, ctx: Context) -> PhaseResult:
        store = ctx.assets()
        if store.service_count() == 0:
            return PhaseResult(st.NOT_APPLICABLE, "no live web service to search")
        binary = tool_path("ffuf")
        if not binary:
            ctx.block("The ffuf tool", "ffuf is not installed, so hidden files could not be searched. "
                      "Run: hunt tools install", [])
            return PhaseResult(st.BLOCKED, "ffuf not installed")
        cfg = {"minutes_per_site": 5, "max_hours": 6, "wordlist": "", **ctx.settings.get("discover", {})}
        wordlist = Path(cfg["wordlist"]).expanduser() if cfg["wordlist"] else DEFAULT_WORDLIST
        if not wordlist.is_file():
            ctx.log(f"wordlist {wordlist} not found; using the built-in list")
            wordlist = DEFAULT_WORDLIST

        scope = ctx.scope()
        todo = store.work_services(scope, "discovered")
        ctx.log(f"{len(todo)} site(s) to search with {sum(1 for _ in wordlist.open())} paths each")
        deadline = time.monotonic() + float(cfg["max_hours"]) * 3600
        gaps: list[str] = []
        searched = hits = 0
        opener = self._opener(ctx)
        new_leads: list[str] = []
        for svc in todo:
            if time.monotonic() > deadline:
                gaps.append(f"discovery time budget ({cfg['max_hours']} h) used up; {len(todo) - searched} "
                            "site(s) not searched yet (they are searched on the next start)")
                break
            if not scope.host_in_scope(svc["host"]):   # avoided while running
                store.mark_service(svc["id"], "discovered")
                continue
            found, leads = self._search(ctx, store, scope, binary, svc, wordlist, cfg, opener)
            hits += found
            new_leads += leads
            store.mark_service(svc["id"], "discovered")
            searched += 1
            if searched % 25 == 0:
                ctx.log(f"searched {searched}/{len(todo)} site(s); {hits} hit(s), {len(new_leads)} lead(s)")

        self._write_views(ctx, store)
        self._announce(ctx, store, searched, hits, new_leads)
        summary = f"{searched} site(s) searched, {hits} hit(s), {len(new_leads)} new lead(s) to validate"
        return PhaseResult(st.PARTIAL if gaps else st.DONE, summary, gaps=gaps)

    # ----------------------------------------------------------- searching
    def _search(self, ctx, store, scope, binary, svc, wordlist, cfg, opener) -> tuple[int, list[str]]:
        base = svc["url"].rstrip("/")
        rps = max(1, int(scope.rate_limit_rps))
        cmd = [str(binary), "-u", f"{base}/FUZZ", "-w", str(wordlist), "-json", "-s", "-noninteractive",
               "-ac", "-mc", MATCH_CODES, "-t", "10", "-rate", str(rps), "-timeout", "10",
               "-maxtime", str(int(cfg["minutes_per_site"]) * 60), "-sf",
               "-x", ctx.proxy().url]
        run = ctx.active_runner().run("ffuf", cmd, name=f"ffuf-{svc['id']}",
                                      timeout_s=int(cfg["minutes_per_site"]) * 60 + 120)
        baseline = json.loads(svc["baseline"]) if svc["baseline"] else {}
        sample = baseline.get("sample") if isinstance(baseline.get("sample"), dict) else {}
        noise = {(sample.get("status"), sample.get("len"))} if sample.get("status") else set()
        found, leads = 0, []
        for record in run.json_lines():
            url = str(record.get("url") or "")
            status, length = record.get("status"), record.get("length")
            if not url or not scope.decide_url(url).allowed:
                continue
            if (status, length) in noise:
                continue          # identical to this site's "not found" answer
            found += 1
            store.add_endpoint("GET", url, "discover", status=status,
                               content_type=record.get("content-type") or "", length=length)
            if status in (200, 206):
                lead = self._check(store, opener, url)
                if lead:
                    leads.append(lead)
        return found, leads

    def _check(self, store, opener, url: str) -> str | None:
        path = url.split("?", 1)[0].lower()
        tests = [(kind, content) for kind, path_test, content in SIGNATURES if path_test(path)]
        if not tests:
            return None
        body = self._fetch(opener, url)
        if body is None:
            return None
        for kind, content in tests:
            evidence = content(body)
            if evidence and store.add_lead(kind, url, "05-discover", evidence, status="signature-match"):
                return f"{kind}: {url} ({evidence[:80]})"
        return None

    def _opener(self, ctx):
        proxy = ctx.proxy()
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy.url, "https": proxy.url}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(proxy.ca_bundle))))

    @staticmethod
    def _fetch(opener, url: str) -> bytes | None:
        try:
            with opener.open(url, timeout=20) as resp:
                return resp.read(65536)
        except (urllib.error.URLError, OSError, ValueError):
            return None

    # --------------------------------------------------------------- views
    def _write_views(self, ctx, store) -> None:
        rows = [r for r in store.endpoints() if r["source"] == "discover"]
        lines = [f"{r['status'] or '-':<4} {r['length'] or '-':>8}  {r['url']}" for r in rows]
        (ctx.target.output / "discovered.txt").write_text("\n".join(lines) + ("\n" if lines else ""),
                                                         encoding="utf-8")
        store.write_leads(ctx.target.output / "leads.txt")

    def _announce(self, ctx, store, searched: int, hits: int, new_leads: list[str]) -> None:
        lines = [f"Sites searched this run: {searched}",
                 f"Hidden paths found: {hits}",
                 f"New leads (content checked, NOT yet validated): {len(new_leads)}"]
        lines += [f"- {lead}" for lead in new_leads[:10]]
        if len(new_leads) > 10:
            lines.append(f"... and {len(new_leads) - 10} more")
        lines.append(f"Lists: {ctx.target.output / 'discovered.txt'}, leads.txt")
        ctx.notify("Discovery done", "\n".join(lines), "warn" if new_leads else "info")
