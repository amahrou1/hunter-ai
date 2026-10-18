"""Phase 04: map. Crawl every live in-scope web service and build the request
inventory: pages, API endpoints, parameters, forms and JavaScript files.

- katana crawls through the scope guard (scope-checked, rate-limited,
  logged), following only the same host, reading robots.txt / sitemap.xml
  and parsing JavaScript for endpoints. Forms are recorded, never submitted.
- Services are crawled highest priority first, so hosts the operator asked
  to focus on (`hunt tell ... focus x`) come first.
- Progress is saved per batch of services: a stopped or crashed run
  continues with the services not crawled yet, and a time budget keeps one
  huge program from eating the whole run (what is left is reported as a gap).
"""

from __future__ import annotations

import json
import math
import time
from collections import Counter
from urllib.parse import urlsplit

from .. import state as st
from ..tools import chunked
from ..toolchain import tool_path
from .base import Context, Phase, PhaseResult

SKIP_EXTENSIONS = "png,jpg,jpeg,gif,svg,ico,webp,avif,bmp,css,woff,woff2,ttf,eot,otf,mp4,mp3,webm,avi,mov,wav"
# Parameter names that usually deserve a closer look in later phases.
INTERESTING_PARAMS = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id", "order", "order_id", "invoice",
    "customer", "customer_id", "email", "redirect", "redirect_uri", "return", "returnurl", "return_url",
    "next", "url", "uri", "callback", "continue", "dest", "destination", "file", "path", "template",
    "page", "doc", "token", "key", "api_key", "apikey", "secret", "role", "admin", "debug", "q", "query",
    "search", "lang", "include", "format", "type", "cmd", "exec",
}


class MapPhase(Phase):
    id = "04-map"
    name = "Mapping and crawl, request inventory, JavaScript collection"
    version = "1.0"
    build_step = 4
    requires = ("00-intake", "03-probe")

    def run(self, ctx: Context) -> PhaseResult:
        store = ctx.assets()
        if store.service_count() == 0:
            return PhaseResult(st.NOT_APPLICABLE, "no live web service to crawl")
        binary = tool_path("katana")
        if not binary:
            ctx.block("The katana tool", "katana is not installed, so the sites could not be crawled. "
                      "Run: hunt tools install", [])
            return PhaseResult(st.BLOCKED, "katana not installed")

        cfg = {"depth": 3, "minutes_per_site": 5, "max_hours": 6, "batch": 10, **ctx.settings.get("crawl", {})}
        scope = ctx.scope()
        todo = store.work_services(scope, "crawled")
        before = store.endpoint_count()
        ctx.log(f"{len(todo)} site(s) to crawl, {before} endpoint(s) already known")

        deadline = time.monotonic() + float(cfg["max_hours"]) * 3600
        gaps: list[str] = []
        crawled = blocked_out = 0
        for batch in chunked(todo, int(cfg["batch"])):
            if time.monotonic() > deadline:
                left = len(todo) - crawled
                gaps.append(f"crawl time budget ({cfg['max_hours']} h) used up; {left} site(s) not crawled "
                            f"yet (they are crawled on the next start)")
                break
            new, out = self._crawl(ctx, store, scope, binary, batch, cfg)
            blocked_out += out
            for svc in batch:
                store.mark_service(svc["id"], "crawled")
            crawled += len(batch)
            ctx.log(f"crawled {crawled}/{len(todo)} site(s); +{new} endpoint(s)")

        total = store.endpoint_count()
        self._write_views(ctx, store)
        self._announce(ctx, store, crawled, total - before, blocked_out)
        summary = f"{total} endpoint(s) known ({total - before} new) from {crawled} site(s) crawled"
        if blocked_out:
            summary += f"; {blocked_out} out-of-scope link(s) ignored"
        status = st.PARTIAL if gaps else st.DONE
        return PhaseResult(status, summary, gaps=gaps)

    # ------------------------------------------------------------ crawling
    def _crawl(self, ctx: Context, store, scope, binary, batch, cfg) -> tuple[int, int]:
        rps = max(1, int(scope.rate_limit_rps))
        minutes = int(cfg["minutes_per_site"])
        parallel = min(5, len(batch))
        cmd = [
            str(binary), "-silent", "-jsonl", "-nc", "-or", "-ob", "-duc",
            "-d", str(int(cfg["depth"])), "-jc", "-kf", "all", "-fx", "-iqp",
            "-fs", "fqdn",                       # stay on the same host
            "-ct", f"{minutes}m", "-timeout", "15", "-retry", "1",
            "-c", "10", "-p", str(parallel), "-rl", str(rps),
            "-ef", SKIP_EXTENSIONS,
            "-proxy", ctx.proxy().url,
        ]
        rounds = math.ceil(len(batch) / parallel)
        run = ctx.active_runner().run(
            "katana", cmd, name=f"katana-{batch[0]['id']}", stdin_lines=[svc["url"] for svc in batch],
            timeout_s=rounds * minutes * 60 + 600)
        new = out = 0
        for record in run.json_lines():
            request = record.get("request") or {}
            response = record.get("response") or {}
            url = str(request.get("endpoint") or "")
            if not url:
                continue
            if not scope.decide_url(url).allowed:
                out += 1
                continue
            headers = response.get("headers") or {}
            status = response.get("status_code")
            if status in (None, 0) and response.get("error"):
                continue
            if store.add_endpoint(str(request.get("method") or "GET"), url, _source(request),
                                  status=status, content_type=headers.get("content-type", ""),
                                  length=response.get("content_length")):
                new += 1
            for form in response.get("forms") or []:
                action = str(form.get("action") or url)
                if not scope.decide_url(action).allowed:
                    out += 1
                    continue
                params = [str(p) for p in form.get("parameters") or []]
                body = "&".join(f"{p}=" for p in params)
                if store.add_endpoint(str(form.get("method") or "GET"), action, "form", body=body):
                    new += 1
        return new, out

    # --------------------------------------------------------------- views
    def _write_views(self, ctx: Context, store) -> None:
        rows = store.endpoints()
        lines = [f"{r['method']:<6} {r['status'] or '-':<4} {r['url']}" + (f"   [body: {r['body']}]" if r["body"] else "")
                 for r in rows if not r["is_js"]]
        (ctx.target.output / "endpoints.txt").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        js = sorted({r["url"] for r in rows if r["is_js"]})
        (ctx.target.output / "js_files.txt").write_text("\n".join(js) + ("\n" if js else ""), encoding="utf-8")
        counts = Counter()
        for r in rows:
            for name in json.loads(r["params"] or "[]"):
                counts[name] += 1
            if r["body"]:
                for pair in r["body"].split("&"):
                    if pair.split("=", 1)[0]:
                        counts[pair.split("=", 1)[0]] += 1
        param_lines = [f"{n:>5}  {name}{'   <- interesting' if name.lower() in INTERESTING_PARAMS else ''}"
                       for name, n in counts.most_common()]
        (ctx.target.output / "params.txt").write_text("\n".join(param_lines) + ("\n" if param_lines else ""),
                                                     encoding="utf-8")

    def _announce(self, ctx: Context, store, crawled: int, new: int, out: int) -> None:
        rows = store.endpoints()
        forms = sum(1 for r in rows if r["source"] == "form")
        js = sum(1 for r in rows if r["is_js"])
        api = sum(1 for r in rows if "/api" in urlsplit(r["url"]).path.lower() or "graphql" in r["url"].lower())
        lines = [f"Sites crawled this run: {crawled}",
                 f"Endpoints known: {len(rows)} ({new} new)",
                 f"API-looking endpoints: {api}",
                 f"Forms (recorded, never submitted): {forms}",
                 f"JavaScript files: {js}"]
        if out:
            lines.append(f"Out-of-scope links ignored: {out}")
        lines.append(f"Lists: {ctx.target.output / 'endpoints.txt'}, params.txt, js_files.txt")
        ctx.notify("Mapping done", "\n".join(lines))


def _source(request: dict) -> str:
    tag = str(request.get("tag") or "")
    if tag == "script" or str(request.get("source") or "").lower().endswith(".js"):
        return "js"
    if tag in ("robotstxt", "sitemapxml"):
        return tag
    return "crawl"
