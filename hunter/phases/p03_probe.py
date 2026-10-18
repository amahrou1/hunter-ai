"""Phase 03: probe and fingerprint.

For every in-scope, resolved, first-party host, find which HTTP(S) services
are live, record status, title, server, technology and a body hash, and
build a per-host baseline (what a request to a path that does not exist
looks like). Later discovery and fuzzing use that baseline to tell a real
page from a catch-all "soft 404".

All traffic goes through the scope proxy, so it is scope-checked again,
rate-limited and logged. httpx does the probing; the baseline is two extra
requests per service to random non-existent paths.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.error
import urllib.request

from .. import assets as A
from .. import state as st
from ..toolchain import tool_path
from .base import Context, Phase, PhaseResult

INTERESTING = ("admin", "api", "dev", "staging", "test", "internal", "portal", "dashboard",
               "auth", "login", "vpn", "git", "jenkins", "gateway", "graphql", "console")


class ProbePhase(Phase):
    id = "03-probe"
    name = "Probe and fingerprint, per-host baselines"
    version = "1.0"
    build_step = 4
    requires = ("00-intake", "02-recon")

    def run(self, ctx: Context) -> PhaseResult:
        store = ctx.assets()
        hosts = [r["host"] for r in store.hosts(scope=A.IN, resolved=True)]
        if not hosts:
            return PhaseResult(st.NOT_APPLICABLE, "no resolved in-scope hosts to probe")

        binary = tool_path("httpx")
        if not binary:
            ctx.block("The httpx tool",
                      "httpx is not installed, so live web services could not be found. Run: hunt tools install",
                      [])
            return PhaseResult(st.BLOCKED, "httpx not installed")

        services = self._probe(ctx, store, binary, hosts)
        baselined = self._baselines(ctx, store)
        self._write_views(ctx, store)
        self._announce(ctx, len(hosts), services, baselined)

        if services == 0:
            return PhaseResult(st.PARTIAL, f"{len(hosts)} hosts probed, no live web service found")
        return PhaseResult(st.DONE, f"{services} live web service(s) across {len(hosts)} host(s); "
                           f"{baselined} baselined")

    # ------------------------------------------------------------- probing
    def _probe(self, ctx: Context, store: A.Assets, binary, hosts: list[str]) -> int:
        runner = ctx.active_runner()
        run = runner.run("httpx", [
            str(binary), "-silent", "-json", "-nc", "-follow-host-redirects",
            "-status-code", "-title", "-tech-detect", "-web-server",
            "-content-type", "-content-length", "-hash", "sha256",
            "-ports", "80,443,8080,8443", "-timeout", "15", "-retries", "1",
            "-rate-limit", str(max(1, int(ctx.scope().rate_limit_rps))),
        ], name="httpx-probe", timeout_s=3600, stdin_lines=hosts)

        count = 0
        for record in run.json_lines():
            url = record.get("url", "")
            host = str(record.get("input") or record.get("host") or "").split(":")[0].lower()
            if not url or not host:
                continue
            port = int(record.get("port") or (443 if url.startswith("https") else 80))
            scheme = "https" if url.startswith("https") else "http"
            tech = record.get("tech") or record.get("technologies") or []
            store.upsert_service(
                host, port, scheme, url=url,
                status=record.get("status_code") or record.get("status-code"),
                title=(record.get("title") or "")[:300],
                server=(record.get("webserver") or record.get("web-server") or "")[:120],
                tech=json.dumps(tech) if tech else "",
                content_type=(record.get("content_type") or record.get("content-type") or "")[:120],
                content_length=record.get("content_length") or record.get("content-length"),
                body_hash=record.get("hash", {}).get("body_sha256") if isinstance(record.get("hash"), dict)
                else record.get("hash"),
                priority=self._priority(host, record),
            )
            count += 1
        return count

    def _priority(self, host: str, record: dict) -> int:
        score = 50
        label = host.split(".")[0]
        if any(token in host for token in INTERESTING):
            score += 20
        status = record.get("status_code") or record.get("status-code") or 0
        if status in (401, 403):
            score += 15          # a gate usually guards something
        if status and 200 <= status < 300:
            score += 5
        tech = json.dumps(record.get("tech") or record.get("technologies") or [])
        if any(t in tech.lower() for t in ("graphql", "swagger", "openapi", "jenkins", "gitlab", "grafana")):
            score += 15
        return min(score, 100)

    # ------------------------------------------------------------ baselines
    def _baselines(self, ctx: Context, store: A.Assets) -> int:
        """Two requests to random non-existent paths per service, through the
        proxy. Records whether the server returns a stable 'not found' or a
        catch-all that mimics real pages (soft 404)."""
        proxy = ctx.proxy()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy.url, "https": proxy.url}))
        done = 0
        for svc in store.services():
            base = svc["url"].rstrip("/")
            samples = []
            for _ in range(2):
                token = secrets.token_hex(8)
                samples.append(self._fetch(opener, f"{base}/hunter-{token}/does-not-exist"))
            root = self._fetch(opener, base + "/")
            baseline = self._classify(root, samples)
            store.set_baseline(svc["id"], baseline)
            done += 1
        return done

    def _fetch(self, opener, url: str) -> dict:
        try:
            with opener.open(url, timeout=20) as resp:
                body = resp.read(20000)
                return {"status": resp.status, "len": len(body),
                        "hash": hashlib.sha256(body).hexdigest()[:16],
                        "ctype": resp.headers.get("content-type", "")}
        except urllib.error.HTTPError as exc:
            body = exc.read(20000) if hasattr(exc, "read") else b""
            return {"status": exc.code, "len": len(body),
                    "hash": hashlib.sha256(body).hexdigest()[:16],
                    "ctype": exc.headers.get("content-type", "") if exc.headers else "",
                    "blocked": bool(exc.headers and exc.headers.get("X-Hunter-Blocked"))}
        except Exception as exc:
            return {"error": str(exc)[:120]}

    def _classify(self, root: dict, samples: list[dict]) -> dict:
        statuses = {s.get("status") for s in samples if "status" in s}
        hashes = {s.get("hash") for s in samples if "hash" in s}
        if any(s.get("blocked") for s in samples):
            kind = "blocked"            # proxy refused (should not happen for in-scope)
        elif not statuses:
            kind = "unknown"
        elif statuses == {404} and len(hashes) <= 1:
            kind = "hard_404"           # clean, distinguishable not-found
        elif statuses & {401, 403}:
            kind = "uniform_gate"       # everything is gated
        elif len(hashes) == 1 and root.get("hash") in hashes:
            kind = "soft_404_like_root"  # catch-all equals the home page (SPA shell)
        elif len(hashes) == 1:
            kind = "soft_404"           # stable catch-all page
        else:
            kind = "unstable"           # responses vary; needs care before fuzzing
        return {"kind": kind, "not_found_status": sorted(s for s in statuses if s),
                "sample": samples[0] if samples else {}, "root_status": root.get("status")}

    # ---------------------------------------------------------------- views
    def _write_views(self, ctx: Context, store: A.Assets) -> None:
        services = []
        for svc in store.services():
            baseline = json.loads(svc["baseline"]) if svc["baseline"] else {}
            services.append({
                "url": svc["url"], "status": svc["status"], "title": svc["title"],
                "server": svc["server"], "tech": json.loads(svc["tech"]) if svc["tech"] else [],
                "priority": svc["priority"], "baseline": baseline.get("kind"),
            })
        ctx.write_json("services.json", services)
        lines = [f"{s['priority']:>3}  {s['url']}  [{s['status']}]  {s['baseline'] or '-'}  {s['title'][:60]}"
                 for s in sorted(services, key=lambda x: -x["priority"])]
        (ctx.target.output / "services.txt").write_text("\n".join(lines) + ("\n" if lines else ""),
                                                        encoding="utf-8")

    def _announce(self, ctx: Context, host_count: int, services: int, baselined: int) -> None:
        store = ctx.assets()
        top = store.services(min_priority=65)[:12]
        lines = [f"- {s['url']} [{s['status']}]" for s in top]
        parts = [f"Live web services: {services} across {host_count} host(s)",
                 f"Baselines built: {baselined}"]
        if lines:
            parts.append("Highest-interest services:\n" + "\n".join(lines))
        parts.append(f"Full list: {ctx.target.output / 'services.txt'}")
        ctx.notify("Probe done", "\n\n".join(parts), "info")
