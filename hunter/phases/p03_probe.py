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
import ssl
import urllib.error
import urllib.request

from .. import assets as A
from .. import state as st
from ..toolchain import tool_path
from .base import Context, Phase, PhaseResult

INTERESTING = ("admin", "api", "dev", "staging", "test", "internal", "portal", "dashboard",
               "auth", "login", "vpn", "git", "jenkins", "gateway", "graphql", "console")


# Bump to make every target probe all its hosts once more after a change
# that alters what targets answer (headers, TLS handling).
PROBE_GENERATION = "2"


class ProbePhase(Phase):
    id = "03-probe"
    name = "Probe and fingerprint, per-host baselines"
    version = "1.4"
    build_step = 4
    requires = ("00-intake", "02-recon")

    def run(self, ctx: Context) -> PhaseResult:
        store = ctx.assets()
        scope = ctx.scope()
        gaps: list[str] = []
        # IP and CIDR scope entries: find open ports first (adds IP hosts).
        self._portscan(ctx, store, scope, gaps)
        all_hosts = [r["host"] for r in store.hosts(scope=A.IN, resolved=True)]
        if not all_hosts:
            return PhaseResult(st.NOT_APPLICABLE, "no resolved in-scope hosts to probe", gaps=gaps)
        # Only hosts not probed yet: a resumed or re-run probe continues where
        # it stopped, and a host added with `hunt tell` is probed on its own.
        if ctx.state.get_meta("probe_generation") != PROBE_GENERATION:
            # Results from an older generation were collected in a way that
            # can change what targets answer (v0.5.2: the User-Agent was
            # replaced, not appended, and bot protection blocked it). Probe
            # everything once more.
            if store.service_count():
                ctx.log("results from an older probe are redone once (request headers changed)")
            store.mark_probed(all_hosts, False)
            store.db.execute("UPDATE services SET baseline=NULL")
            ctx.state.set_meta("probe_generation", PROBE_GENERATION)
        hosts = [h for h in store.unprobed_hosts() if scope.host_in_scope(h)]
        self._operator = ctx.operator()

        binary = tool_path("httpx")
        if not binary:
            ctx.block("The httpx tool",
                      "httpx is not installed, so live web services could not be found. Run: hunt tools install",
                      [])
            return PhaseResult(st.BLOCKED, "httpx not installed")

        ctx.log(f"{len(hosts)} host(s) to probe ({len(all_hosts) - len(hosts)} already done)")
        # Hosts found by the port scan are probed on the ports found open;
        # named hosts on the usual web ports.
        port_targets, named = [], []
        for host in hosts:
            open_ports = store.host_note(host).get("open_ports")
            if open_ports:
                port_targets += [f"{host}:{p}" for p in open_ports]
            else:
                named.append(host)
        ctx.progress("finding live web services", None, len(hosts), "hosts")
        new_services = self._probe(ctx, store, binary, named) if named else 0
        if port_targets:
            new_services += self._probe(ctx, store, binary, port_targets, ports=False,
                                        mark=[h for h in hosts if h not in named])
        baselined = self._baselines(ctx, store)
        takeovers = self._takeovers(ctx, store)
        self._write_views(ctx, store)
        store.write_leads(ctx.target.output / "leads.txt")
        total = store.service_count()
        if hosts or baselined:
            self._announce(ctx, len(hosts), new_services, baselined)

        summary = (f"{total} live web service(s) across {len(all_hosts)} host(s); "
                   f"{new_services} found this time, {baselined} newly baselined")
        if takeovers:
            summary += "; " + takeovers
        if total == 0:
            return PhaseResult(st.PARTIAL, f"{len(all_hosts)} hosts probed, no live web service found", gaps=gaps)
        return PhaseResult(st.PARTIAL if gaps else st.DONE, summary, gaps=gaps)

    # ----------------------------------------------------------- port scan
    def _portscan(self, ctx: Context, store: A.Assets, scope, gaps: list[str]) -> None:
        from .. import portscan
        seeds = [line.strip() for line in ctx.target.input_text("ips.txt").splitlines()
                 if line.strip() and not line.startswith("#")]
        cfg = {"max_probes": 2_000_000, **ctx.settings.get("portscan", {})}
        work = portscan.plan(scope, seeds, max_probes=int(cfg["max_probes"]),
                             ports=[int(p) for p in cfg.get("ports") or []] or None)
        if not work.addresses:
            return
        # "v2": answer-everything detection and protocol checks (v0.6.2).
        key = hashlib.sha256(json.dumps(["v2", work.addresses, work.ports]).encode()).hexdigest()[:16]
        if ctx.state.get_meta("portscan_key") == key:
            return  # same addresses and ports as last time: already done
        for note in work.skipped + ([work.reduced] if work.reduced else []):
            ctx.log(note)
            gaps.append(note)
        rate = max(1.0, float(scope.rate_limit_rps))
        minutes = len(work.addresses) * len(work.ports) / rate / 60
        ctx.log(f"port scan: {len(work.addresses)} address(es) x {len(work.ports)} port(s) "
                f"at {rate:g}/s (about {minutes:.0f} min)")
        total = len(work.addresses) * len(work.ports)
        ctx.progress("port scan of the IP ranges", 0, total, "checks")
        found = portscan.scan(work.addresses, work.ports, rate,
                              on_progress=lambda n: ctx.progress("port scan of the IP ranges", n, total, "checks"))
        # Leads from an earlier scan are rebuilt from this one.
        store.db.execute("DELETE FROM leads WHERE kind='exposed-service' AND source='03-probe'")
        user_agent = self._user_agent(scope)
        verified, unverified, catch_all = [], 0, []
        web_four = [p for p in (443, 80, 8443, 8080) if p in work.ports]
        for address, ports in found.items():
            store.add_host(address, A.IN, "portscan")
            store.set_resolution(address, [address])
            store.mark_probed([address], False)
            if portscan.accepts_everything(ports, len(work.ports)):
                # A firewall or load balancer that completes the handshake on
                # every port: the open ports say nothing. Keep the usual web
                # ports for probing, drop services found on the others.
                catch_all.append(address)
                keep = [p for p in web_four if p in ports]
                store.set_host_note(address, open_ports=keep, accepts_all=True, ports_answering=len(ports))
                marks = ",".join("?" for _ in keep) or "NULL"
                store.db.execute(f"DELETE FROM services WHERE host=? AND port NOT IN ({marks})", (address, *keep))
                continue
            store.set_host_note(address, open_ports=ports, accepts_all=False)
            for port in ports:
                label = portscan.SENSITIVE_PORTS.get(port)
                if not label:
                    continue
                evidence = portscan.verify(address, port, user_agent)
                url = f"tcp://{address}:{port}"
                if evidence:
                    if store.add_lead("exposed-service", url, "03-probe", f"{label}: {evidence}",
                                      status="signature-match"):
                        verified.append(f"{address}:{port} {label} - {evidence}")
                elif store.add_lead("exposed-service", url, "03-probe",
                                    f"port {port} open ({label}); the service did not identify itself"):
                    unverified += 1
        ctx.state.set_meta("portscan_key", key)
        real = {a: p for a, p in found.items() if a not in catch_all}
        open_count = sum(len(p) for p in real.values())
        ctx.log(f"port scan: {open_count} open port(s) on {len(real)} address(es); "
                f"{len(catch_all)} address(es) answer on every port")
        lines = [f"Addresses scanned: {len(work.addresses)} (ports each: {len(work.ports)})",
                 f"Open ports: {open_count} on {len(real)} address(es)"]
        if catch_all:
            lines.append(f"{len(catch_all)} address(es) accept a connection on every port (firewall or load "
                         "balancer): their ports are not counted, only the usual web ports are probed")
        if work.reduced:
            lines.append(work.reduced)
        if verified:
            lines.append("Services that answered their own protocol (NOT yet validated):")
            lines += [f"- {e}" for e in verified[:10]]
        if unverified:
            lines.append(f"Other open sensitive ports that did not identify themselves: {unverified} (leads.txt)")
        ctx.notify("Port scan done", "\n".join(lines), "warn" if verified else "info")

    @staticmethod
    def _user_agent(scope) -> str:
        browser = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/129.0.0.0 Safari/537.36")
        tag = next((v for k, v in scope.required_headers.items() if k.lower() == "user-agent"), "")
        if not tag:
            return browser
        return tag if scope.rules.get("user_agent_mode") == "exact" else f"{browser} {tag}"

    # ------------------------------------------------------------ takeover
    def _takeovers(self, ctx: Context, store: A.Assets) -> str:
        from .. import takeover
        candidates = [r for r in store.takeover_candidates()
                      if "takeover_check" not in store.host_note(r["host"])]
        if not candidates:
            return ""
        opener = takeover.opener_for(ctx.proxy())
        kept = cleared = 0
        for row in candidates:
            verdict, reason = takeover.check(row["host"], row["cname"], opener)
            if verdict == "cleared":
                store.clear_takeover(row["host"], reason)
                cleared += 1
            elif verdict == "candidate":
                store.set_host_note(row["host"], takeover_check=reason)
                store.add_lead("takeover", f"https://{row['host']}/", "03-probe",
                               f"CNAME {row['cname']}: {reason}", status="signature-match")
                kept += 1
            ctx.log(f"takeover check {row['host']}: {verdict} ({reason})")
        if kept:
            ctx.notify("Possible subdomain takeover", f"{kept} host(s) show real signs of a dangling record "
                       f"(NOT yet validated). See leads.txt.", "warn")
        return f"takeover candidates: {kept} kept, {cleared} cleared (in use)"

    # ------------------------------------------------------------- probing
    def _probe(self, ctx: Context, store: A.Assets, binary, hosts: list[str], ports: bool = True,
               mark: list[str] | None = None) -> int:
        """hosts: names (probed on the usual web ports) or host:port pairs
        (ports=False). mark: the host names to record as probed."""
        runner = ctx.active_runner()
        cmd = [
            str(binary), "-silent", "-json", "-nc", "-follow-host-redirects",
            "-status-code", "-title", "-tech-detect", "-web-server",
            "-content-type", "-content-length", "-hash", "sha256",
            "-timeout", "15", "-retries", "1",
            "-rate-limit", str(max(1, int(ctx.scope().rate_limit_rps))),
        ]
        if ports:
            cmd += ["-ports", "80,443,8080,8443"]
        run = runner.run("httpx", cmd, name="httpx-probe" if ports else "httpx-probe-ports",
                         timeout_s=3600, stdin_lines=hosts)
        hosts = mark if mark is not None else hosts

        count = 0
        answered = set()
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
            answered.add(host)
            count += 1
        # A host that answered was probed. If httpx finished normally, the
        # silent ones were probed too (nothing live); if it was cut off, they
        # are tried again next time.
        store.mark_probed(hosts if run.ok else answered)
        return count

    def _priority(self, host: str, record: dict) -> int:
        operator = getattr(self, "_operator", None)
        if operator is not None and operator.is_focus(host):
            return 100           # the operator asked for it
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
            urllib.request.ProxyHandler({"http": proxy.url, "https": proxy.url}),
            # The guard re-signs HTTPS with its own CA; trust it, or every
            # HTTPS baseline fails before it reaches the target.
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(proxy.ca_bundle))))
        done = 0
        scope = ctx.scope()
        services = store.services()
        for index, svc in enumerate(services):
            if index % 10 == 0:
                ctx.progress("checking each site's 'not found' page", index, len(services), "sites")
            if not scope.host_in_scope(svc["host"]):
                continue  # avoided since
            if svc["baseline"] and json.loads(svc["baseline"]).get("kind") != "unknown":
                continue  # done earlier; "unknown" (all samples failed) is retried
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
