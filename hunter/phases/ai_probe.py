"""Phase 03, AI: probe and fingerprint, plus port scan for IP scope.

Finds the live HTTP(S) services among the resolved hosts, fingerprints them,
builds each one's 'not found' baseline, scans any in-scope IP/CIDR ranges with
the safe built-in scanner, and re-checks takeover candidates. All through the
scope guard."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIProbePhase(AgentPhase):
    id = "03-probe"
    name = "Probe and fingerprint, per-host baselines, port scan"
    version = "2.0"
    build_step = 4
    requires = ("00-intake", "02-recon")
    role = "prober"
    prior_scope = "hosts"
    max_turns = 70
    timeout_minutes = 180

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "FIRST AND NON-NEGOTIABLE: probe EVERY resolved in-scope host in batched httpx "
                     "runs and import with `--attempted` until `hk hosts --unprobed` is EMPTY. This is the "
                     "core of the phase; finish it before anything below. Do NOT start M6 (vhost) while any "
                     "host is still unprobed - vhost is a bonus, probing the surface is the job."),
            MustStep("M2", "If the scope has IP/CIDR ranges, run `hk portscan` once and httpx-probe the web "
                     "targets it prints (import those with `--attempted` too)."),
            MustStep("M3", "Run `hk baseline` so every service has its not-found answer (later fuzzing needs it)."),
            MustStep("M4", "Re-check takeover candidates with `hk takeover` and HTTP-probe any flagged host."),
            MustStep("M5", "Clone review: run `hk cluster --apply` (code auto-parks strong-proof clones), "
                     "then review each listed platform-instance group and `hk cluster --approve <parent>` only "
                     "the ones that are clearly one app repeated; leave anything that might be distinct apps."),
            MustStep("M6", "ONLY AFTER `hk hosts --unprobed` IS EMPTY and you still have turns left: "
                     "virtual-host enumeration - for a FEW (at most ~8) distinct in-scope IPs with a live web "
                     "service, run `hk vhost <ip-url>` to surface internal/staging apps that answer only to a "
                     "specific Host header. If you are low on turns, SKIP this - it must never cost you the "
                     "core probing above."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Find and fingerprint the live web services. Work in BATCHES, not host by host - you have many "
            "hosts and a time budget.\n"
            "1. Get the hosts still to probe: `hk hosts --unprobed > todo.txt` (on a fresh run this is all "
            "resolved in-scope hosts; on a resumed run it is only what is left - the rest are already done, "
            "do not redo them). Only resolved in-scope hosts are listed, so you will not waste time on the "
            "dead name tail.\n"
            "2. Probe them in ONE httpx run, not one call per host: "
            "`httpx -l todo.txt -json -o httpx.jsonl -title -tech-detect -web-server -status-code "
            "-content-length -hash sha256 -favicon -ports 80,443,8080,8443 -timeout 10 -rl <scope rate> -nc`. "
            "Then import WITH the attempted list so dead hosts are cleared too: "
            "`hk import httpx httpx.jsonl --attempted todo.txt`. This marks every host you tried as probed - "
            "including the ones that did not answer - so they leave the unprobed queue instead of coming back "
            "every pass. (Without `--attempted`, httpx writes no line for a silent host, it stays 'unprobed' "
            "forever, and this phase can never finish.) Repeat `hk hosts --unprobed > todo.txt` + httpx + "
            "import until `hk hosts --unprobed` is EMPTY. Do not move past this until it is empty.\n"
            "3. If the scope has IP or CIDR ranges, run `hk portscan` once (it scans only in-scope addresses "
            "at the program rate, skips firewalls that answer every port, verifies sensitive services). It "
            "prints web targets - probe those with httpx and import them too.\n"
            "4. `hk baseline` to record each service's 'not found' answer (needed by later fuzzing). This is "
            "one pass over all services; let it run.\n"
            "5. `hk takeover` to re-check subdomain-takeover candidates, and HTTP-probe any flagged host to "
            "see if the provider shows an unclaimed page.\n"
            "6. Sanity-check with `hk services`: if the same page repeats on many hosts (a load-balancer "
            "default), deprioritise them (`hk priority <host> 10`) and note it.\n"
            "7. CLONE REVIEW: after probing, run `hk cluster --apply`. Code auto-parks the strong-proof "
            "clones (random names echo the same page, or exact-duplicate bodies) and lists PLATFORM-INSTANCE "
            "groups for your judgment - hundreds/thousands of hosts on one backend (same IPs, same "
            "server/tech, a shared title pattern) that serve slightly different per-instance content, e.g. an "
            "event or tenant microsite platform. For each listed group, look at its sample hosts and titles: "
            "if it is clearly one app repeated (noise), approve it with `hk cluster --approve <parent>` (keeps "
            "3 representatives, parks the rest). If a group might hold distinct apps, LEAVE it (do nothing) - "
            "it stays fully tested. Never approve a group that looks like real separate apps. Protected hosts "
            "(policy-listed, focused, admin/api/auth-named, or already carrying a lead) are never parked.\n"
            "8. VIRTUAL HOSTS (LAST, and only if `hk hosts --unprobed` is already empty and you have turns "
            "to spare): for a FEW distinct in-scope IPs (at most ~8, pick the most interesting origins) that "
            "have a live web service, run `hk vhost http://<ip>/`. It fuzzes the Host header with in-scope "
            "names and reports any that answer with a DIFFERENT page than the default - internal/staging apps "
            "not in DNS, recorded as vhost leads. This is a bonus: if you are running low on turns, SKIP it "
            "entirely. Never let vhost work stop you from finishing the probing in step 2 - that is the real "
            "job and a half-probed surface is the one failure this phase must not produce.\n"
            "Use `hk progress \"probing\" <done> <total> hosts` as you go. The phase is finished when "
            "`hk hosts --unprobed` is empty (every resolved host probed, responders and dead alike) and "
            "baselines are built. Summarise the live services in ./handoff.md."
        )

    def progress_metric(self, ctx: Context):
        """Probe advances by PROBING HOSTS, not by adding inventory rows. A pass
        that probes hundreds more (mostly dead/internal) hosts adds few new
        service rows, which the default row-count would misread as 'not
        advancing' and stop - leaving the surface half-probed (the Cornelsen
        bug). Counting probed hosts keeps probe going until the surface is
        actually covered."""
        try:
            return len(ctx.assets().hosts(scope=A.IN, resolved=True)) \
                - len(ctx.assets().unprobed_hosts())
        except Exception:  # noqa: BLE001
            return None

    def _covered(self, store: A.Assets) -> bool:
        """True when probe's substantive work is done: the great majority of
        resolved in-scope hosts have been probed. A long tail of slow/dead
        internal hosts (corpinter-style networks that time out) should NOT keep
        the whole pipeline blocked forever - at >=90% probed the testable surface
        is covered and map can start, probe having fingerprinted everything that
        answers. The agent's handoff is a nicety, not required here."""
        resolved = len(store.hosts(scope=A.IN, resolved=True))
        if resolved == 0:
            return False
        probed = resolved - len(store.unprobed_hosts())
        return probed >= max(1, int(resolved * 0.90))

    def outputs_present(self, ctx: Context) -> bool:
        # Probe's "output" for a dependent phase (04-map) is a probed inventory,
        # not the handoff file. A legitimately-covered probe satisfies its
        # dependents even with no handoff - otherwise the downstream dependency
        # gate (_outputs_ok -> outputs_present) leaves 04-map BLOCKED "waiting
        # for 03-probe" while 03-probe is DONE (the Binance symptom: probe hit
        # ground-truth completion on a 31k-service surface without writing
        # handoff.md, and every phase after map stranded).
        if super().outputs_present(ctx):
            return True
        try:
            return self._covered(ctx.assets())
        except Exception:  # noqa: BLE001
            return False

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        total = store.service_count()
        if total == 0:
            return PhaseResult(st.PARTIAL, "no live web service found yet")
        # Ground truth: when the resolvable surface is covered, the phase is
        # complete even without a rich handoff. Without this a fully-probed run
        # can loop PARTIAL for hours, re-probing nothing (the Mercedes symptom:
        # 4741/4743 probed, stuck PARTIAL).
        remaining = len(store.unprobed_hosts())
        if not (ctx.target.output / "phases" / self.id / "work" / "handoff.md").exists() \
                and not self._covered(store):
            return PhaseResult(st.PARTIAL, f"{total} live service(s); agent did not finish, will continue")
        parked = self._cluster(ctx, store)
        suffix = f"; collapsed {parked} infra clone(s) to representatives" if parked else ""
        tail = f" ({remaining} host(s) unprobed - DNS/timeout tail)" if remaining else ""
        return PhaseResult(st.DONE, f"{total} live web service(s) fingerprinted{tail}{suffix}")

    def _cluster(self, ctx: Context, store: A.Assets) -> int:
        """Collapse infrastructure clones so the testing phases see distinct apps.

        Split code/agent: CODE auto-parks only the STRONG proofs (wildcard-echo,
        exact-dup) - no judgment involved - and keeps re-runs idempotent. The
        platform-instance groups (same backend, real per-instance content) are
        LEFT for the probe agent to approve with `hk cluster --approve`, because
        deciding 'is this noise' is judgment. If the agent never reviews them they
        stay fully tested, so the failure mode is extra testing, never a missed
        host. Returns how many services code auto-parked."""
        cfg = ctx.settings.get("cluster", {}) or {}
        if not cfg.get("enabled", True):
            return 0
        from .. import cluster, webprobe
        from collections import defaultdict
        # Re-apply any prior parking first (idempotent after a re-probe).
        store.reconcile_parked()
        # --- Proof A: detect catch-all parents via random-name probes ---------
        services = [dict(r) for r in store.services()]
        by_parent = defaultdict(list)
        for s in services:
            by_parent[cluster.parent_of(s["host"])].append(s)
        min_cluster = int(cfg.get("min_cluster", cluster.DEFAULT_MIN_CLUSTER))
        proxy = ctx.proxy()
        opener = webprobe.opener_through(proxy.url, str(proxy.ca_bundle))
        echo_hosts: list[str] = []
        for parent, members in by_parent.items():
            if len(members) < min_cluster:
                continue
            sigs = []
            for name in cluster.random_probe_names(parent, 3):
                res = webprobe.fetch(opener, f"https://{name}/")
                if res.get("blocked") or "error" in res:
                    continue
                sigs.append((res.get("status"), res.get("hash")))
            if not sigs or len(set(sigs)) != 1:
                continue
            catch_all = sigs[0]
            for m in members:
                if (m.get("status"), m.get("body_hash")) == catch_all:
                    echo_hosts.append(m["host"])
        import json as _json
        store.db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('cluster_echo_hosts', ?)",
                         (_json.dumps(echo_hosts),))
        # --- Build the plan with proofs and auto-park the strong ones ---------
        host_res = {r["host"]: r for r in store.hosts(scope=A.IN)}
        for s in services:
            hr = host_res.get(s["host"])
            if hr:
                s["addresses"], s["cname"] = hr["addresses"], hr["cname"]
        scope = ctx.scope()
        protected = self._protected_hosts(ctx, store, scope)
        apex_roots = set(scope.wildcard_roots()) | {a.host for a in scope.in_scope if a.host}
        report = cluster.plan(
            services, protected=protected, echo_hosts=set(echo_hosts), apex_roots=apex_roots,
            min_cluster=min_cluster, keep=int(cfg.get("keep", cluster.DEFAULT_KEEP)))
        parked = cluster.apply_auto(store, services, report)
        store.reconcile_parked()
        # Stage the review groups so `hk cluster --apply/--review` shows them.
        if parked or report["review"]:
            ctx.log(f"    clustering: auto-parked {parked} clone service(s); "
                    f"{len(report['review'])} group(s) staged for agent review")
            if report["review"]:
                largest = report["review"][0]
                ctx.notify("Infrastructure clones",
                           f"Auto-parked {parked} strong-proof clone(s). "
                           f"{len(report['review'])} platform-instance group(s) await judgment "
                           f"(largest {largest['parent']}, {largest['size']} hosts). The agent reviews them.",
                           "info")
        return parked

    def _protected_hosts(self, ctx: Context, store: A.Assets, scope) -> set[str]:
        protected: set[str] = set()
        for a in scope.in_scope:
            if a.host and not getattr(a, "wildcard_host", False) and a.kind in ("domain", "url"):
                protected.add(a.host.lower())
        try:
            protected.update(h.lower() for h in ctx.operator().focus())
        except Exception:  # noqa: BLE001
            pass
        for lead in store.leads():
            if lead["host"]:
                protected.add(lead["host"].lower())
        for f in store.findings():
            if f["host"]:
                protected.add(f["host"].lower())
        for h in store.takeover_candidates():
            protected.add(h["host"].lower())
        return protected
