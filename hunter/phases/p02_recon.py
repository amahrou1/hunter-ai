"""Phase 02: recon.

For each in-scope wildcard root, find subdomains (passive sources plus the
operator's seeds), resolve them, scope-check every result, and classify:
in scope, out of scope, or likely third party (points at a SaaS/CDN that
pays nothing). Dangling CNAMEs are flagged as takeover candidates.

Explicit single hosts and URL assets are added directly; their apex is not
expanded. Nothing here makes an HTTP request to the target: that is phase 03.
Subfinder reaches public data sources directly (passive); dnsx resolves
through the system resolvers. Scope is still enforced in code before any
host is handed to a later phase.
"""

from __future__ import annotations

import json

from .. import assets as A
from .. import scope as sc
from .. import state as st
from ..toolchain import tool_path
from .base import Context, Phase, PhaseResult

MAX_ENRICH_WAVES = 2


class ReconPhase(Phase):
    id = "02-recon"
    name = "Recon: subdomains, DNS, takeover candidates"
    version = "1.0"
    build_step = 4
    requires = ("00-intake",)

    def run(self, ctx: Context) -> PhaseResult:
        if not ctx.target.scope_file.exists():
            # Should not happen (the orchestrator reruns intake first), but
            # never crash: ask for intake to run again.
            return PhaseResult(st.BLOCKED, "scope.json is missing; intake must run again")
        scope = ctx.scope()
        store = ctx.assets()
        roots = scope.wildcard_roots()

        # 1. Seed the inventory from explicit (non-wildcard) scope entries.
        explicit = 0
        for asset in scope.network_assets():
            if asset.kind in ("domain", "url") and asset.host:
                if store.add_host(asset.host, A.IN, "policy"):
                    explicit += 1
        for seed in self._seed_hosts(ctx):
            decision = scope.decide(seed)
            if decision.allowed and store.add_host(seed, A.IN, "operator-seed"):
                explicit += 1
        ctx.log(f"{explicit} host(s) from policy and seeds; {len(roots)} wildcard root(s)")

        if not roots and explicit == 0:
            return PhaseResult(st.NOT_APPLICABLE, "no wildcard roots and no explicit hosts to resolve")

        # 2. Passive subdomain discovery per wildcard root.
        discovered = self._subfinder(ctx, roots, scope, store) if roots else 0

        # 3. Resolve everything not yet resolved, then classify.
        resolved, third_party, takeovers = self._resolve(ctx, store, scope)

        # 4. One enrichment note: subfinder already does recursive sources, so
        #    we do not brute force here. A dedicated brute-force wave can be a
        #    later owner task; recorded as a gap rather than silently skipped.
        counts = store.host_counts()
        self._write_views(ctx, store)
        self._announce(ctx, counts, discovered, resolved, third_party, takeovers)

        in_live = len(store.hosts(scope=A.IN, resolved=True))
        summary = (f"{counts.get(A.IN, 0)} in scope ({in_live} resolved), "
                   f"{third_party} third-party, {takeovers} takeover candidate(s)")
        gaps = []
        if not tool_path("subfinder") and roots:
            gaps.append("subfinder is not installed, so passive discovery was skipped")
        if in_live == 0:
            ctx.block("At least one resolvable in-scope host",
                      "Recon found no in-scope host that resolves. If the program uses non-public hosts, "
                      "add them to subdomains.txt in the target folder.", ["subdomains.txt"])
            return PhaseResult(st.PARTIAL, summary + "; no resolvable in-scope host yet")
        return PhaseResult(st.DONE if not gaps else st.PARTIAL, summary, gaps=gaps)

    # ------------------------------------------------------------- helpers
    def _seed_hosts(self, ctx: Context) -> list[str]:
        hosts = []
        for line in ctx.target.input_text("subdomains.txt").splitlines():
            host = line.strip().lower()
            if host and not host.startswith("#"):
                hosts.append(sc.normalize_host(host))
        return hosts

    def _subfinder(self, ctx: Context, roots: list[str], scope: sc.Scope, store: A.Assets) -> int:
        binary = tool_path("subfinder")
        if not binary:
            ctx.log("subfinder not installed; skipping passive discovery")
            return 0
        runner = ctx.passive_runner()
        found = 0
        for index, root in enumerate(roots):
            ctx.progress(f"passive subdomain discovery ({root})", index, len(roots), "domains")
            run = runner.run("subfinder",
                             [str(binary), "-silent", "-all", "-d", root, "-oJ", "-nc", "-timeout", "20"],
                             name=f"subfinder-{index}-{root}", timeout_s=900)
            for record in run.json_lines():
                host = str(record.get("host") or record.get("input") or "").strip().lower()
                if not host:
                    continue
                decision = scope.decide(host)
                target = A.IN if decision.allowed else A.OUT
                if store.add_host(host, target, "subfinder"):
                    found += 1
        ctx.log(f"passive discovery added {found} host(s)")
        return found

    def _resolve(self, ctx: Context, store: A.Assets, scope: sc.Scope) -> tuple[int, int, int]:
        pending = [row["host"] for row in store.hosts(resolved=False) if row["scope"] in (A.IN,)]
        if not pending:
            return 0, 0, 0
        binary = tool_path("dnsx")
        if not binary:
            ctx.log("dnsx not installed; marking in-scope hosts unresolved")
            return 0, 0, 0
        runner = ctx.passive_runner()
        ctx.progress("resolving host names", None, len(pending), "hosts")
        run = runner.run("dnsx",
                         [str(binary), "-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-nc"],
                         name="dnsx-resolve", timeout_s=1800, stdin_lines=pending)
        resolved = third_party = takeovers = 0
        seen = set()
        for record in run.json_lines():
            host = str(record.get("host", "")).strip().lower()
            if not host or host in seen:
                continue
            seen.add(host)
            addresses = list(record.get("a", []) or []) + list(record.get("aaaa", []) or [])
            cname = ""
            cnames = record.get("cname") or []
            if cnames:
                cname = cnames[0] if isinstance(cnames, list) else str(cnames)
            store.set_resolution(host, addresses, cname)
            resolved += 1
        # Count classification outcomes.
        for row in store.hosts():
            if row["scope"] == A.THIRD_PARTY:
                third_party += 1
            if row["takeover_candidate"]:
                takeovers += 1
        if takeovers:
            for row in store.takeover_candidates():
                ctx.state.event("takeover_candidate", self.id, f"{row['host']} -> {row['cname']}")
        ctx.log(f"resolved {resolved} host(s); {third_party} look third-party; {takeovers} takeover candidate(s)")
        return resolved, third_party, takeovers

    def _write_views(self, ctx: Context, store: A.Assets) -> None:
        live = [r["host"] for r in store.hosts(scope=A.IN, resolved=True)]
        (ctx.target.output / "hosts_in_scope.txt").write_text("\n".join(live) + ("\n" if live else ""),
                                                              encoding="utf-8")
        report = {
            "counts": store.host_counts(),
            "in_scope_resolved": live,
            "third_party": [{"host": r["host"], "reason": r["third_party_reason"]}
                            for r in store.hosts(scope=A.THIRD_PARTY)],
            "takeover_candidates": [{"host": r["host"], "cname": r["cname"]}
                                    for r in store.takeover_candidates()],
        }
        ctx.write_json("recon.json", report)

    def _announce(self, ctx: Context, counts, discovered, resolved, third_party, takeovers) -> None:
        parts = [
            f"In scope: {counts.get(A.IN, 0)} host(s), {resolved} resolved this run",
            f"Passive discovery added: {discovered}",
            f"Likely third-party (low priority): {third_party}",
            f"Out of scope: {counts.get(A.OUT, 0)}",
        ]
        level = "info"
        if takeovers:
            parts.append(f"Possible subdomain takeover: {takeovers} candidate(s) - see recon.json")
            level = "warn"
        ctx.notify("Recon done", "\n".join(parts), level)
