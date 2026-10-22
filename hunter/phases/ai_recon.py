"""Phase 02, AI-driven: reconnaissance.

The agent maps the attack surface of the in-scope wildcard roots and explicit
hosts: find subdomains (passively), resolve them, keep the in-scope live ones,
notice wildcard DNS or third-party hosts, and flag subdomain-takeover
candidates. It records everything through `hk`. Enumeration tools and the
inventory writes are all scope-checked.
"""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIReconPhase(AgentPhase):
    id = "02-recon"
    name = "Recon: subdomains, DNS, takeover candidates"
    version = "2.0"
    build_step = 4
    requires = ("00-intake", "01c-expand")
    role = "scanner"
    prior_scope = "hosts"
    max_turns = 200
    timeout_minutes = 180

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Enumerate subdomains passively for every in-scope wildcard root "
                     "(subfinder + crt.sh); import each with `hk import subfinder`.", "done-roots.txt"),
            MustStep("M2", "Resolve them with dnsx (pass `-rl $HUNTER_DNS_MAX_RPS` to stay polite), then "
                     "`hk import dnsx` to classify third-party and takeover candidates."),
            MustStep("M3", "Re-check subdomain-takeover candidates with `hk takeover`."),
            MustStep("M4", "Flag wildcard-DNS roots (a random name resolves) with `hk note` and "
                     "deprioritise their echo hosts."),
            MustStep("M5", "If the scope has IP/CIDR ranges: find the HOSTNAMES on them (reverse-DNS/PTR, "
                     "and passive certificate data from Shodan/Censys if keys are set), so apps that only "
                     "answer to a Host header are not missed. Import the in-scope names with `hk import dnsx`."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Map the attack surface. On a big program this is a LOT of hosts, so work RESUMABLY and make "
            "forward progress every run - do not restart from scratch each time.\n"
            "1. `hk scope` to see the roots: enumerate EVERY entry in `wildcard_roots` (it includes the domains the discovery phase proved and added, listed under `discovered_in_scope`) plus the explicit hosts. Keep a file ./done-roots.txt "
            "in this directory listing the roots you have FULLY enumerated and resolved; on every run skip any "
            "root already in it and reuse files you already produced.\n"
            "2. For each remaining wildcard root, find subdomains passively (subfinder -silent -all -d <root> "
            "-oJ -o subs-<root>.jsonl, and you may also query crt.sh directly). Import each result: "
            "`hk import subfinder <file>`.\n"
            "3. Resolve them: run dnsx (-json -a -aaaa -cname -resp) over that root's hosts into a file, then "
            "`hk import dnsx <file>` (this also classifies third-party and takeover candidates). Public "
            "resolvers do NOT go through the proxy, so pass `-rl $HUNTER_DNS_MAX_RPS` to dnsx to keep the "
            "query rate polite. Then append that root to ./done-roots.txt before moving to the next, so the "
            "next run continues where you stopped.\n"
            "4. Check the takeover candidates for real: `hk takeover`.\n"
            "5. Watch for measurement problems: if a made-up random name under a root resolves, that root has "
            "wildcard DNS and most 'hosts' are echoes - note it (`hk note`) and deprioritise them "
            "(`hk priority <host> 10`). Use `hk stats` to sanity-check your numbers.\n"
            "6. If the scope includes IP or CIDR ranges, find the HOSTNAMES that live on those IPs so apps "
            "that only answer to a specific Host header are not missed: reverse-DNS (PTR) every in-scope "
            "address, and if a Shodan/Censys key is set, pull the certificate/hostname data for those IPs "
            "from there (passive, not a scan). Keep only names that are in scope and import them "
            "(`hk import dnsx`); the vhost step in the probe phase then uses them as Host headers.\n"
            "Do NOT make HTTP requests to the hosts here (that is the next phase) and do NOT port scan.\n"
            "Write ./handoff.md ONLY when every in-scope root is in ./done-roots.txt and its hosts are "
            "resolved and classified - that marks this phase complete. If you run low on turns before then, "
            "stop cleanly WITHOUT writing handoff.md; your ./done-roots.txt progress is saved and you will be "
            "continued automatically."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        live = len(store.hosts(scope=A.IN, resolved=True))
        counts = store.host_counts()
        takeovers = len(store.takeover_candidates())
        summary = (f"{counts.get(A.IN, 0)} in scope, {live} resolved, "
                   f"{counts.get(A.THIRD_PARTY, 0)} third-party, {takeovers} takeover candidate(s)")
        if live == 0:
            ctx.block("At least one resolvable in-scope host",
                      "Recon found no in-scope host that resolves. If the program uses non-public hosts, "
                      "add them to subdomains.txt in the target folder.", ["subdomains.txt"])
            return PhaseResult(st.PARTIAL, summary + "; no resolvable in-scope host yet")
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, summary + "; the agent did not finish, it will continue next start")
        return PhaseResult(st.DONE, summary)
