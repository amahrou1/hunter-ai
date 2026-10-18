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
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


class AIReconPhase(AgentPhase):
    id = "02-recon"
    name = "Recon: subdomains, DNS, takeover candidates"
    version = "2.0"
    build_step = 4
    requires = ("00-intake",)
    role = "scanner"
    max_turns = 80
    timeout_minutes = 90

    def task(self, ctx: Context) -> str:
        return (
            "Map the attack surface.\n"
            "1. `hk scope` to see the wildcard roots and explicit hosts in scope.\n"
            "2. For each wildcard root, find subdomains passively (subfinder -silent -all -d <root> "
            "-oJ -o subs-<root>.jsonl, and you may also query crt.sh directly). Import each result: "
            "`hk import subfinder <file>`.\n"
            "3. Resolve everything: take the host list, run dnsx (-json -a -aaaa -cname -resp) into a "
            "file, then `hk import dnsx <file>`. This also classifies third-party and takeover candidates.\n"
            "4. Check the takeover candidates for real: `hk takeover`.\n"
            "5. Watch for measurement problems: if a made-up random name under a root resolves, that root "
            "has wildcard DNS and most 'hosts' are echoes - note it (`hk note`) and deprioritise them "
            "(`hk priority <host> 10`). Use `hk stats` to sanity-check your numbers.\n"
            "Do NOT make HTTP requests to the hosts here (that is the next phase) and do NOT port scan. "
            "Finish when the in-scope hosts are resolved and classified."
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
