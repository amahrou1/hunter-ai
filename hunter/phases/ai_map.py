"""Phase 04, AI: mapping and crawl.

Crawls every live in-scope service, builds the request inventory (pages, API
endpoints, parameters, forms) and collects JavaScript files. Forms are
recorded, never submitted."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIMapPhase(AgentPhase):
    id = "04-map"
    name = "Mapping and crawl, request inventory, JavaScript collection"
    version = "2.0"
    build_step = 4
    requires = ("00-intake", "03-probe")
    role = "mapper"
    max_turns = 90
    timeout_minutes = 300

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Crawl every live in-scope service with katana through the proxy (scope rate), "
                     "importing each batch with `hk import katana`; add in-scope gau/wayback URLs."),
            MustStep("M2", "`hk mark crawled <service-id>` after each batch so a resumed run continues."),
            MustStep("M3", "Record interesting parameters, forms (never submitted) and JavaScript files "
                     "into the inventory as you go."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Map every live service, highest priority first (`hk services --todo crawled`).\n"
            "1. Crawl with katana through the proxy (-jsonl -jc -kf all -fx -iqp -fs fqdn -d 3, with "
            "-rl matching the scope rate and -ef for static assets png,jpg,css,woff...). Save to a file "
            "per batch and `hk import katana <file>`. You may also add gau/wayback URLs that are in scope.\n"
            "2. After each batch, `hk mark crawled <service-id>...` so a resumed run continues where it "
            "stopped, and `hk progress` as you go.\n"
            "3. Skip dead upstreams (5xx), uniform gates, and the same page repeated across hosts.\n"
            "4. Watch for a wall of 403/429 (a WAF or rate limit): if most answers are blocked, slow down, "
            "note it, and move on - do not hammer.\n"
            "Finish when the in-scope services are crawled. Summarise the endpoints, interesting "
            "parameters, forms and JavaScript files in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        n = store.endpoint_count()
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{n} endpoint(s); agent did not finish, will continue")
        return PhaseResult(st.DONE if n else st.PARTIAL, f"{n} endpoint(s) in the inventory")
