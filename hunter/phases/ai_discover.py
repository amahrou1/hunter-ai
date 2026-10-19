"""Phase 05, AI: content and parameter discovery.

Searches each live service for files and paths that are not linked anywhere:
admin panels, API docs, debug endpoints, version-control folders, config and
backup files. Uses the per-service baselines and noise filters so catch-all
pages do not produce false hits, and confirms sensitive hits by content."""

from __future__ import annotations

from ..agent_phase import AgentPhase
from .base import Context


class AIDiscoverPhase(AgentPhase):
    id = "05-discover"
    name = "Content and parameter discovery"
    version = "2.0"
    build_step = 4
    requires = ("00-intake", "03-probe")
    role = "discoverer"
    max_turns = 90
    timeout_minutes = 300

    def task(self, ctx: Context) -> str:
        return (
            "Find unlinked files and paths on each live service (`hk services --todo discovered`, "
            "highest priority first).\n"
            "1. Use the built-in wordlist (`hk wordlist`) with ffuf through the proxy (-json -ac -mc "
            "200,201,204,301,302,307,401,403,405,500 -rate <scope rate> -sf). Save to a file and "
            "`hk import ffuf <file>` - the importer drops results that match this site's known noise.\n"
            "2. If an import warns that most hits share one status and length, that site has a catch-all "
            "page: run the `hk filter <host> <status> <length> --reason catch-all` it suggests, then "
            "re-run that one site.\n"
            "3. For every interesting 200 hit on a sensitive name (.git, .env, swagger, actuator, backups), "
            "confirm it by content: `hk check-content <url>`. Only confirmed ones become leads.\n"
            "4. `hk mark discovered <service-id>...` as you finish each, and `hk progress` as you go.\n"
            "Finish when the services are searched. List the confirmed leads in ./handoff.md."
        )
