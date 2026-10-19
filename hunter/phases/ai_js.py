"""Phase 06, AI: JavaScript analysis.

Downloads the JavaScript files found while crawling and reads them for hidden
API endpoints, parameters, and leaked secrets or keys. Higher-signal than
variable names: fetch/axios calls, URLSearchParams, GraphQL operations."""

from __future__ import annotations

from ..agent_phase import AgentPhase
from .base import Context


class AIJsPhase(AgentPhase):
    id = "06-js"
    name = "JavaScript analysis"
    version = "2.0"
    build_step = 5
    requires = ("00-intake", "04-map")
    role = "jsanalyst"
    max_turns = 150
    timeout_minutes = 120

    def task(self, ctx: Context) -> str:
        return (
            "Read the target's JavaScript for hidden endpoints and secrets. There can be a LOT of files, so "
            "work RESUMABLY and make forward progress every run - do not restart from the top each time.\n"
            "1. Build the queue: `hk endpoints --source js` and `hk endpoints` for the .js URLs found while "
            "crawling. Keep a file ./done.txt in this directory listing JS URLs you have already analysed. On "
            "every run, SKIP any URL already in ./done.txt and reuse any file you already downloaded here. "
            "Process the rest HIGHEST VALUE FIRST: login/auth, main/app/vendor bundles, admin, and the most "
            "sensitive hosts.\n"
            "2. For each file: download it in-scope through the proxy (curl) if it is not already local, then "
            "extract endpoints and parameters from high-signal sources (fetch()/axios, XMLHttpRequest, "
            "URLSearchParams, route tables, GraphQL operation names and variables) and add in-scope ones with "
            "`hk add endpoint GET <url>` (or the right method). Then append that file's URL to ./done.txt so "
            "the next run does not repeat it.\n"
            "3. Secrets: API keys, tokens, cloud/private keys, internal URLs -> `hk add lead secret-in-js "
            "<js-url> --evidence \"<which kind of key, NOT the value>\"`. Never write a secret value anywhere.\n"
            "4. Note interesting features (admin routes, feature flags, AI/LLM endpoints, GraphQL schema) for "
            "the testing phases, and call `hk progress \"js files\" <done> <total> files` as you go.\n"
            "Write ./handoff.md ONLY when the queue is fully drained (every in-scope JS URL is in ./done.txt) "
            "- that is what marks this phase complete. If you are running low on turns before then, stop "
            "cleanly WITHOUT writing handoff.md; your ./done.txt progress is saved and the next run continues "
            "where you left off. Put the new endpoints and the secrets (by kind) in that final handoff."
        )
