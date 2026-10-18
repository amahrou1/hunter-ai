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
    max_turns = 80
    timeout_minutes = 120

    def task(self, ctx: Context) -> str:
        return (
            "Read the JavaScript for hidden endpoints and secrets.\n"
            "1. `hk endpoints --source js` and `hk endpoints` for the .js URLs found while crawling. "
            "Download the in-scope ones through the proxy (curl) into files.\n"
            "2. Extract endpoints and parameters, focusing on high-signal sources: fetch()/axios calls, "
            "XMLHttpRequest, URLSearchParams, route tables, and GraphQL operation names and variables. "
            "Add in-scope ones with `hk add endpoint GET <url>` (or the right method).\n"
            "3. Look for leaked secrets: API keys, tokens, cloud keys, private keys, internal URLs. If you "
            "find one, record it with `hk add lead secret-in-js <js-url> --evidence \"<which kind of key, "
            "NOT the value>\"` - never write the secret value anywhere.\n"
            "4. Note any interesting feature the JS reveals (admin routes, feature flags, AI/LLM endpoints, "
            "GraphQL schema) for the testing phases.\n"
            "Summarise the new endpoints and any secrets (by kind) in ./handoff.md."
        )
