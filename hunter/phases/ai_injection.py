"""Phase 09, AI: injection and client-side testing.

Tests the mapped parameters and endpoints for injection and client-side flaws
(reflected/stored/DOM XSS, SQL and NoSQL injection, SSRF, SSTI, open redirect,
header/host injection) and, where the app has AI/LLM features, prompt-injection
and model-authorization issues. Detection and minimal proof only: never a
destructive or data-exfiltrating payload."""

from __future__ import annotations

from ..agent_phase import AgentPhase, MustStep
from .base import Context


class AIInjectionPhase(AgentPhase):
    id = "09-injection"
    name = "Injection and client-side testing"
    version = "2.0"
    build_step = 7
    requires = ("00-intake", "04-map")
    role = "injection"
    max_turns = 160
    timeout_minutes = 240

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M0", "List the open high-signal leads (`hk leads` - kinds parameters, 403-bypass, "
                     "hidden-endpoint, dom-sink, graphql-op, secret-in-js, origin-ip) and account for EACH in "
                     "./handoff.md: tested (with result) or skipped (with reason). Do not leave them unread.",
                     "leads-addressed.md"),
            MustStep("M1", "Gather the test surface: interesting params (`hk endpoints`), the 'parameters' "
                     "and injection-candidate leads (`hk leads`), and forms."),
            MustStep("M2", "Test each for reflected/stored/DOM XSS, SQL/NoSQL, SSRF, SSTI, open redirect, "
                     "CRLF/header/host-header injection - detect with a harmless marker, then stop."),
            MustStep("M3", "Where the app has AI/LLM features, test prompt injection, system-prompt/tool-"
                     "schema leakage, and authz on AI-backed endpoints (REST and WebSocket)."),
            MustStep("M4", "Record each candidate with `hk finding add` (exact request + the marker/response "
                     "that proves it), status candidate; respect the excluded-vuln list."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Test the mapped parameters and inputs for injection and client-side flaws. Use the interesting "
            "parameters from the crawl (`hk endpoints`), the parameter leads discovery recorded "
            "(`hk leads` - kinds 'parameters' and injection candidates), and any forms.\n"
            "START by reading the open high-signal leads the earlier phases left you: `hk leads`. The kinds "
            "that are yours to act on - parameters, 403-bypass, hidden-endpoint, dom-sink, graphql-op, "
            "secret-in-js, origin-ip - are concrete starting points other hunters do not have. Work each one "
            "and, in ./handoff.md, write a line per lead: tested (what you found) or skipped (why). These "
            "leads are the highest-signal surface on the target; do not leave them untouched.\n"
            "Cover: reflected/stored/DOM XSS, SQL and NoSQL injection, SSRF, SSTI, open redirect, CRLF/"
            "header and host-header injection. Where the app has AI/LLM features, also test prompt injection, "
            "system-prompt or tool-schema leakage, and authorization on AI-backed endpoints (REST and "
            "WebSocket); a reliable detector is a conditional probe like asking the model to do X only if a "
            "nonexistent token is absent.\n"
            "Method: use a harmless marker to DETECT the flaw (a unique string for reflection, a boolean or "
            "short time-based test for injection, an out-of-band callback only to a host you are allowed to "
            "use). Confirm it is real, then stop. Do NOT weaponise: no payload that reads real user data, "
            "drops or changes data, runs commands for impact, or causes denial of service. For XSS, a "
            "proof that script executes (e.g. a marker in the DOM) is enough - no cookie theft against real "
            "users.\n"
            "Stay in scope and under the rate limit (the proxy enforces both). Respect the program's "
            "excluded vulnerability list.\n"
            "Record each candidate with `hk finding add --kind xss|sqli|ssrf|ssti|redirect|injection "
            "--severity <guess> --url <url> --summary ... --steps \"exact request and the marker/response "
            "that proves it\" --impact ...` and leave status candidate. Note unfinished areas in ./handoff.md."
        )
