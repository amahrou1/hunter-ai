"""Phase 10, AI: misconfiguration, disclosure, CORS and cache.

Checks the live services for security misconfigurations and information
disclosure that do not need an account: CORS, cookie and security headers,
cache behaviour, exposed files and listings, verbose errors and version
leaks, default or debug pages, and the exposed services found by the port
scan. Turns the discovery-phase leads into findings where they hold up."""

from __future__ import annotations

from ..agent_phase import AgentPhase, MustStep
from .base import Context


class AIMisconfigPhase(AgentPhase):
    id = "10-misconfig"
    name = "Misconfiguration, disclosure, gates, CORS, cache"
    version = "2.0"
    build_step = 7
    requires = ("00-intake", "04-map", "05-discover")
    role = "misconfig"
    max_turns = 110
    timeout_minutes = 150

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Confirm the discovery leads (`hk leads`): verify each exposed file/service is "
                     "real, say what it exposes, promote real ones to findings."),
            MustStep("M2", "CORS: test arbitrary/null Origin reflection with credentials."),
            MustStep("M3", "Security & cookie headers with real impact (CSP/HSTS/XFO; Secure/HttpOnly/"
                     "SameSite on authed hosts)."),
            MustStep("M4", "Cache: is any per-user/sensitive response cacheable or shared-cached "
                     "(deception/poisoning signals)?"),
            MustStep("M5", "Disclosure: verbose errors, stack traces, version banners, dir listings, "
                     "debug pages; and confirm each exposed-service lead read-only."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Check the live services for misconfigurations and information disclosure (no account needed).\n"
            "1. Review the discovery leads (`hk leads`): confirm the exposed files are real and say what they "
            "expose (use `hk check-content` where it fits). Promote the real ones to findings.\n"
            "2. CORS: does any endpoint reflect an arbitrary Origin with credentials? Test with a crafted "
            "Origin header and check Access-Control-Allow-Origin/Credentials.\n"
            "3. Security and cookie headers: missing or weak CSP, HSTS, X-Frame-Options; cookies without "
            "Secure/HttpOnly/SameSite on authenticated hosts. Report only where it has real impact.\n"
            "4. Cache: run `hk cache <url>` on per-user/sensitive and reflected-input endpoints - it "
            "probes unkeyed-header poisoning and static-suffix deception (detect-only, on its own cache key) "
            "and records a lead for any signal. Confirm a real lead by hand before reporting.\n"
            "5. Disclosure: verbose errors, stack traces, version banners, directory listings, debug pages.\n"
            "   Run `hk techhints` first: it lists high-yield checks for the exact stacks fingerprinted on "
            "this target (Salesforce/IIS/ASP.NET/Rails/WordPress/Grafana/JIRA/Swagger/Spring...). Work the "
            "ones that apply.\n"
            "6. The exposed services from the port scan (`hk leads` kind exposed-service): confirm what each "
            "one exposes, read-only, without logging in.\n"
            "Record each real issue with `hk finding add` (kind cors|headers|cache|info-leak|exposure, a "
            "severity guess, the exact request, and the concrete impact), status candidate. Avoid "
            "best-practice noise with no impact. Summarise in ./handoff.md."
        )
