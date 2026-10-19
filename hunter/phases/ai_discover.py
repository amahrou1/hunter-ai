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
            "Find unlinked files and paths, tuned to each asset - this is where many bugs are found, so do "
            "it like a hunter, not a blind brute force. First read the playbook: `cat $(hk playbook)`.\n"
            "Work through the services highest-priority first (`hk services --todo discovered`). For EACH "
            "service:\n"
            "1. Get its tailored plan: `hk fuzzplan <service-id>`. It gives the right wordlist(s), the "
            "extensions for that stack (ASP.NET, PHP, Java, API, ...), and a params wordlist - chosen from the "
            "service's fingerprint. Use those, not one generic list.\n"
            "2. Run ffuf through the proxy with that wordlist and `-e <extensions from the plan>` "
            "(-json -ac -mc 200,201,204,301,302,307,401,403,405,500 -rate <scope rate> -sf), save to a file, "
            "`hk import ffuf <file>` (it drops this site's known noise). If an import warns of a catch-all "
            "(most hits one status+length), run the `hk filter` it suggests and re-run that site. Always also "
            "run one general pass; on a high-value host add a deeper pass with `hk wordlist --kind big`.\n"
            "3. RECURSE WITH JUDGEMENT. For every interesting hit (admin, dashboard, internal, api, upload, "
            "backup, config, a 401/403 gate, an odd 200): fetch it, read the response and source, and decide "
            "what it is - an internal dashboard or admin panel reachable without auth, a sensitive-data or "
            "stack-trace leak, a login/gate for later auth testing, a WAF/block page, or useless. Record a "
            "finding (`hk finding add`) for a real exposure, a lead for something to test later, and skip the "
            "noise. Only then fuzz one level deeper (e.g. /admin -> /admin/FUZZ), at most 2-3 levels, stopping "
            "a branch that turns to noise or a WAF wall. For a 403, try the bypasses in the playbook "
            "(ASP.NET cookieless (S(x)) tokens, case/slash/normalisation tricks).\n"
            "4. PARAMETERS on dynamic endpoints (.php/.aspx/.ashx/.jsp/.do or API routes): find hidden params "
            "with `arjun -u <url>` if installed, else fuzz the params wordlist from the plan. Record each as a "
            "lead (`hk add lead parameters <url> --evidence \"params: ...\"`) for the injection and authz "
            "phases. If a param looks like a boolean gate (authenticated=, isAdmin=, debug=), try flipping it "
            "and record a BAC/logic finding if access or behaviour changes; if it looks like a path/url/id/"
            "query, record it as an injection candidate (do not exploit destructively here).\n"
            "5. `hk mark discovered <service-id>...` as you finish each, and `hk progress` as you go.\n"
            "Finish when the services are searched. In ./handoff.md list the confirmed exposures, the gated "
            "endpoints for the auth phase, and the parameter leads for the injection phase."
        )
