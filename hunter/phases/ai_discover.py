"""Phase 05, AI: content and parameter discovery.

Searches each live service for files and paths that are not linked anywhere:
admin panels, API docs, debug endpoints, version-control folders, config and
backup files. Uses the per-service baselines and noise filters so catch-all
pages do not produce false hits, and confirms sensitive hits by content."""

from __future__ import annotations

from ..agent_phase import AgentPhase, MustStep
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

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Read the fuzzing playbook first: `cat $(hk playbook)` (wordlists, extensions, "
                     "403-bypass tricks)."),
            MustStep("M2", "Pick the HIGH-VALUE hosts (admin/api/internal/auth/portal/vpn/dashboard names, "
                     "login gates, odd or old tech) and list them in ./deep-targets.md - these get deep, "
                     "targeted fuzzing, not one shallow pass.", "deep-targets.md"),
            MustStep("M3", "For each service, get its tailored plan `hk fuzzplan <service-id>` and ffuf with "
                     "that wordlist + extensions through the proxy; `hk import ffuf`. On the deep targets: "
                     "detect the stack and use the MATCHING wordlist + extensions (ASP.NET -> .aspx/.asmx/"
                     ".ashx + IIS lists; PHP -> .php/.phps; Java -> .jsp/.do/.action; API -> api list), and "
                     "fuzz RECURSIVELY on every promising directory."),
            MustStep("M4", "Triage every interesting hit (admin/internal/api/upload/backup/config/401-403): "
                     "fetch, read, record a finding for a real exposure or a lead to test later; recurse "
                     "deeper on the high-value hosts (4-5 levels while it stays productive). Try the playbook's "
                     "403 bypasses on EVERY gated path - do not stop at a 401/403."),
            MustStep("M5", "Discover hidden parameters on dynamic endpoints (arjun or the plan's params list); "
                     "record each as a lead for the injection/authz phases."),
            MustStep("M6", "`hk mark discovered <service-id>` as you finish each service."),
            MustStep("M7", "For hosts behind a WAF/CDN (Cloudflare/Akamai/Fastly server header, or a WAF block "
                     "page), run `hk origin <host>` to find the real origin IP. If it finds one in scope, fuzz "
                     "it directly - the origin usually leaks what the edge hides."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Find unlinked files and paths, tuned to each asset - this is where many bugs are found, so do "
            "it like a hunter, not a blind brute force. First read the playbook: `cat $(hk playbook)`.\n"
            "\n"
            "FIRST, TRIAGE FOR DEPTH (this is what separates a real hunter from a scanner). Look over "
            "`hk services` and pick the HIGH-VALUE hosts: admin/api/internal/auth/portal/vpn/dashboard/git/"
            "jenkins names, anything with a login gate, anything on odd or old tech. Write them to "
            "./deep-targets.md. Those get DEEP, TARGETED, RECURSIVE fuzzing with the wordlist and extensions "
            "that MATCH their stack. The rest get the standard pass. Spreading equal shallow effort over "
            "everything is how bugs get missed - concentrate on the juicy targets.\n"
            "\n"
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
            "noise. Only then fuzz one level deeper (e.g. /admin -> /admin/FUZZ). Recursion depth is by VALUE: "
            "go SHALLOW (1-2 levels) on ordinary hosts, but DEEP (4-5 levels, as long as each level keeps "
            "producing real paths) on the high-value hosts in ./deep-targets.md - that is where the buried "
            "panels and debug endpoints live. Stop a branch that turns to noise or a WAF wall. For a 403, try "
            "the bypasses in the playbook (ASP.NET cookieless (S(x)) tokens, case/slash/normalisation tricks).\n"
            "4. PARAMETERS on dynamic endpoints (.php/.aspx/.ashx/.jsp/.do or API routes): find hidden params "
            "with `arjun -u <url>` if installed, else fuzz the params wordlist from the plan. Record each as a "
            "lead (`hk add lead parameters <url> --evidence \"params: ...\"`) for the injection and authz "
            "phases. If a param looks like a boolean gate (authenticated=, isAdmin=, debug=), try flipping it "
            "and record a BAC/logic finding if access or behaviour changes; if it looks like a path/url/id/"
            "query, record it as an injection candidate (do not exploit destructively here).\n"
            "5. `hk mark discovered <service-id>...` as you finish each, and `hk progress` as you go.\n"
            "6. ORIGIN BEHIND A WAF: if a host sits behind Cloudflare/Akamai/Fastly or shows a WAF block page, "
            "run `hk origin <host>`. It finds the real origin IP from passive data (certificate siblings, mail/"
            "infra names) and, if that IP is in scope, confirms it serves the app directly. To widen it, first "
            "gather candidate IPs yourself from the OSINT sources whose keys are set - Shodan "
            "(`hostname:<host>`), Censys, SecurityTrails IP history, ViewDNS - and pass them in: "
            "`hk origin <host> --ips 1.2.3.4,5.6.7.8`. A reachable origin is gold - the WAF's protections and "
            "rate limits usually do not apply there, so fuzz it directly for stack traces, debug endpoints and "
            "admin panels the edge hides. An out-of-scope origin IP is recorded as an observation for the "
            "operator, not tested.\n"
            "Finish when the services are searched. In ./handoff.md list the confirmed exposures, the gated "
            "endpoints for the auth phase, and the parameter leads for the injection phase."
        )
