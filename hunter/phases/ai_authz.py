"""Phase 08, AI: access control, business logic and API testing.

The core of this researcher's methodology. Using the prepared accounts, tests
for broken access control and IDOR/BOLA, privilege escalation, tenant
isolation, business-logic flaws, and API/GraphQL authorization at the resolver
level. Records each candidate as a finding with a minimal, non-destructive
proof of concept for the validation phase to confirm."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIAuthzPhase(AgentPhase):
    id = "08-authz-logic"
    name = "Access control, business logic and API testing"
    version = "2.0"
    build_step = 6
    requires = ("00-intake", "04-map", "07-accounts")
    role = "authz"
    max_turns = 160
    timeout_minutes = 240

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M0", "List the open high-signal leads (`hk leads` - kinds hidden-endpoint, "
                     "auth-mechanism, role-string, login-weakness, origin-ip, vhost) and account for EACH in "
                     "./handoff.md: tested or skipped-with-reason. These are your sharpest starting points.",
                     "leads-addressed.md"),
            MustStep("M1", "Broken access control / IDOR / BOLA: do an action as the higher-priv account, "
                     "replay as the lower-priv one and with no session; a reachable object/action is a finding."),
            MustStep("M2", "Tenant isolation: can account A read/change account B's org data?"),
            MustStep("M3", "Privilege escalation: can a member reach owner/admin functions (direct URL, "
                     "forced browsing, parameter/role tampering)?"),
            MustStep("M4", "API & GraphQL authz at the resolver: REST object IDs; GraphQL variables, nested "
                     "queries, mutations, persisted/hashed queries."),
            MustStep("M5", "Business logic: price/quantity/step manipulation, state skipping, one-time-action "
                     "reuse. Record each with `hk finding add` incl. the control request; status candidate."),
            MustStep("M6", "Every login gate / admin or internal dashboard (from discover, jsintel, vhost "
                     "leads): run `hk login-probe <login-url>` (tries collected + default creds, capped - not "
                     "brute force) and `hk login-probe <login-url> --enum` for valid usernames. If a gate "
                     "enforces access CLIENT-SIDE (a deny page/redirect that the JS turns into 'allowed'), "
                     "forge the success response/flag and record a finding if you get in."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Test authorization and business logic, the highest-value area for this program.\n"
            "Read ./test-credentials.txt for the accounts and `hk endpoints` / `hk handoff` for the surface.\n"
            "Focus, in order:\n"
            "1. Broken access control / IDOR / BOLA: take an action as the higher-privilege or first account, "
            "capture the request, then replay it as the lower-privilege or second account (and with no "
            "session). If the object or action is reachable when it should not be, that is a finding.\n"
            "2. Tenant isolation: can account A read or change data belonging to account B's organisation?\n"
            "3. Privilege escalation: can a member reach owner/admin functions (by direct URL, forced "
            "browsing, parameter or role tampering)?\n"
            "4. API and GraphQL: authorization must hold at the resolver. Test REST object IDs, and for "
            "GraphQL test variables, nested queries, mutations and persisted/hashed queries (operation names "
            "from headers and JS), changing variables while keeping the hash.\n"
            "5. Business logic: price/quantity/step manipulation, state skipping, repeated use of one-time "
            "actions - whatever the app's workflows allow.\n"
            "6. LOGIN GATES & INTERNAL DASHBOARDS (high-value - this is where auth-bypass criticals live). For "
            "every admin/internal/login gate in the inventory (discover findings, jsintel hidden-endpoint and "
            "auth-mechanism leads, vhost leads):\n"
            "   a. `hk login-probe <login-url>` - it tries the credentials the run collected (org GitHub/JS "
            "leaks) first, then a small set of vendor defaults. It auto-detects the form field names, but if "
            "the login is a JSON API or an unusual form, FIRST read the page/JS for the real field names and "
            "pass them: `--user-field <name> --pass-field <name>` (add `--json-body` for a JSON API, and "
            "`--extra csrf=<token>` for any required hidden field). It is CAPPED in code (~25 attempts) and is "
            "NOT a brute force; use it, do not try to brute force by hand (that is blocked). A success is "
            "recorded as a finding automatically.\n"
            "   b. `hk login-probe <login-url> --enum` - differential username enumeration. If it finds valid "
            "usernames, that is a lead and a reason to try the collected creds for those users.\n"
            "   c. CLIENT-SIDE-ENFORCED ACCESS: if the gate denies with a page/redirect/status that the "
            "JavaScript decides on (e.g. a 403 or a non-200 'access denied', and the JS only shows the app on a "
            "specific status/body/flag), FORGE the success condition: re-request and rewrite the response to "
            "the allowed status/body the JS expects, or send the header/param/cookie the client checks. If the "
            "server does not actually enforce the gate, you reach the app - record a critical auth-bypass "
            "finding with the exact forge.\n"
            "   d. Read the auth-mechanism leads from jsintel: a header checked only for PRESENCE (not a valid "
            "credential) is a classic bypass - send a made-up value and see if you are let in.\n"
            "Rules: use ONLY accounts you created or were given. Show a problem with the SMALLEST possible "
            "proof (one object, one request). Never read or change real users' data beyond the minimum to "
            "prove access, never run destructive actions, never mass-enumerate. Capture the exact "
            "request(s) and the control request that shows the difference.\n"
            "Record each candidate: `hk finding add --title \"...\" --kind idor|bac|logic|graphql "
            "--severity <guess> --url <url> --summary \"intended vs what happens\" --steps \"exact requests, "
            "including the control\" --impact \"what an attacker gains\"`. Leave status as candidate; the "
            "validation phase confirms it. Note anything you could not finish in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        n = len(store.findings())
        missing = self.missing_artifacts(ctx)
        if not self.outputs_present(ctx) or missing:
            # Stay PARTIAL (resume next run) until the handoff AND the contract
            # artifacts exist - including leads-addressed.md, so the high-signal
            # leads meant for this phase are actually accounted for, not dropped.
            detail = f"; missing {', '.join(missing)}" if missing else "; agent did not finish"
            return PhaseResult(st.PARTIAL, f"{n} candidate finding(s){detail}, will continue")
        return PhaseResult(st.DONE, f"{n} candidate finding(s) recorded")
