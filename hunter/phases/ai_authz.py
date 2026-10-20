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
            MustStep("M1", "Broken access control / IDOR / BOLA: do an action as the higher-priv account, "
                     "replay as the lower-priv one and with no session; a reachable object/action is a finding."),
            MustStep("M2", "Tenant isolation: can account A read/change account B's org data?"),
            MustStep("M3", "Privilege escalation: can a member reach owner/admin functions (direct URL, "
                     "forced browsing, parameter/role tampering)?"),
            MustStep("M4", "API & GraphQL authz at the resolver: REST object IDs; GraphQL variables, nested "
                     "queries, mutations, persisted/hashed queries."),
            MustStep("M5", "Business logic: price/quantity/step manipulation, state skipping, one-time-action "
                     "reuse. Record each with `hk finding add` incl. the control request; status candidate."),
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
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{n} candidate finding(s); agent did not finish, will continue")
        return PhaseResult(st.DONE, f"{n} candidate finding(s) recorded so far")
