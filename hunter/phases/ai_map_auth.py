"""Phase 07c, AI: authenticated mapping and discovery.

The map (04) and discover (05) phases run UNAUTHENTICATED, so the richest
surface - admin panels, account settings, object/tenant endpoints, the whole
IDOR/BAC goldmine - is invisible to them. This phase logs in with the prepared
accounts and re-crawls the high-priority hosts WITH the session, and re-tries a
light discovery pass on paths that were 401/403 unauthenticated. Endpoints found
only with a session are tagged so the access-control phase knows to test them
cross-role.

It is a no-op (instant DONE) when there are no accounts: nothing to log in with.
Runs after 07-accounts (needs the session) and feeds 08-authz-logic and
09-injection. It MAPS as the authenticated user; it does not test access control
here (that is 08's job)."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIMapAuthPhase(AgentPhase):
    id = "07c-map-auth"
    name = "Authenticated mapping and discovery"
    version = "1.0"
    build_step = 6
    requires = ("00-intake", "04-map", "07-accounts")
    role = "mapper"
    max_turns = 110
    timeout_minutes = 180

    def _has_accounts(self, ctx: Context) -> bool:
        text = ctx.target.input_text("test-credentials.txt")
        # at least one non-comment line that looks like it carries a credential
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and any(c in line for c in (":", "|", "@")):
                return True
        return False

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Read ./test-credentials.txt; for EACH account, log in and capture its session "
                     "(cookies/bearer token). Keep the session per account.", "sessions.md"),
            MustStep("M2", "Re-crawl the high-priority in-scope hosts WITH each session (katana/curl with the "
                     "session header/cookies, through the proxy); import with `hk import katana`. New "
                     "endpoints are added to the inventory.", "authed-endpoints.txt"),
            MustStep("M3", "Re-try the paths that were 401/403 while unauthenticated (from discover's leads and "
                     "the inventory) WITH the session; record the ones that now return content."),
            MustStep("M4", "Record each authenticated-only endpoint with `hk add endpoint <method> <url> "
                     "--source crawl-auth` and note which account/role reached it; add a lead "
                     "(`hk add lead authed-endpoint <url> --evidence \"role X only\"`) for anything only one "
                     "role can reach - that is pre-IDOR signal for phase 08."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Map the AUTHENTICATED surface the unauthenticated crawl could not see. This is where the "
            "access-control bugs live, so it feeds phase 08 directly. You MAP here; you do not test access "
            "control yet.\n"
            "1. Read ./test-credentials.txt. For EACH account, log in through the proxy and capture its "
            "session - the cookies or the bearer/JWT token. If a login needs a CSRF token or a specific field, "
            "read the login page/JS for it (the login flow 07-accounts recorded may help). Write a short "
            "./sessions.md: account label -> how its session is sent (Cookie: ... or Authorization: ...).\n"
            "2. Re-crawl the HIGH-PRIORITY hosts (admin/app/api/portal and anything with a login) WITH each "
            "session: katana with the session header/cookies, or curl + a crawl of the links you see, through "
            "the proxy at the scope rate. Import each batch with `hk import katana <file>`. Save the new, "
            "authenticated-only URLs to ./authed-endpoints.txt.\n"
            "3. Take the paths that returned 401/403 unauthenticated (discover's leads, the inventory's gated "
            "endpoints) and request them again WITH the session. The ones that now return real content are "
            "authenticated endpoints - add them.\n"
            "4. Record every authenticated-only endpoint with `hk add endpoint <METHOD> <url> --source "
            "crawl-auth`, noting the account/role that reached it. If an endpoint is reachable by one role but "
            "should not be (e.g. a low-priv member reaching an admin route), that is strong pre-IDOR/BAC "
            "signal - record `hk add lead authed-endpoint <url> --evidence \"reached by role X\"` so phase 08 "
            "tests it cross-account.\n"
            "Stay with ONLY the accounts in ./test-credentials.txt; never use anyone else's session. In "
            "./handoff.md, summarise the authenticated surface per role and the strongest cross-role threads "
            "for the access-control phase."
        )

    def run(self, ctx: Context) -> PhaseResult:
        if not self._has_accounts(ctx):
            return PhaseResult(st.DONE, "no accounts available; authenticated mapping skipped")
        return super().run(ctx)

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        if not self._has_accounts(ctx):
            return PhaseResult(st.DONE, "no accounts available; authenticated mapping skipped")
        authed = store.endpoint_count(source="crawl-auth")
        missing = self.missing_artifacts(ctx)
        if not self.outputs_present(ctx) or missing:
            detail = f"; missing {', '.join(missing)}" if missing else "; agent did not finish"
            return PhaseResult(st.PARTIAL, f"{authed} authenticated endpoint(s){detail}, will continue")
        return PhaseResult(st.DONE, f"{authed} authenticated-only endpoint(s) mapped")
