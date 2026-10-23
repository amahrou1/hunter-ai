"""Phase 06c, AI: JavaScript intelligence (deep semantic analysis).

06-js collects the files and pulls obvious endpoints. This phase reads the JS
for MEANING - the things a grep misses that become real bugs: the auth
mechanism and token builders (the classic "presence-only Authorization" bypass
lives here), role strings, hidden/admin/legacy endpoints, GraphQL operations,
secrets, and dangerous DOM sinks. Everything becomes inventory leads that make
the testing phases (injection, authz, graphql) sharp.

It does not exploit anything; it produces the map. Reuses 06-js's downloads;
registries/JS are read through the scope proxy.
"""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class JsIntelPhase(AgentPhase):
    id = "06c-jsintel"
    name = "JavaScript intelligence: endpoints, auth, roles, secrets, sinks"
    version = "1.0"
    build_step = 6
    requires = ("00-intake", "04-map")
    role = "intel"
    max_turns = 120
    timeout_minutes = 120

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Extract every REST endpoint in the JS, grouped by function; add in-scope ones "
                     "with `hk add endpoint`.", "endpoints.txt"),
            MustStep("M2", "Extract GraphQL query/mutation/subscription names and shapes.", "graphql-ops.txt"),
            MustStep("M3", "Describe the auth mechanism: token builders (e.g. an Authorization: Basic "
                     "constructor), where tokens live, any presence-only check.", "auth.md"),
            MustStep("M4", "Record hidden/admin/debug/legacy endpoints and client-side route gates as leads.",
                     "hidden.txt"),
            MustStep("M5", "Record role/permission strings (ROLE_ADMIN, isAdmin, scopes) for the "
                     "authenticated-testing phase.", "roles.txt"),
            MustStep("M6", "Run `hk secrets <jsdir>` over the bundles; record real ones by KIND only "
                     "(`hk add lead secret-in-js`). If you find an actual username:password pair (a hardcoded "
                     "login, a default admin, a basic-auth string), record it with `hk creds add 'user:pass'` "
                     "so the authz phase tries it on login gates.", "secrets.txt"),
            MustStep("M7", "Record dangerous DOM sinks and their sources (innerHTML, document.write, "
                     "location/hash, postMessage, window.name, eval) as DOM-XSS leads.", "sinks.txt"),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Read the target's JavaScript for MEANING - the auth, roles, hidden endpoints, GraphQL ops, "
            "secrets and sinks that become real bugs. First read the playbook: `cat $(hk jsintel)`.\n"
            "Reuse what 06-js already downloaded (see `hk handoff` for 06-js and its work dir); fetch a "
            "missing bundle with curl through the proxy - do NOT re-crawl. Beautify minified files where it "
            "helps, then read for structure, not just patterns.\n"
            "Produce each artifact in the run contract above. The highest-value targets: trace how the "
            "`Authorization` header is BUILT (a header checked for presence, not a validated credential, is a "
            "critical bypass); any client-side role gate (server often does not enforce it); and any "
            "user-controllable source (location.hash, postMessage.data, window.name, a query param) flowing "
            "into a DOM sink.\n"
            "Record in-scope endpoints with `hk add endpoint`, and everything else of value as precise leads "
            "(`hk add lead hidden-endpoint|auth-mechanism|dom-sink|graphql-op|role-string|secret-in-js|"
            "adjacent-host <url> --evidence \"...\"`). Secrets: `hk secrets` first, record by KIND only, "
            "never a value. Do NOT exploit anything here - this phase is the map for the testing phases.\n"
            "In ./handoff.md, group what you found and name the 10 highest-value threads for the testing "
            "phases."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        n_ep = store.endpoint_count()
        n_leads = len([l for l in store.leads()
                       if l["kind"] in ("hidden-endpoint", "auth-mechanism", "dom-sink",
                                        "graphql-op", "role-string", "secret-in-js", "adjacent-host")])
        note = f"{n_ep} endpoints in inventory, {n_leads} jsintel lead(s)"
        missing = self.missing_artifacts(ctx)
        if not self.outputs_present(ctx) or missing:
            detail = f"; missing {', '.join(missing)}" if missing else "; agent did not finish"
            return PhaseResult(st.PARTIAL, note + detail)
        return PhaseResult(st.DONE, note)
