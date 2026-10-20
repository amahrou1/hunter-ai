"""Phase 09b, AI: GraphQL testing.

Finds GraphQL endpoints, probes introspection (or recovers operations from JS),
and tests the GraphQL-specific bug classes: introspection exposure, GET-based
CSRF on mutations, and field-level over-exposure. Two deliberate boundaries:
per-object authorization / BOLA against mutations is handled by a SEPARATE
authenticated-testing effort and is not done here; DoS / query-cost abuse is
detected and NOTED, never executed (most programs exclude DoS).

Uses 06c-jsintel's graphql-ops.txt when present.
"""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class GraphQLPhase(AgentPhase):
    id = "09b-graphql"
    name = "GraphQL: introspection, CSRF, field exposure"
    version = "1.0"
    build_step = 9
    requires = ("00-intake", "04-map")
    role = "injection"
    max_turns = 100
    timeout_minutes = 90

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Find GraphQL endpoints (common paths + the ops from 06c-jsintel).",
                     "gql-endpoints.txt"),
            MustStep("M2", "Probe introspection; dump the schema if enabled, else recover operations "
                     "from JS.", "operations.txt"),
            MustStep("M3", "GET-based CSRF: if a state-changing mutation works over GET with cookies, "
                     "record a CSRF lead."),
            MustStep("M4", "Info exposure: field-suggestion/verbose errors, broad queries returning other "
                     "users' fields -> leads."),
            MustStep("M5", "DoS NOTE-ONLY: if query-cost/alias/deep-nesting abuse looks possible, record a "
                     "caveated lead - never execute it."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Test GraphQL. First read the playbook: `cat $(hk graphql)`.\n"
            "SCOPE BOUNDARY, important: do NOT test per-object authorization / BOLA on mutations here - that "
            "is a separate authenticated-testing effort. And DoS / query-cost / alias / deep-nesting abuse is "
            "DESCRIBED as a caveated lead, NEVER executed (programs commonly exclude DoS).\n"
            "For each GraphQL endpoint (common paths + 06c-jsintel's graphql-ops): confirm it, probe "
            "introspection (`{__schema{types{name}}}`) and dump the schema if enabled, else recover "
            "operations from the JS. Then test the GraphQL-specific classes: GET-based CSRF (url-encode the "
            "query, send a mutation over GET with the session cookie - if it works, that is CSRF), "
            "introspection/field-suggestion exposure, and overly broad queries that return other users' "
            "fields.\n"
            "Record findings with `hk finding add --kind graphql ...`; leads with `hk add lead graphql "
            "<endpoint> --evidence \"...\"`. In ./handoff.md, list the endpoints, whether introspection is on, "
            "the operation inventory, the leads, and an explicit note that per-object mutation authz is "
            "deferred to the authenticated-testing effort."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        finds = len([f for f in store.findings() if f["kind"] == "graphql"])
        leads = len([l for l in store.leads() if l["kind"] == "graphql"])
        note = f"{finds} graphql candidate(s), {leads} lead(s)"
        missing = self.missing_artifacts(ctx)
        if not self.outputs_present(ctx) or missing:
            detail = f"; missing {', '.join(missing)}" if missing else "; agent did not finish"
            return PhaseResult(st.PARTIAL, note + detail)
        return PhaseResult(st.DONE, note)
