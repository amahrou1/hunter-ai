"""The ordered pipeline. `hunt start` runs these in order, on their own.

00-intake is code (it builds the scope guard and must be deterministic); it
calls an AI to read the policy. Every other phase is an AI agent that decides
and acts, with the scope proxy, the command checker and the orchestrator
enforcing safety in code. One command per target runs the whole chain."""

from __future__ import annotations

from .base import Context, Phase, PhaseResult, PlannedPhase
from .p00_intake import IntakePhase
from .ai_intel import IntelPhase
from .ai_dork import GithubDorkPhase
from .ai_expand import ScopeExpandPhase
from .ai_recon import AIReconPhase
from .ai_probe import AIProbePhase
from .ai_map import AIMapPhase
from .ai_discover import AIDiscoverPhase
from .ai_js import AIJsPhase
from .ai_jsintel import JsIntelPhase
from .ai_depconf import DepConfusionPhase
from .ai_accounts import AIAccountsPhase
from .ai_authflows import AuthFlowsPhase
from .ai_authz import AIAuthzPhase
from .ai_injection import AIInjectionPhase
from .ai_graphql import GraphQLPhase
from .ai_misconfig import AIMisconfigPhase
from .ai_hunt import AIHuntPhase
from .ai_validate import AIValidatePhase
from .ai_disprove import AIDisprovePhase
from .ai_report import AIReportPhase
from .ai_skills import AISkillsPhase


def all_phases() -> list[Phase]:
    return [
        IntakePhase(),
        IntelPhase(),
        GithubDorkPhase(),
        # Scope expansion: for *.brand.* or ownership scopes, discover and prove
        # the owned domains/TLDs and add them before recon enumerates them. A
        # no-op (instant DONE) on a plain, explicit scope.
        ScopeExpandPhase(),
        AIReconPhase(),
        AIProbePhase(),
        AIMapPhase(),
        AIDiscoverPhase(),
        AIJsPhase(),
        # Semantic JS analysis: auth mechanisms, roles, hidden endpoints, GraphQL
        # ops, secrets and DOM sinks. Runs after 06-js (reuses its downloads) and
        # before the testing phases it feeds.
        JsIntelPhase(),
        # Dependency confusion: internal package names from the harvested JS (+
        # the org repos) cross-referenced against public registries. Runs before
        # validation so its candidates are validated, disproved and reported.
        DepConfusionPhase(),
        AIAccountsPhase(),
        # Account & auth-flow logic (registration/reset/2FA/OAuth ATO class).
        # Needs the accounts from 07-accounts; not IDOR (a separate effort).
        AuthFlowsPhase(),
        AIAuthzPhase(),
        AIInjectionPhase(),
        # GraphQL-specific testing (introspection, GET-CSRF, field exposure).
        # Per-object mutation authz is deferred to the authed-testing effort;
        # DoS is noted, never executed.
        GraphQLPhase(),
        AIMisconfigPhase(),
        # Skills pass is a TESTING phase: it must run before validation so any
        # finding/lead it produces is validated, disproved and reported.
        AISkillsPhase(),
        # Free hunt: the creative capstone. Runs after all structured testing and
        # the skills pass, with the whole picture in hand, and before validation.
        AIHuntPhase(),
        AIValidatePhase(),
        AIDisprovePhase(),
        AIReportPhase(),
    ]


__all__ = ["Context", "Phase", "PhaseResult", "PlannedPhase", "all_phases"]
