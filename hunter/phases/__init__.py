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
from .ai_recon import AIReconPhase
from .ai_probe import AIProbePhase
from .ai_map import AIMapPhase
from .ai_discover import AIDiscoverPhase
from .ai_js import AIJsPhase
from .ai_accounts import AIAccountsPhase
from .ai_authz import AIAuthzPhase
from .ai_injection import AIInjectionPhase
from .ai_misconfig import AIMisconfigPhase
from .ai_validate import AIValidatePhase
from .ai_disprove import AIDisprovePhase
from .ai_report import AIReportPhase
from .ai_skills import AISkillsPhase


def all_phases() -> list[Phase]:
    return [
        IntakePhase(),
        IntelPhase(),
        GithubDorkPhase(),
        AIReconPhase(),
        AIProbePhase(),
        AIMapPhase(),
        AIDiscoverPhase(),
        AIJsPhase(),
        AIAccountsPhase(),
        AIAuthzPhase(),
        AIInjectionPhase(),
        AIMisconfigPhase(),
        # Skills pass is a TESTING phase: it must run before validation so any
        # finding/lead it produces is validated, disproved and reported.
        AISkillsPhase(),
        AIValidatePhase(),
        AIDisprovePhase(),
        AIReportPhase(),
    ]


__all__ = ["Context", "Phase", "PhaseResult", "PlannedPhase", "all_phases"]
