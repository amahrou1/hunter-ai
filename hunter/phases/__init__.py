"""The ordered list of phases. Unbuilt phases are explicit placeholders so
`hunt status` always shows the whole plan and what is still missing."""

from __future__ import annotations

from .base import Context, Phase, PhaseResult, PlannedPhase
from .p00_intake import IntakePhase
from .p02_recon import ReconPhase
from .p03_probe import ProbePhase
from .p02_recon import ReconPhase
from .p03_probe import ProbePhase


def all_phases() -> list[Phase]:
    return [
        IntakePhase(),
        PlannedPhase("01-intel", "Intelligence: past and disclosed reports", 5),
        ReconPhase(),
        ProbePhase(),
        PlannedPhase("04-map", "Mapping and crawl, request inventory, JavaScript collection", 4),
        PlannedPhase("05-discover", "Content and parameter discovery", 4),
        PlannedPhase("06-js", "JavaScript analysis", 5),
        PlannedPhase("07-accounts", "Accounts: supplied and self-registered", 6),
        PlannedPhase("08-authz-logic", "Access control, business logic and API testing", 6),
        PlannedPhase("09-injection", "Injection and client-side testing", 7),
        PlannedPhase("10-misconfig", "Misconfiguration, disclosure, gates, CORS, cache", 7),
        PlannedPhase("11-validate", "Validation with controls and attacker delivery", 8),
        PlannedPhase("12-disprove", "Independent disproof by a second session or model", 8),
        PlannedPhase("13-report", "Report drafts and run summary", 8),
        PlannedPhase("14-skills", "Skills pass (optional second look)", 9),
    ]


__all__ = ["Context", "Phase", "PhaseResult", "PlannedPhase", "ReconPhase", "ProbePhase", "all_phases"]
