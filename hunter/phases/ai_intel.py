"""Phase 01, AI: intelligence from past and disclosed reports.

Reads the researcher's own past reports (reports.txt) and other researchers'
disclosed reports (resolved-reports.txt), and looks up public write-ups for
this program, to learn where bugs have been found before and which classes to
prioritise. Produces a prioritised list of hypotheses for the later phases;
contacts no target."""

from __future__ import annotations

from ..agent_phase import AgentPhase
from .base import Context


class IntelPhase(AgentPhase):
    id = "01-intel"
    name = "Intelligence: past and disclosed reports"
    version = "2.0"
    build_step = 5
    requires = ("00-intake",)
    role = "intel"
    max_turns = 60
    timeout_minutes = 60

    def task(self, ctx: Context) -> str:
        return (
            "Learn where bugs have been found in this program before, so later phases test the right things.\n"
            "1. Read ./reports.txt in the target folder if present (the researcher's own past reports). "
            "Resolved ones are fixed - note the bypass idea; open ones must NOT be duplicated - note them "
            "as 'avoid duplicate'.\n"
            "2. Read ./resolved-reports.txt if present (other researchers' disclosed reports) and pull out "
            "the recurring vulnerability patterns and the endpoints or features involved.\n"
            "3. You may look up public disclosed reports and write-ups for this program on the web "
            "(hackerone hacktivity, disclosed Intigriti/Bugcrowd reports, blogs). Reading the public web "
            "is allowed; do not touch the program's own hosts here.\n"
            "4. Record what you learn as notes and leads: `hk note \"...\"` for general guidance, and "
            "`hk add lead <kind> <url> --evidence \"from a past report: ...\"` for a specific endpoint or "
            "feature worth close testing (only if the URL is in scope).\n"
            "Write a prioritised hypotheses list to ./handoff.md: which vulnerability classes and which "
            "areas to focus on, and anything to avoid duplicating."
        )
