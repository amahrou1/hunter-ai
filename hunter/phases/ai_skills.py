"""Phase 10b, AI: skills pass (a second look with the researcher's playbooks).

Runs AFTER the main testing phases (06-js .. 10-misconfig) and BEFORE validation,
so any finding or lead it produces still goes through 11-validate, 12-disprove
and 13-report like every other testing phase. (It used to run dead last, after
the report, so its findings were never validated or reported - fixed.) Re-checks
the surface using the researcher's own skill playbooks (the skills collection on
the VPS). Optional: skipped cleanly if no skills are installed."""

from __future__ import annotations

from pathlib import Path

from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AISkillsPhase(AgentPhase):
    id = "10b-skills"
    name = "Skills pass (optional second look)"
    version = "2.1"
    build_step = 7
    requires = ("00-intake", "04-map", "05-discover")
    role = "authz"
    max_turns = 120
    timeout_minutes = 180

    def _skills_dir(self, ctx: Context) -> Path:
        return Path(ctx.settings.get("skills", {}).get("dir") or Path.home() / ".claude" / "skills")

    def run(self, ctx: Context) -> PhaseResult:
        skills = self._skills_dir(ctx)
        if not skills.is_dir() or not any(skills.rglob("SKILL.md")) and not any(skills.rglob("*.md")):
            ctx.log("no skills installed; skipping the skills pass")
            return PhaseResult(st.NOT_APPLICABLE, "no skills installed")
        return super().run(ctx)

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "List the researcher's skill playbooks and read the ones that fit this target."),
            MustStep("M2", "Follow each relevant playbook against the mapped surface, reusing the test "
                     "accounts, looking for what earlier phases missed."),
            MustStep("M3", "Record new candidates with `hk finding add` (they go through validation/disproof)."),
        ]

    def task(self, ctx: Context) -> str:
        skills = self._skills_dir(ctx)
        return (
            f"Do a final second look using the researcher's skill playbooks in {skills}.\n"
            "1. List the available skills there and read the ones that fit this target (their SKILL.md or "
            ".md files).\n"
            "2. Follow each relevant playbook against the mapped surface (`hk endpoints`, `hk services`, "
            "`hk handoff`), looking for anything the earlier phases missed. Reuse the accounts in "
            "./test-credentials.txt.\n"
            "3. Same rules as the other testing phases: in scope only, minimal non-destructive proof, record "
            "new candidates with `hk finding add` (they will go through validation and disproof).\n"
            "Summarise what the skills pass added in ./handoff.md."
        )
