"""Phase 14, AI: optional skills pass.

A final second look using the researcher's own skill playbooks (the skills.md
collection on the VPS). Re-checks the surface for anything the main phases
missed, following those playbooks. Optional: it is skipped cleanly if no
skills are installed."""

from __future__ import annotations

from pathlib import Path

from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


class AISkillsPhase(AgentPhase):
    id = "14-skills"
    name = "Skills pass (optional second look)"
    version = "2.0"
    build_step = 9
    requires = ("00-intake", "04-map")
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
