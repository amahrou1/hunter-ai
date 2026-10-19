"""Phase 13, AI: report drafts.

Writes a submission-ready draft for each confirmed finding, in this
researcher's house style, and a run summary. Drafts only: the researcher
verifies and submits every one by hand. The system never submits anything."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


class AIReportPhase(AgentPhase):
    id = "13-report"
    name = "Report drafts and run summary"
    version = "2.0"
    build_step = 8
    requires = ("00-intake", "12-disprove")
    role = "writer"
    max_turns = 120
    timeout_minutes = 180

    def task(self, ctx: Context) -> str:
        return (
            "Write a submission-ready draft for every CONFIRMED finding. Drafts only - the researcher "
            "submits them by hand.\n"
            "`hk finding list --status confirmed`, and `hk finding show <id>` for each.\n"
            "Write one Markdown file per finding into a ./reports/ folder in your CURRENT WORKING DIRECTORY "
            "(./reports/<id>-<short-slug>.md); create the folder. House style, follow it exactly:\n"
            "- Plain English, short sentences, human-sounding. No em dashes. No AI-style formatting or filler.\n"
            "- Structure: clear title; summary (intended behaviour vs the issue); steps to reproduce as "
            "copy-paste, BOTH a browser/Burp version and a curl version; real business/user impact as one "
            "concrete scenario, not a list of justifications; CVSS 3.1 score with vector and a short "
            "rationale; and the Bugcrowd VRT category.\n"
            "- Written for a triager who knows nothing about the app. Not too long.\n"
            "- If the program policy requires disclosing AI assistance, add that note at the end.\n"
            "Then set each finding to reported (`hk finding set <id> --status reported`). Write a run summary "
            "to ./reports/SUMMARY.md: what was tested, what was found (by severity), and what to double-check "
            "before submitting. Point the researcher to the reports folder in ./handoff.md.\n"
            "Do not submit anything anywhere. Do not contact the program."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        # The agent writes drafts to ./reports in its work dir; publish them to
        # hunt-output/reports/ so the operator and `hunt findings` can see them
        # (same pattern as the handoff).
        out = ctx.target.output / "reports"
        work_reports = self._workdir(ctx) / "reports"
        if work_reports.is_dir():
            out.mkdir(parents=True, exist_ok=True)
            for src in work_reports.glob("*.md"):
                (out / src.name).write_text(src.read_text(encoding="utf-8", errors="replace"),
                                            encoding="utf-8")
        n = len(list(out.glob("*.md"))) if out.is_dir() else 0
        confirmed = len(store.findings("confirmed")) + len(store.findings("reported"))
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{n} draft(s) written; agent did not finish")
        return PhaseResult(st.DONE, f"{n} report draft(s) for {confirmed} confirmed finding(s)")
