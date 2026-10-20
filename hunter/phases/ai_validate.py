"""Phase 11, AI: validation.

Re-proves each candidate finding with a clean, controlled test: the vulnerable
request next to a control request that should behave differently, run fresh.
Confirms reproducibility, settles the real severity and CVSS, and either marks
the finding validated or drops it. This is the gate before anything becomes a
report."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


class AIValidatePhase(AgentPhase):
    id = "11-validate"
    name = "Validation with controls and attacker delivery"
    version = "2.0"
    build_step = 8
    requires = ("00-intake",)
    role = "validator"
    max_turns = 140
    timeout_minutes = 240

    def task(self, ctx: Context) -> str:
        return (
            "Re-prove every candidate finding so only real, reproducible ones go forward.\n"
            "`hk finding list --status candidate`. For each one:\n"
            "1. Reproduce it fresh from the steps, through the proxy. Run the vulnerable request AND a "
            "control request that should behave differently (e.g. the same call as the un-privileged account, "
            "or without the payload). The difference is the proof.\n"
            "2. Confirm it is consistent, not a one-off or a measurement artefact. If it does not reproduce, "
            "set the finding to disproved with a short reason: `hk finding set <id> --status disproved "
            "--evidence \"did not reproduce: ...\"`.\n"
            "3. For the real ones, settle the severity and a CVSS 3.1 vector with a one-line rationale, and "
            "tighten the steps to a clean copy-paste sequence. Then `hk finding set <id> --status validated "
            "--severity <s> --cvss \"<vector>\" --steps \"...\" --impact \"...\" --evidence \"control vs "
            "vulnerable: ...\"`.\n"
            "Dependency-confusion candidates (kind=dependency-confusion) validate differently: their proof is "
            "that the package name is STILL unclaimed on the public registry - re-run the one registry GET "
            "(`hk depconf` has the URLs). If still unclaimed, set it validated and KEEP the operator's "
            "publish+callback PoC in the steps; do NOT publish anything, and do NOT drop it for lacking a live "
            "callback (publishing is the operator's manual step). Disprove it only if the name is now claimed "
            "by the target or a legitimate owner.\n"
            "Stay within scope and the rules; keep proofs minimal and non-destructive. Summarise which "
            "findings passed and which were dropped in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        validated = len(store.findings("validated"))
        candidates = len(store.findings("candidate"))
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{validated} validated, {candidates} still to check")
        return PhaseResult(st.DONE, f"{validated} finding(s) validated")

    def needs_rerun(self, ctx: Context, store: A.Assets) -> bool:
        return len(store.findings("candidate")) > 0   # unvalidated candidates waiting
