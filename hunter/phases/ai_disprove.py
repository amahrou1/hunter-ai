"""Phase 12, AI: independent disproof.

A second, adversarial pass (run on the disprover model, which can be a
different provider) that actively tries to prove each validated finding WRONG:
a benign explanation, a non-security cause, out-of-scope, already-public, or
not reproducible. Only findings that survive become confirmed. This stops the
system from grading its own work and keeps false reports from reaching you."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIDisprovePhase(AgentPhase):
    id = "12-disprove"
    name = "Independent disproof by a second session or model"
    version = "2.0"
    build_step = 8
    requires = ("00-intake", "11-validate")
    role = "disprover"
    max_turns = 120
    timeout_minutes = 180

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "For each validated finding, try hard to prove it WRONG: does it reproduce now? "
                     "is there a benign explanation? is the asset in scope and the class accepted? is it a "
                     "known duplicate?"),
            MustStep("M2", "If it survives all challenges, set status confirmed; otherwise set status "
                     "disproved with the reason. A finding you are unsure about is disproved, not confirmed. "
                     "Dependency-confusion: confirm if still unclaimed; do not disprove for lacking a live "
                     "callback."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Try hard to prove each validated finding WRONG. You are the skeptic; assume it is a false "
            "positive until it survives your challenge.\n"
            "`hk finding list --status validated`. For each one, ask and test:\n"
            "- Does it actually reproduce right now, from the steps, through the proxy?\n"
            "- Is there a benign explanation (the 'victim' object is public anyway; the second account was "
            "in the same tenant on purpose; the reflection is not executed; the error is cosmetic)?\n"
            "- Is the affected asset really in scope, and is the class accepted by the program (not on the "
            "excluded list)?\n"
            "- Is it already public or a known/duplicate issue (from the intel phase)?\n"
            "For a dependency-confusion finding, 'reproduce' means the package name is still unclaimed on the "
            "public registry (re-check the GET); confirm those - do NOT disprove them merely for having no "
            "live callback, since publishing the package is the operator's manual step. Still disprove if the "
            "name is actually public/owned, the asset is out of scope, or the class is excluded.\n"
            "If it survives all of that, `hk finding set <id> --status confirmed`. If not, "
            "`hk finding set <id> --status disproved --evidence \"why it does not hold: ...\"`.\n"
            "Be strict: a finding you are not sure about is disproved, not confirmed. List the confirmed and "
            "the dropped ones, with reasons, in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        confirmed = len(store.findings("confirmed"))
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{confirmed} confirmed so far; agent did not finish")
        return PhaseResult(st.DONE, f"{confirmed} finding(s) confirmed")

    def needs_rerun(self, ctx: Context, store: A.Assets) -> bool:
        return len(store.findings("validated")) > 0   # validated findings not yet confirmed/dropped
