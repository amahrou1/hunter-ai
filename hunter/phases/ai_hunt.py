"""Phase 10c, AI: free hunt (deep, creative, chaining).

After every structured phase has mapped and tested the surface, this hands the
agent the whole picture - inventory, leads, findings, every handoff, the
researcher's own past reports and other researchers' disclosed reports - and
turns it loose: decide where the bugs are, go deep, and CHAIN. It is the
creative layer on top of the methodical pipeline, run before validation so
anything it finds is validated, disproved and reported like any other.

The hard problem here is laziness: weak models poke for a few minutes and
announce "no bugs". Two things fight that. The prompt challenges effort (not a
quota) with the true fact that active programs take valid criticals/highs every
day, so the surface almost certainly holds findable bugs. And `check()` enforces
a real floor: the agent must log the hypotheses it tested, and a thin log is
PARTIAL (it re-runs and goes deeper), so shallow effort does not pass.
"""

from __future__ import annotations

import re

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult

# A run that passes must show it genuinely tried. The agent logs one entry per
# hypothesis it tested; fewer than this is shallow -> PARTIAL, so it continues.
MIN_HYPOTHESES = 12


class AIHuntPhase(AgentPhase):
    id = "10c-hunt"
    name = "Free hunt: deep, creative, chaining"
    version = "1.0"
    build_step = 7
    requires = ("00-intake", "10-misconfig")
    role = "hunter"
    max_turns = 400
    timeout_minutes = 300

    def task(self, ctx: Context) -> str:
        return (
            "== FREE HUNT: you are off the rails now ==\n"
            "Every structured phase has run. The whole surface is mapped, fingerprinted, fuzzed, and tested, "
            "and the leads are in the inventory. Now you hunt like a top human researcher in a live "
            "competition: YOU decide where the bugs are, from the data, and you go deep.\n"
            "\n"
            "Mindset - read this twice:\n"
            "- On platforms like Intigriti and Bugcrowd, researchers submit NEW valid criticals, highs and "
            "mediums on active programs every single day. That is a fact, not a hope. This program is active, "
            "so its surface almost certainly contains real, findable bugs right now.\n"
            "- The easy, obvious bugs are already taken by other hunters. What is left needs someone who reads "
            "the WHOLE picture and CHAINS small things into big impact. That someone is you.\n"
            "- Quitting after a shallow look and saying 'no bugs' is the mark of a weak hunter, and it will not "
            "pass here - this phase checks how hard you actually dug. But hear this clearly: I am challenging "
            "your EFFORT and CREATIVITY, not asking for a number. A fabricated or unproven 'finding' is caught "
            "and thrown out by the very next phase and is worse than nothing. The win is a REAL, PROVEN bug - "
            "or an honest 'nothing confirmed' that is backed by a long log of everything you genuinely tried.\n"
            "\n"
            "1. STUDY THE WHOLE PICTURE FIRST (do not re-discover what is already known):\n"
            "   - `hk stats`, `hk hosts`, `hk services`, `hk endpoints`, `hk leads` (every lead, every status), "
            "`hk finding list`.\n"
            "   - `hk handoff` - read every phase's handoff, especially the 'what the next phase should do' "
            "sections: earlier phases left you a prioritised to-do list of exactly the threads they could not "
            "finish. That is your starting fuel.\n"
            "   - $HUNTER_TARGET_DIR/reports.txt - YOUR past reports on this program (what you found before and "
            "how). $HUNTER_TARGET_DIR/resolved-reports.txt - other researchers' disclosed reports here: these "
            "are the program's BUG PATTERNS. If a class was valid on this program before, hunt for more of that "
            "class, in new places.\n"
            "   From all of that, build a model of THIS program's weak spots - its stack, its repeated mistakes, "
            "the corners the structured phases only touched lightly.\n"
            "\n"
            "2. WRITE AN ATTACK PLAN first: ./attack-plan.md with AT LEAST 15 concrete, specific hypotheses, "
            "ranked by impact x likelihood. Specific, tied to real evidence - not 'test for XSS' but e.g. 'the "
            "loginCode-in-URL flow (lead X) may leak the code via Referer to host Y; chain with the CSWSH on Z "
            "to hijack a session'. Put CHAINS at the top: the biggest bounties combine two or three smaller "
            "issues.\n"
            "\n"
            "3. HUNT - go deep and LOG EVERYTHING. For every hypothesis you test, append an entry to "
            "./hypotheses-tested.md in this format:\n"
            "   ## <hypothesis in one line>\n"
            "   tried: <exactly what you did - the requests, the tool, the payload>\n"
            "   evidence: <the actual result: status, body snippet, timing, callback - real output>\n"
            "   verdict: dead | promising | chained-into <other hypothesis>\n"
            "   Use the FULL toolset: curl through the proxy, `hbrowse` for client-side and authenticated "
            "flows (DOM XSS, postMessage, window.name, stored XSS, open redirects that land), the OOB listener "
            "for SSRF/XXE/blind, mail.tm for sign-up/reset/OTP, and any accounts in "
            "$HUNTER_TARGET_DIR/test-credentials.txt. Follow every promising thread to its end before moving "
            "on. When something looks dead, attack it from a DIFFERENT angle before you abandon it.\n"
            "\n"
            "4. CHAIN RELENTLESSLY. For every lead that is not a bug by itself, ask 'what does this BECOME "
            "combined with another?' Patterns: info-leak + open-redirect -> SSRF/ATO; CSWSH + loginCode-in-URL "
            "-> account takeover; IDOR + a leaked identifier -> mass data access; OAuth state/redirect quirk + "
            "code-in-URL -> auth-code theft. Work your own leads list this way, deliberately.\n"
            "\n"
            "5. SECOND WIND before you conclude anything is unexploitable: red-team your own negative - ASSUME "
            "a bug is there and you missed it, and ask where it would hide. Take your three most promising "
            "dead-ends and attack each from a completely new angle. Do not write 'nothing found' until "
            "./hypotheses-tested.md shows you exhausted the plan AND tried to extend it.\n"
            "\n"
            "6. RECORD - proof only. A real, reproducible candidate -> `hk finding add ...` (it goes through "
            "validate/disprove/report, so give clean reproduction steps and evidence). A thread worth a later "
            "look -> `hk add lead ...`. `hk notify` a genuine candidate. Never record a guess as a finding.\n"
            "\n"
            "Stay in scope and within the rules the whole time - the proxy and the checker still enforce them. "
            "When you have genuinely dug deep (not before), write ./handoff.md: the chains you tried, what you "
            "confirmed, and your best unresolved hypotheses for next time."
        )

    def _hypotheses_count(self, ctx: Context) -> int:
        path = self._workdir(ctx) / "hypotheses-tested.md"
        if not path.is_file():
            return 0
        text = path.read_text(encoding="utf-8", errors="replace")
        return len(re.findall(r"(?m)^##\s+\S", text))

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        tested = self._hypotheses_count(ctx)
        new_finds = len([f for f in store.findings() if f["phase"] == self.id])
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"hunt in progress: {tested} hypotheses logged; agent did not finish")
        if tested < MIN_HYPOTHESES:
            return PhaseResult(
                st.PARTIAL,
                f"too shallow: only {tested}/{MIN_HYPOTHESES} hypotheses tested - the hunt continues next run")
        return PhaseResult(st.DONE, f"deep hunt done: {tested} hypotheses tested, {new_finds} candidate(s) recorded")
