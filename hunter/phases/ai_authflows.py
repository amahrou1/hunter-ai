"""Phase 07b, AI: account & auth-flow logic.

Tests the logic of sign-up, password reset, 2FA/MFA and OAuth linking - the
account-takeover class that scanners never find and that pays well. This is
AUTH-FLOW logic, deliberately NOT object-level authorization / IDOR (handled by
a separate effort). Everything is done with the run's own accounts and temp
mailboxes, non-destructive and in scope.

Needs the test accounts from 07-accounts and the mailbox/OOB infra the system
already wires.
"""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AuthFlowsPhase(AgentPhase):
    id = "07b-authflows"
    name = "Account & auth-flow logic: registration, reset, 2FA, OAuth"
    version = "1.0"
    build_step = 7
    requires = ("00-intake", "07-accounts")
    role = "authz"            # account-logic reasoning -> strong tier
    max_turns = 120
    timeout_minutes = 120

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Map the auth surface (registration, login, reset, email-change, 2FA, invite, "
                     "OAuth) from `hk endpoints`/`hk handoff` (esp. 06c-jsintel).", "auth-surface.md"),
            MustStep("M2", "Registration abuse: email-parser tricks (case/+tag/whitespace/%00/second-email), "
                     "register-over-unverified ATO, UUID->numeric on a register endpoint."),
            MustStep("M3", "Password-reset abuse: multi-recipient injection, token leakage, host-header "
                     "poisoning of the reset link."),
            MustStep("M4", "2FA/MFA logic: method-swap on the OTP send, reset-skips-2FA, expired/empty code, "
                     "sequential recovery codes, MFA-missing on an endpoint."),
            MustStep("M5", "OAuth/social-login linking confusion (record as a lead where it needs a manual "
                     "provider step)."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Test ACCOUNT and AUTH-FLOW logic - the account-takeover class. First read the playbook: "
            "`cat $(hk authflows)`. This is sign-up / reset / 2FA / OAuth logic, NOT IDOR or object-level "
            "authorization (that is a separate effort - do not do it here).\n"
            "Use ONLY the accounts in ./test-credentials.txt and temp mailboxes (mail.tm), or the program "
            "relay address. Everything non-destructive, in scope, under the rate limit. If the program "
            "excludes a class (e.g. account/email enumeration), skip it and `hk note` why.\n"
            "Work every run-contract step the target supports: registration email-parser and "
            "register-over-unverified ATO; password-reset multi-recipient injection, token leakage and "
            "host-header poisoning (a reset link landing on your OOB host is the proof); 2FA method-swap / "
            "reset-skips-2FA / expired-or-empty code / sequential recovery codes / MFA-missing endpoints; and "
            "OAuth account-linking confusion. A client-side response-manipulation signal (false->true, "
            "403->200) must be confirmed server-side or recorded as a lead marked 'needs server-side "
            "confirmation'.\n"
            "Record each real issue with `hk finding add --kind auth-logic ...` (exact requests incl. the "
            "control, concrete ATO impact), status candidate; weaker/manual ones as `hk add lead auth-logic`. "
            "Mask any token. Summarise what you tested and confirmed in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        finds = len([f for f in store.findings() if f["kind"] == "auth-logic"])
        leads = len([l for l in store.leads() if l["kind"] == "auth-logic"])
        note = f"{finds} auth-logic candidate(s), {leads} lead(s)"
        missing = self.missing_artifacts(ctx)
        if not self.outputs_present(ctx) or missing:
            detail = f"; missing {', '.join(missing)}" if missing else "; agent did not finish"
            return PhaseResult(st.PARTIAL, note + detail)
        return PhaseResult(st.DONE, note)
