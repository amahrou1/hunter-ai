"""Phase 07, AI: accounts.

Prepares the test accounts the access-control and logic phases need. Uses the
accounts the researcher supplied (test-credentials.txt) if present; otherwise,
and only if the program allows self-registration, creates the minimum set:
ideally two accounts in the same tenant (an owner/admin and a low-privilege
member) so permission boundaries can be tested. Never touches real users."""

from __future__ import annotations

from ..agent_phase import AgentPhase, MustStep
from .base import Context


class AIAccountsPhase(AgentPhase):
    id = "07-accounts"
    name = "Accounts: supplied and self-registered"
    version = "2.0"
    build_step = 6
    requires = ("00-intake", "03-probe")
    role = "accounts"
    max_turns = 70
    timeout_minutes = 90

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Read ./test-credentials.txt; if usable accounts exist, record them with `hk note` "
                     "and skip creation."),
            MustStep("M2", "`hk scope` - check self-registration is allowed; if forbidden or host is "
                     "unauthenticated-only, record a blocker-note and stop."),
            MustStep("M3", "If allowed, create the minimum set for authz testing - ideally two accounts in "
                     "the same org/tenant (one higher, one lower privilege) using the required email domain."),
            MustStep("M4", "Save every account created/confirmed to ./test-credentials.txt "
                     "(label|email|password|notes); never store anyone else's credentials.", ),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Prepare the test accounts later phases need, within the program rules.\n"
            "1. Read ./test-credentials.txt in the target folder. If it has usable accounts, record what is "
            "available with `hk note` and you are done with creation.\n"
            "2. `hk scope` - check self-registration. If the program forbids it, or a host is marked "
            "unauthenticated-only, do NOT create accounts there; record that as a blocker-note and stop.\n"
            "3. If self-registration is allowed, create the minimum set for authorization testing: where "
            "possible two accounts in the SAME organisation/tenant - one higher privilege (owner/admin) and "
            "one lower (member) - so cross-role access can be tested later. Use the researcher's platform "
            "email domain for addresses if the program requires it (see scope). A mailbox API such as "
            "mail.tm is allowed for confirmation emails (it is not a target).\n"
            "4. Save every account you create or confirm to ./test-credentials.txt in the target folder, "
            "one per line: label | email | password | notes (role, tenant). Never store anyone else's "
            "credentials; only accounts you created.\n"
            "Summarise which accounts exist and their roles in ./handoff.md. Do not test anything here."
        )
