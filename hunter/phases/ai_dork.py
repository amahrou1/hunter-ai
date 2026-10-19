"""Phase 01b, AI: OSINT / GitHub dorking and secret validation.

Finds the target's GitHub org and repos, searches them (and the domain) for
leaked credentials and API keys with a dork set, filters out the junk
(localhost / example / test), and VALIDATES the real ones with a single minimal
read-only call to the vendor before recording them as findings. Standalone, so
Google/Bing/other dorking can be added here later.

Network: GitHub and the vendor validation hosts are reachable (they are not the
bug-bounty target). The target's own hosts still go through the scope proxy.
"""

from __future__ import annotations

from pathlib import Path

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


def _validate_hosts(settings: dict) -> tuple[str, ...]:
    osint = settings.get("osint", {}) or {}
    return tuple(osint.get("validate_hosts", [])) if osint.get("enabled", True) else ()


class GithubDorkPhase(AgentPhase):
    id = "01b-dork-github"
    name = "OSINT: GitHub dorking and secret validation"
    version = "1.0"
    build_step = 5
    requires = ("00-intake",)
    role = "intel"
    max_turns = 120
    timeout_minutes = 120
    secret_env = {"GITHUB_TOKEN": "GITHUB_TOKEN", "GH_TOKEN": "GITHUB_TOKEN"}

    def run(self, ctx: Context) -> PhaseResult:
        if not ctx.settings.get("osint", {}).get("enabled", True):
            return PhaseResult(st.NOT_APPLICABLE, "OSINT/dorking disabled in settings")
        if not (ctx.secrets.get("GITHUB_TOKEN") or ctx.secrets.get("GH_TOKEN")):
            ctx.block("A GitHub token for code search",
                      "GitHub dorking needs a read-only GitHub token. Add one with: hunt setup "
                      "(GITHUB_TOKEN). The run continues with other work.", [])
            return PhaseResult(st.BLOCKED, "no GitHub token saved")
        # Allow the vendor validation hosts through the command checker for this phase.
        self.allow_hosts = _validate_hosts(ctx.settings) + ("api.github.com", "raw.githubusercontent.com",
                                                            "github.com", "codeload.github.com")
        return super().run(ctx)

    def task(self, ctx: Context) -> str:
        hosts = ", ".join(_validate_hosts(ctx.settings)) or "(none configured)"
        return (
            "Hunt for leaked secrets tied to this target on GitHub, and validate the real ones. First read "
            "the dork playbook: `cat $(hk dorks)`. Your GitHub token is in $GITHUB_TOKEN.\n"
            "1. Identify the target: the in-scope domain(s) from `hk scope`, and find the GitHub org via the "
            "users/orgs search API. Use both org: and the bare domain in queries.\n"
            "2. Run the dork queries from the playbook against the GitHub code-search API (authenticated, "
            "paced for its rate limit). For each hit, fetch the file's raw content and read the secret in "
            "context.\n"
            "3. Filter the junk: discard hits that are localhost/example/test/sample/demo/placeholder, "
            "example or tutorial repos, documented sample keys, admin/admin in a fixtures file, etc. Keep "
            "only real-looking secrets tied to the target (its org, domain, or infra).\n"
            "4. VALIDATE each real secret with ONE minimal read-only call to its vendor - only to prove it is "
            f"live, never to read or change data. You may reach these vendor hosts for validation: {hosts}. "
            "If a secret's vendor is NOT in that list, record it as a finding marked UNVALIDATED (do not hit "
            "an arbitrary host). The target's own API keys are validated through the scope proxy as usual.\n"
            "5. Record every live secret: `hk finding add --kind leaked-secret --severity <by impact> "
            "--url <github file url> --summary \"...\" --steps \"where found + the validation call and its "
            "result\" --impact \"...\"`. NEVER write the secret value anywhere - mask it (last 4 chars only). "
            "Also record unvalidated-but-promising ones as leads. If a dork reveals new subdomains of the "
            "target, add them with `hk add host`.\n"
            "Respect the program rules: if the policy forbids testing found credentials, record them as "
            "findings WITHOUT validating. Summarise what you found and validated in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        secrets = [f for f in store.findings() if f["kind"] == "leaked-secret"]
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{len(secrets)} leaked-secret finding(s); agent did not finish")
        return PhaseResult(st.DONE, f"{len(secrets)} leaked-secret finding(s)")
