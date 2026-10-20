"""Phase 01b, AI: OSINT / GitHub dorking and secret validation.

Finds the target's GitHub org and repos, searches them (and the domain) for
leaked credentials and API keys with a dork set, filters out the junk
(localhost / example / test), then classifies each real secret by WHO leaked it
- because that, not whether the key is live, decides if it is reportable:

  - leaked from the company's own org repos          -> finding (their mistake)
  - leaked by a company employee, and it is an        -> finding
    internal/privileged company asset
  - leaked by a customer / seller / integrator, or    -> lead, out of scope
    by an employee but it is only their own tenant key

Only finding-track secrets are validated, with a single minimal read-only call
to the vendor; third-party credentials are recorded masked and never touched.
Standalone, so Google/Bing/other dorking can be added here later.

Network: GitHub and the vendor validation hosts are reachable (they are not the
bug-bounty target). The target's own hosts still go through the scope proxy.
"""

from __future__ import annotations

from pathlib import Path

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


def _validate_hosts(settings: dict) -> tuple[str, ...]:
    osint = settings.get("osint", {}) or {}
    return tuple(osint.get("validate_hosts", [])) if osint.get("enabled", True) else ()


class GithubDorkPhase(AgentPhase):
    id = "01b-dork-github"
    name = "OSINT: GitHub dorking and secret validation"
    version = "1.1"
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

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Search the target's GitHub for leaked secrets with the curated dork/regex set; "
                     "collect candidate secrets."),
            MustStep("M2", "Filter false positives (examples/placeholders/revoked) and keep only plausible "
                     "live secrets."),
            MustStep("M3", "Classify each by REPO OWNER provenance (company-org / company-person / "
                     "third-party) - this decides reportability, not whether the key is live."),
            MustStep("M4", "Judge the secret's nature (internal/privileged vs tenant/customer)."),
            MustStep("M5", "Validate ONLY finding-track secrets with one read-only call; never validate a "
                     "third-party/customer credential."),
            MustStep("M6", "Record masked (last 4 only): reportable -> `hk finding add` with provenance; "
                     "third-party -> `hk add lead`. Group by provenance in ./handoff.md."),
        ]

    def task(self, ctx: Context) -> str:
        hosts = ", ".join(_validate_hosts(ctx.settings)) or "(none configured)"
        return (
            "Hunt for leaked secrets tied to this target on GitHub, classify each by WHO leaked it, and "
            "validate only the reportable ones. First read the dork playbook: `cat $(hk dorks)`. Your "
            "GitHub token is in $GITHUB_TOKEN.\n"
            "1. Identify the target: the in-scope domain(s) from `hk scope`, and find the official GitHub "
            "org(s) via the users/orgs search API. Note the org login(s) - you need them to tell a company "
            "repo from a stranger's. Use both org: and the bare domain in queries.\n"
            "2. Run the dork queries from the playbook against the GitHub code-search API (authenticated, "
            "paced for its rate limit). For each hit, fetch the raw file and read the secret in context.\n"
            "3. Filter the junk: discard localhost/example/test/sample/demo/placeholder values, example or "
            "tutorial repos, documented sample keys, fixtures. Keep only real-looking secrets tied to the "
            "target.\n"
            "4. CLASSIFY each surviving secret by the OWNER of the repo it leaked from - this, not whether "
            "the key is live, decides if it is reportable. Establish the owner with bounded, read-only "
            "OSINT (the repo owner's GitHub profile company/bio/email, whether they are a public member of "
            "the target's org, commit-author domains):\n"
            "   - company-org: the repo sits under the target's official GitHub org(s). The company exposed "
            "its own secret -> reportable.\n"
            "   - company-person: an individual you can SHOW is an employee/affiliate of the target (profile "
            "employer = target, a @<target-domain> commit email, listed org member). Reportable ONLY when "
            "the secret is an INTERNAL company asset (step 5), not the person's own customer key.\n"
            "   - third-party: a customer / seller / affiliate / integrator, OR any account whose link to "
            "the company you cannot establish. Out of scope. Default here whenever affiliation is unproven "
            "- never guess someone into company-person.\n"
            "5. Also judge the secret's NATURE: internal/privileged (internal, admin, infra, CI/CD, service "
            "account, database, cloud, signing keys, or anything granting cross-tenant / company-wide "
            "access) vs tenant/customer (one third party's own credential for using the target's public or "
            "partner API as themselves - e.g. a retailer/affiliate OAuth client_id+secret, scoped to that "
            "one account).\n"
            "6. DECIDE:\n"
            "   - company-org + any live secret        -> FINDING.\n"
            "   - company-person + internal/privileged  -> FINDING.\n"
            "   - company-person + tenant/customer      -> LEAD (they leaked their own customer key; same "
            "as a customer leak, out of scope).\n"
            "   - third-party (any secret)              -> LEAD. Out of scope: record it masked, do NOT "
            "validate it, do NOT use it. A courtesy heads-up to the company to revoke it may be noted, but "
            "it is not a program finding.\n"
            "7. VALIDATE only finding-track secrets (company-org, or company-person internal) with ONE "
            f"minimal read-only call to the vendor - only to prove it is live, never to read or change "
            f"data. Reachable vendor hosts for validation: {hosts}. If a finding-track secret's vendor is "
            "NOT listed, record the finding marked UNVALIDATED (do not hit an arbitrary host). The target's "
            "own keys validate through the scope proxy as usual. Never validate a third-party/customer "
            "credential - that is touching someone else's account.\n"
            "8. RECORD, masking every secret to its last 4 chars - never write the full value anywhere. "
            "Reportable: `hk finding add --kind leaked-secret --severity <by impact> --url <github file "
            "url> --summary \"what + provenance (company-org | company-person-internal)\" --steps \"where "
            "found + the validation call and its result\" --impact \"...\"`. Out-of-scope: `hk add lead "
            "leaked-secret-thirdparty <github file url> --evidence \"masked secret, scope=<>, owner="
            "<seller/customer>, provenance=third-party; out of scope\"`. If a dork reveals new target "
            "subdomains, add them with `hk add host`.\n"
            "Respect the program rules: if the policy forbids testing found credentials, record "
            "finding-track secrets WITHOUT validating. Summarise in ./handoff.md, grouped by provenance "
            "(reportable findings vs third-party leads), so the report phase only drafts the reportable ones."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        secrets = [f for f in store.findings() if (f["kind"] or "").startswith("leaked-secret")]
        leads = [l for l in store.leads() if (l["kind"] or "").startswith("leaked-secret")]
        note = (f"{len(secrets)} reportable secret finding(s), "
                f"{len(leads)} third-party/out-of-scope lead(s)")
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, note + "; agent did not finish")
        return PhaseResult(st.DONE, note)
