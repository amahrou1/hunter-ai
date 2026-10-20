"""Phase 06b, AI: dependency confusion (internal package discovery).

Finds the target's private/internal package names from its own JavaScript
(harvested in phase 06) and, if a GitHub token is set, from its org's repo
manifests, then cross-references each name against the matching PUBLIC registry
(npm / PyPI / RubyGems). A name the target depends on that is UNCLAIMED
publicly - or whose public scope is unclaimed - is a dependency-confusion
candidate: if a build resolves the public registry, an attacker-published
package of the same name (higher version) runs on the build/dev host (RCE).

This phase does the safe, automatable half: discover, cross-reference, validate
that the name is unclaimed, record, notify. It NEVER publishes a package - that
is the exploit step, it has a real side effect on the public registry and the
target's builds, and the command checker blocks it. The operator does the
publish + callback PoC by hand (the playbook spells out the exact steps), and
the finding carries those steps for the report.

Registries and GitHub are passive sources (not targets); the target's own hosts
still go through the scope proxy.
"""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


class DepConfusionPhase(AgentPhase):
    id = "06b-depconf"
    name = "Dependency confusion: internal package discovery"
    version = "1.1"
    build_step = 6
    # Depends on 04-map (JS/endpoints harvested there), not 06-js: it still runs
    # after 06-js in the pipeline and uses its output when present, but a flaky
    # 06-js left PARTIAL must not block it.
    requires = ("00-intake", "04-map")
    role = "intel"
    max_turns = 120
    timeout_minutes = 120
    # Optional: GitHub scanning is a bonus. JS-based discovery works without it.
    secret_env = {"GITHUB_TOKEN": "GITHUB_TOKEN", "GH_TOKEN": "GITHUB_TOKEN"}

    def task(self, ctx: Context) -> str:
        has_gh = bool(ctx.secrets.get("GITHUB_TOKEN") or ctx.secrets.get("GH_TOKEN"))
        gh = ("Your GitHub token is in $GITHUB_TOKEN - also scan the target's org repos (found in phase 01b; "
              "see `hk handoff` / `hk leads` / notes) for manifests."
              if has_gh else
              "No GitHub token is set, so work from the target's own JavaScript only (do not skip - the JS "
              "bundles are the richer source anyway).")
        return (
            "Hunt for DEPENDENCY CONFUSION: internal package names the target depends on that are unclaimed on "
            "the public registry. First read the playbook: `cat $(hk depconf)`.\n"
            f"{gh}\n"
            "1. Collect candidate package names from (a) the target's own JavaScript already harvested in "
            "phase 06 (reuse it - see `hk handoff` for 06-js and its work dir; fetch a missing bundle with "
            "curl, it goes through the proxy) and (b) the org's repo manifests if you have a token "
            "(package.json/.npmrc, requirements.txt/setup.py/pyproject.toml, Gemfile). Extract module "
            "specifiers properly (require/import/dynamic import, inlined package.json, webpack maps) - use a "
            "real parser where you can, not one fragile regex. Drop relative paths, URLs, single letters and "
            "webpack internals.\n"
            "2. Classify each name's ecosystem (npm / pip / gem) and normalise it.\n"
            "3. Cross-reference the PUBLIC registry with a read-only GET per name (npmjs / pypi / rubygems; "
            "the playbook has the exact URLs). Only a CONFIRMED 404 counts as unclaimed: retry once, and treat "
            "a 429/5xx/000/timeout as UNKNOWN (a weak lead), never as unclaimed - a failed lookup is not a free "
            "name. 200 = already public = usually NOT a candidate. For a scoped npm name, the scope is only "
            "unclaimed when BOTH the org endpoint AND the user endpoint 404; if either resolves it is owned "
            "(often a defensive empty registration) - not a candidate. A name published only as a "
            "'0.0.1-security' placeholder is already held (someone locked and likely already reported it) - "
            "treat it as taken, not a candidate.\n"
            "4. Keep only high-confidence candidates, and judge PROVENANCE the same way the dork phase does: "
            "the specifier must come from the TARGET's OWN first-party code (its bundle/app code or a manifest "
            "in its own org) - NOT from an embedded seller/partner/integrator widget, an iframe's bundle, or a "
            "customer blob that merely sits on a target page. First-party -> finding-track. Third-party, or "
            "use you cannot establish as first-party -> LEAD, out of scope (default to this when unsure; never "
            "guess a seller's widget into a finding). Also drop typos of famous packages and "
            "placeholders/examples/local names.\n"
            "5. Record, and set SEVERITY BY CONFIDENCE. This phase proves only the precondition (referenced + "
            "unclaimed), NOT that a build resolves public npm - that needs the operator callback PoC. So file "
            "first-party confirmed-unclaimed candidates at --severity MEDIUM, status candidate, and say so: "
            "`hk finding add --kind dependency-confusion --severity medium --url <first-party github/JS URL> "
            "--summary \"internal <eco> package '<name>' used by <first-party where> is unclaimed on <registry> "
            "(scope org+user 404). UNCONFIRMED - reachability not proven\" --steps \"<source + evidence + the "
            "confirmed 404s> + the operator publish+callback PoC from the playbook (callback at your OOB host)\" "
            "--impact \"IF a build resolves public <registry>, attacker <name>@<higher> runs on a build/dev "
            "host (RCE); not yet confirmed reachable\"`. Weaker/third-party/unknown-registry ones: `hk add lead "
            "dependency-confusion <url> --evidence \"<name>, registry=<code>, provenance=<first|third>-party\"`. "
            "Then `hk notify` each candidate so the operator sees it.\n"
            "DO NOT publish anything: `npm publish` / `twine upload` / `gem push` are blocked for the run. "
            "Publishing the placeholder and the callback payload is the operator's manual step; your job is to "
            "prove the name is unclaimed and hand over a ready PoC. Summarise the candidates (name, ecosystem, "
            "source, registry result) in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        finds = [f for f in store.findings() if f["kind"] == "dependency-confusion"]
        leads = [l for l in store.leads() if l["kind"] == "dependency-confusion"]
        note = f"{len(finds)} dependency-confusion candidate(s), {len(leads)} lead(s)"
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, note + "; agent did not finish")
        return PhaseResult(st.DONE, note)
