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
    version = "1.0"
    build_step = 6
    requires = ("00-intake", "06-js")
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
            "3. Cross-reference the PUBLIC registry with ONE read-only GET per name (npmjs / pypi / rubygems; "
            "the playbook has the exact URLs). 404 = unclaimed = candidate; 200 = already public = usually "
            "NOT a candidate. For scoped npm names, check whether the whole @scope is unclaimed (strongest "
            "case).\n"
            "4. Keep only high-confidence candidates: a name the TARGET actually uses (its repo or its own "
            "bundle, not a third-party vendor blob), unclaimed publicly, and not a typo of a famous package. "
            "Discard placeholders/examples/local names.\n"
            "5. Record. High confidence: `hk finding add --kind dependency-confusion --severity high --url "
            "<github file or JS bundle URL> --summary \"internal <eco> package '<name>' used by <where> is "
            "unclaimed on <registry>\" --steps \"<source + evidence + the registry 404> + the operator's "
            "two-stage publish+callback PoC from the playbook (pointing the callback at your OOB host)\" "
            "--impact \"RCE on a build/dev host if the build resolves the public registry\"`. Weaker ones: "
            "`hk add lead dependency-confusion <url> --evidence \"...\"`. Then `hk notify` each candidate so "
            "the operator sees it.\n"
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
