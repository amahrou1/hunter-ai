"""Phase 00: intake.

1. Hashed snapshot of every input file.
2. An AI agent reads policy.txt and writes a structured draft.
3. Code validates the draft (up to two repair rounds), cross-checks every
   in-scope entry against the policy text, applies scope-overrides.txt and
   writes scope.json plus a human-readable scope_review.md.
4. The scope proxy is started once and must prove that it blocks
   out-of-scope traffic before any later phase may touch a target.
"""

from __future__ import annotations

import hashlib
import json
import shutil

from .. import policy
from .. import scope as sc
from .. import state as st
from ..proxy import ProxyError, ScopeProxy
from ..target import INPUT_FILES
from .base import Context, Phase, PhaseResult

WATCH = ["policy.txt", "scope-overrides.txt"]


class IntakePhase(Phase):
    id = "00-intake"
    name = "Intake: inputs, policy and scope guard"
    # 1.3: leading-dot URLs, any-TLD exclusions (support.x.*), infix label
    # wildcards (*dev*.x.com). Bumped so existing targets re-read their policy.
    version = "1.3"
    build_step = 3

    def outputs_present(self, ctx: Context) -> bool:
        return ctx.target.scope_file.exists()

    def run(self, ctx: Context) -> PhaseResult:
        self._snapshot(ctx)
        policy_text = ctx.target.input_text("policy.txt")
        overrides_text = ctx.target.input_text("scope-overrides.txt")

        work = ctx.phase_dir() / "work"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)
        (work / "policy.txt").write_text(policy_text + "\n", encoding="utf-8")

        draft, problems = self._read_policy(ctx, work)
        if draft is None:
            detail = "\n".join(f"- {p}" for p in problems[:8])
            ctx.notify("Policy could not be read", f"The AI could not produce a valid scope from policy.txt.\n{detail}\n"
                       "The run will try again on the next start. Nothing was tested.", "error")
            return PhaseResult(st.FAILED, "policy could not be read: " + "; ".join(problems[:3]))
        shutil.copy2(work / policy.DRAFT_FILE, ctx.target.output / "scope_draft.json")

        build = policy.build_scope(draft, policy_text, overrides_text, ctx.settings)
        scope = build.scope
        self._carry_over(ctx, scope, overrides_text)
        sc.save(scope, ctx.target.scope_file)
        ctx.target.scope_review.write_text(policy.render_review(scope, build, ctx.target.name), encoding="utf-8")
        ctx.log(f"scope: {len(scope.in_scope)} in, {len(scope.out_of_scope)} out, "
                f"{len(scope.ambiguities)} unclear, {scope.rate_limit_rps}/s")
        self._announce(ctx, scope, build)

        ownership = scope.rules.get("ownership_scope")
        confirmed = sc.parse_overrides(overrides_text)[0]
        if ownership and not confirmed and scope.network_assets():
            # There ARE assets to test, so "confirm more owned assets" is an
            # optional expansion, not something to idle-wait on. Record it as an
            # informational gap (no watched file) so an unattended run proceeds
            # immediately instead of waiting out the blocker timeout. If the
            # operator later adds lines to scope-overrides.txt, that change
            # restarts the run on its own.
            owner = ownership["owner"]
            ctx.block(f"Assets you confirm belong to {owner}",
                      f"This program's scope is \"assets owned by {owner}\", without a full list. The run tests "
                      f"what policy.txt names ({len(scope.network_assets())} asset(s)) plus its wildcards and "
                      f"proceeds now. To widen it, add domains/wildcards/IP ranges you have confirmed belong to "
                      f"{owner} to scope-overrides.txt (e.g. 'in *.{owner.lower().split()[0]}.com'); saving that "
                      f"file restarts the run under the new scope.", [])
        elif ownership and not confirmed:
            owner = ownership["owner"]
            ctx.block(f"Assets you confirm belong to {owner}",
                      f"This program's scope is \"assets owned by {owner}\", without a full list, and nothing "
                      f"testable was confirmed yet. Add domains/wildcards/IP ranges you have checked belong to "
                      f"{owner} to scope-overrides.txt, one per line, e.g.:\n"
                      f"in *.{owner.lower().split()[0]}.com\nin 203.0.113.0/24", WATCH)
        if not scope.network_assets():
            if not ownership:
                ctx.block("A clear scope",
                          "No web asset could be confirmed from policy.txt. Check the pasted policy, or add lines "
                          "such as 'in *.example.com' to scope-overrides.txt.", WATCH)
            return PhaseResult(st.BLOCKED, "no testable asset in scope yet")
        if scope.rules.get("unresolved_headers"):
            ctx.block("Value for a required header",
                      "The policy requires: " + "; ".join(scope.rules["unresolved_headers"])
                      + ". Run 'hunt handle <your-username>' once, or add a line like "
                      "'header X-Bug-Bounty: yourname' to scope-overrides.txt.", WATCH)
            return PhaseResult(st.BLOCKED, "required header value missing")

        ok, message = self._check_guard(ctx)
        if not ok:
            ctx.notify("Scope guard failed its self-test", message + "\nNo target traffic is allowed until this works.",
                       "error")
            return PhaseResult(st.FAILED, f"scope guard self-test failed: {message}")

        summary = (f"{len(scope.in_scope)} in scope, {len(scope.out_of_scope)} out, "
                   f"{len(scope.ambiguities)} unclear; {scope.rate_limit_rps}/s; guard verified")
        return PhaseResult(st.DONE, summary)

    # -------------------------------------------------------------- helpers
    def _carry_over(self, ctx: Context, scope: sc.Scope, overrides_text: str) -> None:
        """Keep what a fresh policy read must not wipe when intake re-runs (a code
        update or a policy edit): a rate the operator set with `hunt rate`,
        unless scope-overrides.txt now sets one."""
        if not ctx.target.scope_file.exists():
            return
        try:
            prev = sc.load(ctx.target.scope_file)
        except (OSError, ValueError, KeyError):
            return
        source = str(prev.rules.get("rate_source") or "")
        if source.startswith("operator set") and sc.parse_override_rate(overrides_text) is None:
            scope.rules["effective_rps"] = prev.rules.get("effective_rps")
            scope.rules["rate_source"] = source

    def _snapshot(self, ctx: Context) -> None:
        snapshot = ctx.target.output / "inputs"
        snapshot.mkdir(parents=True, exist_ok=True)
        manifest = {}
        for filename, (required, description) in INPUT_FILES.items():
            text = ctx.target.input_text(filename)
            entry = {"present": bool(text), "required": required, "description": description}
            if text:
                entry["sha256"] = hashlib.sha256(text.encode()).hexdigest()
                entry["lines"] = text.count("\n") + 1
                shutil.copy2(ctx.target.input_path(filename), snapshot / filename)
            manifest[filename] = entry
        ctx.write_json("inputs/manifest.json", manifest)
        present = [name for name, entry in manifest.items() if entry["present"]]
        ctx.log("inputs: " + ", ".join(present))

    def _read_policy(self, ctx: Context, work) -> tuple[dict | None, list[str]]:
        draft_path = work / policy.DRAFT_FILE
        problems: list[str] = []
        for attempt in range(1, 4):
            if attempt == 1 or not draft_path.exists():
                prompt = policy.PROMPT.format(draft_file=policy.DRAFT_FILE)
            else:
                prompt = policy.REPAIR_PROMPT.format(
                    draft_file=policy.DRAFT_FILE, problems="\n".join(f"- {p}" for p in problems))
            ctx.log(f"reading the policy (attempt {attempt})")
            result = ctx.agent("planner", prompt, name=f"policy-reader-{attempt}", workdir=work,
                               max_turns=30, timeout_minutes=25)
            if not draft_path.exists():
                problems = [f"the file {policy.DRAFT_FILE} was not written"
                            + (f" ({result.error})" if result.error else "")]
                continue
            try:
                data = json.loads(draft_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                problems = [f"the file is not valid JSON ({exc})"]
                continue
            problems = policy.validate_draft(data)
            if not problems:
                return data, []
            ctx.log(f"draft has {len(problems)} problem(s): {problems[0]}")
        return None, problems

    def _announce(self, ctx: Context, scope: sc.Scope, build: policy.BuildResult) -> None:
        def short(items, limit=15):
            items = list(items)
            text = "\n".join(f"- {x}" for x in items[:limit])
            return text + (f"\n- ... and {len(items) - limit} more" if len(items) > limit else "")

        rules = scope.rules
        parts = [
            f"Program: {scope.program.get('name') or '(not named)'} ({scope.program.get('platform')})",
            f"In scope ({len(scope.in_scope)}):\n{short(a.raw for a in scope.in_scope) or '- none'}",
            f"Out of scope: {len(scope.out_of_scope)} entries",
            f"Rate: {scope.rate_limit_rps} requests/second",
        ]
        if rules.get("required_headers"):
            parts.append("Headers: " + ", ".join(f"{k}: {v}" for k, v in rules["required_headers"].items()))
        if rules.get("ownership_scope"):
            parts.append(f"Scope by ownership: assets owned by {rules['ownership_scope']['owner']}. Only listed "
                         "and confirmed assets are tested (see the Blocked message).")
        if rules.get("low_automation"):
            parts.append(f"Automated scanning is '{rules['automated_scanning']}' in this program: "
                         "the run will keep automation to a minimum.")
        if scope.ambiguities:
            parts.append(f"Unclear assets, NOT tested ({len(scope.ambiguities)}):\n"
                         + short(f"{a['item']}: {a['why']}" for a in scope.ambiguities))
        if scope.questions:
            parts.append(f"Notes about the rules ({len(scope.questions)}), nothing held back:\n"
                         + short((a["item"] for a in scope.questions), limit=6))
        if scope.unclassified_hosts:
            parts.append(f"Mentioned but not classified, NOT tested: {', '.join(scope.unclassified_hosts[:10])}")
        parts.append(f"Full review: {ctx.target.scope_review}\n"
                     f"Correct anything with scope-overrides.txt in {ctx.target.path}")
        level = "warn" if scope.ambiguities or scope.unclassified_hosts or build.problems else "success"
        ctx.notify("Scope ready", "\n\n".join(parts), level)

    def _check_guard(self, ctx: Context) -> tuple[bool, str]:
        proxy = ScopeProxy(ctx.target.scope_file, ctx.target.logs / "proxy-selftest", ctx.settings)
        try:
            proxy.start()
            ok, message = proxy.self_test()
        except ProxyError as exc:
            return False, str(exc)
        finally:
            proxy.stop()
        ctx.log(f"scope guard: {message}")
        return ok, message
