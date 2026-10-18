"""Run a phase as an AI agent (the core of the rebuilt system).

Each testing phase is an AI session that decides what to do and does it, with
the toolkit (`hk`) and the recon tools on its PATH. Three things keep it safe,
and none of them depend on the AI behaving:

1. The scope proxy. Every request to a target goes through it; out-of-scope
   traffic is blocked at the network layer. Passive data sources and the model
   API bypass it (they are not targets).
2. The command checker (hunter/guard_hook.py), wired as a PreToolUse hook: it
   reads each command before it runs and blocks out-of-scope hosts, anything
   that would switch the proxy off, port scanners, brute forcing, and the run's
   own controls. Exit 2 stops the command and tells the agent why.
3. The orchestrator. It still owns phase order, scope, rate, state, resume and
   completion; the AI only works inside one phase.

The agent records everything through `hk` (scope-checked writes to the shared
inventory) and writes a short handoff for the next phase. After it exits, the
phase verifies the expected outputs exist; if not, it returns PARTIAL/BLOCKED
with what is missing, so a later start sends the agent back in.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import paths
from .toolchain import tools_dir
from . import state as st
from .phases.base import Context, Phase, PhaseResult

# Prepended to the phase prompt: the rules and the toolkit, same for every phase.
PREAMBLE = """You are one phase of an automated, AUTHORISED bug bounty run against a single
program the researcher is allowed to test. You are an experienced bug bounty
hunter. Work on your own: choose what to run, read the results, notice problems
and fix your approach, follow what looks interesting, and stop when this phase
is done. No human is watching, so never wait for input.

Scope and rules (this is what the program authorises):
{scope_summary}

Hard limits, enforced in code (not just asked of you):
- Every request to a target goes through a scope proxy. Out-of-scope hosts are
  blocked; do not try to disable, unset or change the proxy (*_PROXY variables,
  --noproxy, proxychains): those commands are refused.
- A checker reads each command before it runs. It blocks out-of-scope hosts,
  port scanners (use `hk portscan`), brute forcing (never allowed), and the
  run's own files. If a command is blocked you will see the reason; adjust and
  continue, do not fight it.
- Stay within the program rules above. Do only what is needed to show a problem
  is real: a minimal, non-destructive proof of concept. Never exfiltrate real
  user data, never run denial of service, never change or delete data you did
  not create. When a rule is unclear, treat it as not allowed and record a note.

Your toolkit is `hk` (run `hk help`). Use it for everything that must be
remembered, because only `hk` writes to the shared inventory the next phases
read, and every write is scope-checked:
- read: hk scope / hk scope check <url> / hk stats / hk hosts / hk services /
  hk endpoints / hk leads / hk handoff
- run tool, then import: e.g. `httpx -l hosts.txt -json -o out.jsonl` then
  `hk import httpx out.jsonl`. Importers: subfinder, dnsx, httpx, katana, ffuf.
- record: hk add host|endpoint|lead, hk priority, hk filter, hk mark
- built-in safe checks: hk portscan, hk baseline, hk check-content <url>,
  hk takeover, hk wordlist
- report: hk progress "<step>" <done> <total> <unit>; hk notify "<title>"
  "<msg>" (Discord, secrets masked); hk note "<text>"

Installed tools on your PATH (they already route through the proxy): subfinder,
dnsx, httpx, katana, ffuf, plus curl, jq, python3, and the usual shell. Call
them by name. For a port scan use `hk portscan`, never nmap/masscan.

Work in this directory. Save tool output to files here and import it; do not
paste large output back to yourself. Call `hk progress` as you go so the
operator can see how far along you are.

== YOUR TASK FOR THIS PHASE ==
{task}

When you are done, write a short plain-English summary to ./handoff.md for the
next phase: what you found, what is worth a closer look, and anything you could
not finish. Then reply DONE.
"""


class AgentPhase(Phase):
    """Base for a phase driven by an AI agent. Subclasses set id/name/version/
    requires, `role` (which model tier), and `task(ctx)` (the phase's goal).
    They may override `check(ctx)` to decide the result from the inventory."""

    role = "scanner"
    max_turns = 120
    timeout_minutes = 120

    def task(self, ctx: Context) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def check(self, ctx: Context, store) -> PhaseResult:
        """Default: DONE if the agent wrote a handoff, else PARTIAL."""
        if (self._workdir(ctx) / "handoff.md").exists():
            return PhaseResult(st.DONE, "phase completed")
        return PhaseResult(st.PARTIAL, "the agent did not finish; it will continue on the next start")

    # ------------------------------------------------------------------ run
    def run(self, ctx: Context) -> PhaseResult:
        if not ctx.target.scope_file.exists():
            return PhaseResult(st.BLOCKED, "scope.json is missing; intake must run again")
        proxy = ctx.proxy()                       # make sure the guard is up
        workdir = self._workdir(ctx)
        workdir.mkdir(parents=True, exist_ok=True)
        self._write_settings(ctx, workdir)
        env = self._env(ctx, proxy, workdir)
        scope_summary = self._scope_summary(ctx)
        prompt = PREAMBLE.format(scope_summary=scope_summary, task=self.task(ctx))
        ctx.log(f"AI phase {self.id}: starting ({self.role})")
        ctx.progress(f"{self.name}: the AI is working", None, None)
        result = ctx.agent(self.role, prompt, name=self.id, workdir=workdir, base_env=env,
                           bare=False, max_turns=self.max_turns, timeout_minutes=self.timeout_minutes,
                           add_dirs=[workdir])
        self._save_handoff(ctx, workdir)
        if result.fatal:
            return PhaseResult(st.BLOCKED, f"model error: {result.error}")
        outcome = self.check(ctx, ctx.assets())
        ctx.log(f"AI phase {self.id}: {outcome.status} - {outcome.summary}")
        return outcome

    def outputs_present(self, ctx: Context) -> bool:
        return (self._workdir(ctx) / "handoff.md").exists()

    # -------------------------------------------------------------- helpers
    def _workdir(self, ctx: Context) -> Path:
        return ctx.target.output / "phases" / self.id / "work"

    def _env(self, ctx: Context, proxy, workdir: Path) -> dict:
        env = proxy.env()                         # proxy + CA for all target traffic
        tools = str(tools_dir())
        bindir = str(paths.REPO_DIR / "bin")
        env["PATH"] = os.pathsep.join(p for p in (bindir, tools, env.get("PATH", "")) if p)
        env["HUNTER_TARGET_DIR"] = str(ctx.target.path)
        env["HUNTER_PHASE"] = self.id
        env["HUNTER_SCOPE_FILE"] = str(ctx.target.scope_file)
        env["HUNTER_PROTECTED"] = os.pathsep.join(str(p) for p in (
            ctx.target.scope_file, ctx.target.output / "avoid.json", ctx.target.state_db, tools))
        env["HUNTER_HOOK_LOG"] = str(ctx.target.logs / "hook-blocks.jsonl")
        env["HUNTER_NOTES_FILE"] = str(workdir / "notes.md")
        scope = ctx.scope()
        ua = next((v for k, v in scope.required_headers.items() if k.lower() == "user-agent"), "")
        env["HUNTER_USER_AGENT"] = ua or "Mozilla/5.0"
        env["HUNTER_EXTRA_HOSTS"] = ",".join(ctx.settings.get("agent", {}).get("extra_hosts", []))
        return env

    def _write_settings(self, ctx: Context, workdir: Path) -> None:
        """A project settings file in the agent's cwd that wires the command
        checker as a PreToolUse hook on Bash and WebFetch."""
        python = str(paths.REPO_DIR / ".venv" / "bin" / "python")
        hook = f"{python} {paths.REPO_DIR / 'hunter' / 'guard_hook.py'}"
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash|WebFetch",
                     "hooks": [{"type": "command", "command": hook, "timeout": 20}]},
                ]
            }
        }
        claude_dir = workdir / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        (claude_dir / "settings.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")

    def _scope_summary(self, ctx: Context) -> str:
        scope = ctx.scope()
        rules = scope.rules
        lines = [
            "In scope: " + (", ".join(a.raw for a in scope.in_scope) or "(none listed)"),
            "Out of scope: " + (", ".join(a.raw for a in scope.out_of_scope) or "(none)"),
        ]
        if scope.operator_out:
            lines.append("Never touch (operator): " + ", ".join(a.raw for a in scope.operator_out))
        lines.append(f"Max request rate: {scope.rate_limit_rps} per second (the proxy enforces this).")
        if rules.get("required_headers"):
            lines.append("Required headers: " + ", ".join(f"{k}: {v}" for k, v in rules["required_headers"].items()))
        if scope.forbidden_actions:
            lines.append("Forbidden: " + "; ".join(scope.forbidden_actions))
        if scope.excluded_vulnerabilities:
            lines.append("Not accepted (do not report): " + "; ".join(scope.excluded_vulnerabilities))
        if scope.other_rules:
            lines.append("Other rules: " + "; ".join(scope.other_rules))
        if rules.get("low_automation"):
            lines.append("This program limits automated scanning: keep automation light.")
        return "\n".join(lines)

    def _save_handoff(self, ctx: Context, workdir: Path) -> None:
        src = workdir / "handoff.md"
        if src.exists():
            dest = ctx.target.output / "handoff"
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{self.id}.md").write_text(src.read_text(encoding="utf-8", errors="replace"),
                                                encoding="utf-8")
