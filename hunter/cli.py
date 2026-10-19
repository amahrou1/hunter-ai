"""The `hunt` command."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import signal
import subprocess
import sys
from pathlib import Path

from . import __version__, config, models, paths
from . import state as st
from . import target as target_mod
from .orchestrator import Orchestrator, is_running

HUNT = str(paths.REPO_DIR / "bin" / "hunt")

HELP = f"""hunter-ai {__version__}

First time:
  hunt setup                 paste your keys (Discord, GLM, ...)
  hunt doctor                check that everything works

For each program:
  hunt new <name>            create the target folder ~/targets/<name>
  nano ~/targets/<name>/policy.txt      paste the program page, save with Ctrl+O, Enter, Ctrl+X
  hunt start <name>          start the run in the background
  hunt watch <name>          watch it live (leave with Ctrl+b, then d)
  hunt status [name]         what is done, what is blocked
  hunt logs <name>           follow the log (leave with Ctrl+c)
  hunt stop <name>           stop it; hunt start continues where it stopped
  hunt tell <name> "message"  steer a run, also while it runs: focus / add / avoid / skip, or any hint
  hunt tell <name>           list your messages and what they changed
  hunt chat <name>           talk to an AI about what the run found (it can pass on your instructions)
  hunt reset <name> [phase]  clear a stuck phase (e.g. 02-recon) so it runs again; no phase = all
  hunt findings <name>       findings found so far, by severity, and report drafts
  hunt scope <name>          what the AI read as in scope / out of scope / unclear
  hunt scope <name> check <url>      would this URL be allowed?
  hunt handle <username>     your platform username (for required headers and emails)
  hunt rate-cap <n>          max requests/second this VPS will send (per-program limit still wins)
  hunt tools                 show which recon tools are installed
  hunt tools install         download the recon tools (subfinder, dnsx, httpx, ...)

Models:
  hunt models                show which model each task uses
  hunt models use glm        switch everything to glm, deepseek or claude

Tools:
  hunt tools status          are the recon tools installed?
  hunt tools install         download or update the recon tools
  hunt models role <role> <profile[:tier]>   advanced: one task on another model

Maintenance:
  hunt update                download and install the newest version
  hunt version
"""


def _print(text: str = "") -> None:
    print(text, flush=True)


# ------------------------------------------------------------------ commands

def cmd_setup(_args) -> int:
    from .setup_wizard import run_setup
    return run_setup()


def cmd_doctor(args) -> int:
    from .doctor import run_doctor
    return run_doctor(quick=args.quick)


def cmd_new(args) -> int:
    target, created = target_mod.create(args.name)
    _print(f"Target folder: {target.path}")
    if created:
        _print("Created: " + ", ".join(created))
    _print("")
    _print("Next steps:")
    _print(f"  1. Paste the program page:   nano {target.input_path('policy.txt')}")
    _print("     (paste with a right click or Ctrl+Shift+V, save with Ctrl+O then Enter, exit with Ctrl+X)")
    _print(f"  2. Optional: accounts in     nano {target.input_path('test-credentials.txt')}")
    _print(f"     Optional: your reports in nano {target.input_path('reports.txt')}")
    _print(f"     Optional: disclosed ones  nano {target.input_path('resolved-reports.txt')}")
    _print(f"  3. Start:                    hunt start {target.name}")
    return 0


def _load_target(name: str) -> target_mod.Target:
    return target_mod.resolve(name)


def cmd_run(args) -> int:
    target = _load_target(args.target)
    if getattr(args, 'until', None):
        os.environ['HUNTER_UNTIL'] = args.until
    settings = config.load_settings()
    secrets = config.load_secrets()
    return Orchestrator(target, settings, secrets).run()


def _tmux_has(session: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", session],
                          capture_output=True).returncode == 0


def cmd_start(args) -> int:
    target = _load_target(args.target)
    problems = target.validate()
    if problems:
        for problem in problems:
            _print(f"ERROR: {problem}")
        return 2
    if not shutil.which("tmux"):
        _print("ERROR: tmux is not installed. Run the installer again.")
        return 1
    session = target.tmux_session()
    if is_running(target):
        _print(f"'{target.name}' is already running. Watch it with: hunt watch {target.name}")
        return 0
    if _tmux_has(session):
        # A window is left over from a finished run (it sits at the "press
        # Enter" prompt). No run is active, so close it and open a fresh one.
        subprocess.run(["tmux", "kill-session", "-t", session], capture_output=True)
    until = f" --until {shlex.quote(args.until)}" if getattr(args, "until", None) else ""
    command = (f"{shlex.quote(HUNT)} run {shlex.quote(str(target.path))}{until}; "
               "echo; echo 'The run has ended. Press Enter to close this window.'; read _")
    created = subprocess.run(["tmux", "new-session", "-d", "-s", session, "-c", str(target.path),
                              "bash", "-lc", command], capture_output=True)
    if created.returncode != 0:
        # Another `hunt start` opened the window a moment ago: keep that one.
        if _tmux_has(session):
            _print(f"'{target.name}' was just started. Watch it with: hunt watch {target.name}")
            return 0
        _print("ERROR: could not open the background window: "
               + created.stderr.decode(errors="replace").strip())
        return 1
    subprocess.run(["tmux", "set-option", "-t", session, "history-limit", "50000"], capture_output=True)
    _print(f"Started '{target.name}' in the background (tmux session {session}).")
    _print("You can close this terminal; the run keeps going.")
    _print(f"Watch it:  hunt watch {target.name}    Status: hunt status {target.name}")
    return 0


def cmd_watch(args) -> int:
    target = _load_target(args.target)
    session = target.tmux_session()
    if not _tmux_has(session):
        _print(f"No live window for '{target.name}'. Status: hunt status {target.name}")
        return 1
    _print("Leave the window with Ctrl+b, then d. The run keeps going.")
    os.execvp("tmux", ["tmux", "attach-session", "-t", session])
    return 0


def cmd_stop(args) -> int:
    target = _load_target(args.target)
    session = target.tmux_session()
    if _tmux_has(session) and is_running(target):
        subprocess.run(["tmux", "send-keys", "-t", session, "C-c"], capture_output=True)
        _print(f"Stop signal sent to '{target.name}'. It saves its state and stops in a few seconds.")
        _print(f"Continue later with: hunt start {target.name}")
        return 0
    lock = target.output / ".lock"
    if is_running(target) and lock.exists():
        try:
            pid = int(lock.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            _print(f"Stop signal sent to process {pid}.")
            return 0
        except (ValueError, ProcessLookupError, PermissionError):
            pass
    _print(f"'{target.name}' is not running.")
    return 0


def cmd_logs(args) -> int:
    target = _load_target(args.target)
    log = target.logs / "run.log"
    if not log.exists():
        _print(f"No log yet for '{target.name}'.")
        return 1
    _print("Following the log. Leave with Ctrl+c (the run keeps going).")
    os.execvp("tail", ["tail", "-n", "60", "-F", str(log)])
    return 0


def _status_one(target: target_mod.Target) -> None:
    running = is_running(target)
    _print(f"Target: {target.name}  ({'RUNNING' if running else 'not running'})")
    _print(f"Folder: {target.path}")
    if not target.state_db.exists():
        _print("No run yet. Start with: hunt start " + target.name)
        return
    state = st.State(target.state_db)
    try:
        _print("")
        from .progress import describe
        rows = state.phases()
        width = max((len(r["phase_id"]) for r in rows), default=10)
        for row in rows:
            if row["status"] == st.RUNNING:
                _print(f"  {row['phase_id']:<{width}}  {row['status']:<15} <- now")
                _print(f"  {'':<{width}}  {describe(state.get_progress(row['phase_id']), row['started_at'])}")
                continue
            _print(f"  {row['phase_id']:<{width}}  {row['status']:<15} {row['summary'] or ''}"[:200])
        settled = sum(1 for r in rows if r["status"] in st.SETTLED)
        _print(f"\n  {settled} of {len(rows)} phases finished.")
        open_blockers = state.open_blockers()
        _print("")
        if open_blockers:
            _print("Waiting for you:")
            for b in open_blockers:
                files = b["watch_files"] or "[]"
                _print(f"  #{b['id']} {b['need']}  (add: {files.strip('[]').replace(chr(34), '')})")
        else:
            _print("Nothing is waiting for you.")
        totals = state.agent_totals()
        _print(f"AI sessions: {totals['runs']} ({totals['ok']} succeeded)")
        summary = target.output / "run_summary.md"
        if summary.exists():
            _print(f"Last summary: {summary}")
    finally:
        state.close()


def cmd_status(args) -> int:
    if args.target:
        _status_one(_load_target(args.target))
        return 0
    targets = target_mod.list_targets()
    if not targets:
        _print(f"No targets yet in {paths.targets_dir()}. Create one with: hunt new <name>")
        return 0
    for target in targets:
        label = "RUNNING" if is_running(target) else "-"
        done = total = 0
        if target.state_db.exists():
            state = st.State(target.state_db)
            rows = state.phases()
            total = len(rows)
            done = sum(1 for r in rows if r["status"] in st.SETTLED)
            state.close()
        progress = f"{done}/{total} phases finished" if total else "not started"
        _print(f"  {target.name:<30} {label:<8} {progress}")
    return 0


def cmd_models(args) -> int:
    settings = config.load_settings()
    secrets = config.load_secrets()
    if args.action == "use":
        if not args.values or args.values[0] not in settings["profiles"]:
            _print("Use one of: " + ", ".join(settings["profiles"]))
            return 1
        name = args.values[0]
        settings["active_profile"] = name
        settings.setdefault("detected", {}).pop("bare_ok", None)
        config.save_settings(settings)
        profile = settings["profiles"][name]
        _print(f"Active model profile is now: {profile['label']}")
        if not secrets.get(profile["key_name"]):
            _print(f"Note: no {profile['key_name']} saved yet. Run: hunt setup")
        _print("Run hunt doctor to test it.")
        return 0
    if args.action == "role":
        if len(args.values) != 2:
            _print("Usage: hunt models role <role> <profile[:tier]>   e.g. hunt models role disprover claude:max")
            _print("Roles: " + ", ".join(config.ROLES) + ". Tiers: " + ", ".join(config.TIERS))
            return 1
        role, spec = args.values
        if ":" not in spec:
            spec = f"{spec}:{config.DEFAULT_SETTINGS['roles'].get(role, 'active:strong').split(':')[1]}"
        settings["roles"][role] = spec
        models.resolve(settings, role)  # validates, raises ConfigError
        config.save_settings(settings)
        _print(f"Role '{role}' now uses {models.resolve(settings, role).label}")
        return 0
    if args.action == "reset":
        settings["roles"] = dict(config.DEFAULT_SETTINGS["roles"])
        config.save_settings(settings)
        _print("Roles reset to the defaults.")
        return 0

    active = settings["profiles"][settings["active_profile"]]
    _print(f"Active profile: {settings['active_profile']} ({active['label']})")
    _print("")
    for role in settings["roles"]:
        choice = models.resolve(settings, role)
        has_key = "key saved" if secrets.get(choice.profile["key_name"]) else "NO KEY"
        _print(f"  {role:<10} -> {choice.label:<45} [{has_key}]")
    _print("")
    _print("Switch everything: hunt models use glm | deepseek | claude")
    return 0


def cmd_scope(args) -> int:
    target = _load_target(args.target)
    if not target.scope_file.exists():
        _print(f"No scope yet for '{target.name}'. It is created by the first phase of: hunt start {target.name}")
        return 1
    from . import scope as sc
    scope = sc.load(target.scope_file)
    if args.action == "check":
        if not args.value:
            _print("Usage: hunt scope <target> check <url-or-host>")
            return 1
        decision = scope.decide_url(args.value)
        verdict = "ALLOWED" if decision.allowed else "BLOCKED"
        _print(f"{verdict}: {args.value} ({decision.reason}{': ' + decision.matched if decision.matched else ''})")
        return 0 if decision.allowed else 3
    _print(target.scope_review.read_text(encoding="utf-8") if target.scope_review.exists() else "(no review file)")
    return 0


def cmd_handle(args) -> int:
    settings = config.load_settings()
    if not args.name:
        handle = settings["researcher"].get("handle") or "(not set)"
        _print(f"Your bug bounty username: {handle}")
        _print("Set it with: hunt handle <your-username>")
        return 0
    name = args.name.strip()
    if not name or any(ch.isspace() for ch in name) or len(name) > 64:
        _print("ERROR: give your username without spaces, for example: hunt handle amahrou1")
        return 1
    settings["researcher"]["handle"] = name
    config.save_settings(settings)
    _print(f"Saved. Your bug bounty username is now: {name}")
    _print("It fills placeholders like 'X-Bug-Bounty: <username>' and builds emails like "
           f"{name}@intigriti.me.")
    return 0


def cmd_tools(args) -> int:
    from . import toolchain
    if args.action == "status":
        ok = toolchain.status(_print)
        return 0 if ok else 1
    _print("Installing recon tools into " + str(toolchain.tools_dir()))
    report = toolchain.install_all(prefer_latest=not args.pinned, force=args.force, out=_print)
    missing = [r.name for r in report.results if not r.ok]
    if missing:
        _print("")
        _print("These did not install: " + ", ".join(missing) + ". You can try again with: hunt tools install")
        return 1
    _print("All recon tools are installed.")
    return 0


def cmd_rate_cap(args) -> int:
    settings = config.load_settings()
    if args.value is None:
        _print(f"Hardware rate ceiling: {settings['scope']['max_rps']} requests/second")
        _print("This caps every program, to protect run quality on this VPS.")
        _print("Change it with: hunt rate-cap <number>")
        return 0
    try:
        value = float(args.value)
        if value <= 0:
            raise ValueError
    except ValueError:
        _print("ERROR: give a positive number, e.g. hunt rate-cap 300")
        return 1
    settings["scope"]["max_rps"] = value
    config.save_settings(settings)
    _print(f"Hardware rate ceiling set to {value:g} requests/second.")
    _print("A program's own limit still applies when it is lower.")
    return 0


def cmd_update(_args) -> int:
    repo = paths.REPO_DIR
    _print("Downloading the newest version ...")
    pull = subprocess.run(["git", "-C", str(repo), "pull", "--ff-only"])
    if pull.returncode != 0:
        _print("ERROR: the download failed. Send the lines above to Claude.")
        return 1
    return subprocess.run(["bash", str(repo / "install.sh"), "--update"]).returncode


def cmd_tell(args) -> int:
    from .instructions import Operator
    from .notify import Notifier
    target = _load_target(args.target)
    target.output.mkdir(parents=True, exist_ok=True)
    state = st.State(target.state_db)
    try:
        operator = Operator(target, state)
        text = " ".join(args.message).strip()
        if not text:
            return _tell_list(target, operator)
        instruction = operator.submit(text)
    finally:
        state.close()
    lines = instruction.lines()
    _print(f"Saved as message #{instruction.id}.")
    for line in lines:
        _print("  " + line)
    running = is_running(target)
    _print("The AI sessions will also read your message as you wrote it.")
    if running:
        _print("The run picks it up before its next step. You will see it in: hunt watch " + target.name)
    else:
        _print(f"The run is not active; it uses this when you start it: hunt start {target.name}")
    settings, secrets = config.load_settings(), config.load_secrets()
    Notifier(secrets, settings["notify"].get("discord", True)).send(
        f"Got your message #{instruction.id}", f"\"{text[:300]}\"\n" + "\n".join(lines), "info",
        target=target.name)
    return 0


def _tell_list(target, operator) -> int:
    messages = operator.all()
    if not messages:
        _print(f"No messages yet. Example: hunt tell {target.name} \"focus api.example.com\"")
        _print(TELL_HELP)
        return 0
    for message in messages:
        flag = "  (no longer shown to the AI)" if message.withdrawn else ""
        _print(f"#{message.id}  {message.created[:16].replace('T', ' ')}  {message.text}{flag}")
        for line in message.lines():
            _print("      " + line)
    _print()
    _print("Focus:   " + (", ".join(operator.focus()) or "-"))
    _print("Avoid:   " + (", ".join(operator.avoided()) or "-"))
    _print("Skipped: " + (", ".join(sorted(operator.skipped())) or "-"))
    return 0


TELL_HELP = """
Things it understands (plain English works too):
  focus api.example.com        test it first in every later phase (also *.example.com)
  add 10.1.2.3                 add a host or IP you found (scope-checked first)
  avoid admin.example.com      never touch it; blocked even in the middle of the run
  skip javascript              do not run a phase (by name or number, e.g. "skip phase 6")
  unfocus / unavoid / unskip   undo
  forget 3                     stop showing message #3 to the AI
Anything else is passed to the AI sessions as a hint."""


CHAT_PROMPT = """You are helping the operator of an autonomous bug bounty run (hunter-ai).
Target: {name}. Target folder (your working directory): {path}

The run itself is a separate background process. Your job in this chat is to
answer the operator's questions about what the run has found and to pass
their decisions to the run. Explain things in simple English; the operator
is a bug bounty hunter but not a programmer.

What you can read:
- policy.txt and scope-overrides.txt: the program rules and the operator's scope corrections
- hunt-output/scope_review.md: what is in scope, out of scope, unclear, and the request rate
- hunt-output/run_summary.md and hunt-output/logs/run.log: progress and the live log
- hunt-output/hosts_in_scope.txt, recon.json: hosts, third-party hosts, takeover candidates
- hunt-output/services.txt, services.json: live web services, highest priority first
- hunt-output/state.db: SQLite (tables phases, hosts, services, blockers, instructions).
  There is no sqlite3 command; use: python3 -c "import sqlite3; ..."
- Commands: hunt status {name}, hunt scope {name}, hunt scope {name} check <url>

How to change what the run does (the only way):
  hunt tell {name} "<instruction>"
  e.g. hunt tell {name} "focus api.example.com", "add 10.1.2.3", "avoid admin.example.com",
  "skip javascript", or any free-text hint for the testing agents. Run `hunt tell {name}`
  with no message to list what was already said. Show the operator what you are about to
  send, then send it; the command prints how it was understood.

Hard rules:
- Do NOT send any request to the target's hosts yourself (no curl, no browser, no tools
  that touch the target). All testing goes through the run, which enforces scope and the
  rate limit. Looking things up on the public web about the program or a technology is fine.
- Do not edit files under hunt-output/ or the run's state. Do not stop or start the run
  unless the operator asks (hunt stop {name} / hunt start {name}).
- Never suggest testing anything that is out of scope or that the program rules forbid.
"""


def cmd_chat(args) -> int:
    target = _load_target(args.target)
    if not target.path.is_dir():
        _print(f"No target folder {target.path}. Create it with: hunt new {target.name}")
        return 1
    settings, secrets = config.load_settings(), config.load_secrets()
    try:
        choice = models.resolve(settings, "tester")
        env = models.agent_env(choice, secrets)
    except config.ConfigError as exc:
        _print(f"ERROR: {exc}")
        return 1
    claude = paths.claude_bin()
    if not shutil.which(claude) and not Path(claude).exists():
        _print("ERROR: Claude Code is not installed. Run the installer again.")
        return 1
    _print(f"Chat about '{target.name}' using {choice.label}. The run keeps going in the background.")
    _print("Leave the chat with /exit (or Ctrl+c twice).")
    prompt = CHAT_PROMPT.format(name=target.name, path=target.path)
    os.chdir(target.path)
    os.execvpe(claude, [claude, "--model", choice.model, "--dangerously-skip-permissions",
                        "--append-system-prompt", prompt], env)
    return 0


def cmd_findings(args) -> int:
    from hunter import assets as A
    target = _load_target(args.target)
    if not target.state_db.exists():
        _print(f"{target.name} has not run yet.")
        return 0
    state = st.State(target.state_db)
    try:
        store = A.Assets(state.db)
        rows = store.findings(args.status)
        if not rows:
            _print("No findings recorded yet." if not args.status else f"No findings with status {args.status}.")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for r in sorted(rows, key=lambda r: (order.get(r["severity"], 9), r["id"])):
            _print(f"#{r['id']} [{r['status']}] {r['severity'] or '-'} {r['kind'] or '-'}: {r['title']}")
            if r["url"]:
                _print(f"      {r['url']}")
            if args.full and r["summary"]:
                _print(f"      {r['summary']}")
        reports = target.output / "reports"
        drafts = sorted(reports.glob("*.md")) if reports.is_dir() else []
        if drafts:
            _print(f"\nReport drafts ({len(drafts)}) in {reports}:")
            for d in drafts:
                _print(f"  {d.name}")
    finally:
        state.close()
    return 0


def cmd_oob(args) -> int:
    """View or change the out-of-band testing infrastructure the agents use."""
    settings = config.load_settings()
    oob = settings.setdefault("oob", {})
    changed = False
    if args.callback_host is not None:
        oob["callback_host"] = args.callback_host; changed = True
    if args.blind_xss_url is not None:
        oob["blind_xss_url"] = args.blind_xss_url; changed = True
    if args.on:
        oob["enabled"] = True; changed = True
    if args.off:
        oob["enabled"] = False; changed = True
    if changed:
        config.save_settings(settings)
        _print("Saved.")
    _print(f"Out-of-band infrastructure (enabled: {oob.get('enabled', True)}):")
    _print(f"  Callback / SSRF server : {oob.get('callback_host') or '(none)'}")
    _print(f"  Listener ports         : {', '.join(str(p) for p in oob.get('listener_ports', [])) or '(none)'}")
    _print(f"  Blind-XSS collector    : {oob.get('blind_xss_url') or '(none)'}")
    _print(f"  Temporary mail (mail.tm): {oob.get('temp_mail', True)}")
    _print("\nThe agents use these only where the program rules allow (e.g. temp mail only when any email is "
           "accepted). Change: hunt oob --callback-host <ip> --blind-xss-url <url> | --on | --off")
    return 0


def cmd_leads(args) -> int:
    from hunter import assets as A
    target = _load_target(args.target)
    if not target.state_db.exists():
        _print(f"{target.name} has not run yet.")
        return 0
    state = st.State(target.state_db)
    try:
        rows = A.Assets(state.db).leads(args.status)
        if not rows:
            _print("No leads recorded yet." if not args.status else f"No leads with status {args.status}.")
            return 0
        by_kind: dict = {}
        for r in rows:
            by_kind.setdefault(r["kind"], []).append(r)
        _print(f"{len(rows)} lead(s) for {target.name}:\n")
        for kind in sorted(by_kind):
            group = by_kind[kind]
            _print(f"{kind} ({len(group)}):")
            for r in group:
                _print(f"  #{r['id']} [{r['status']}] {r['url']}")
                if r["evidence"]:
                    _print(f"        {r['evidence'][:160]}")
            _print("")
    finally:
        state.close()
    return 0


def cmd_reset(args) -> int:
    """Clear a stuck phase (or all phases) so the next `hunt start` runs it again.

    Only phase status is cleared; the hosts and findings already stored stay.
    """
    target = _load_target(args.target)
    if not target.state_db.exists():
        _print(f"{target.name} has not run yet; nothing to reset.")
        return 0
    state = st.State(target.state_db)
    try:
        rows = state.phases()
        known = {r["phase_id"] for r in rows}
        if args.phase:
            if args.phase not in known:
                _print(f"No phase '{args.phase}' for {target.name}. Known: " + ", ".join(sorted(known)))
                return 1
            state.reset_phase(args.phase, "reset by hand", reset_attempts=True)
            _print(f"{args.phase} cleared. Run: hunt start {target.name}")
        else:
            for row in rows:
                state.reset_phase(row["phase_id"], "reset by hand", reset_attempts=True)
            _print(f"All phases for {target.name} cleared. Run: hunt start {target.name}")
    finally:
        state.close()
    return 0


def cmd_reset_settings(_args) -> int:
    config.reset_settings()
    _print("Settings reset to the defaults. Your keys were not touched.")
    return 0


def cmd_version(_args) -> int:
    _print(f"hunter-ai {__version__}")
    return 0


# --------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hunt", add_help=False)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("setup").set_defaults(func=cmd_setup)
    p = sub.add_parser("doctor")
    p.add_argument("--quick", action="store_true")
    p.set_defaults(func=cmd_doctor)
    p = sub.add_parser("new")
    p.add_argument("name")
    p.set_defaults(func=cmd_new)
    for name, func in (("run", cmd_run), ("start", cmd_start), ("resume", cmd_start),
                       ("watch", cmd_watch), ("stop", cmd_stop), ("logs", cmd_logs)):
        p = sub.add_parser(name)
        p.add_argument("target")
        if name in ("run", "start", "resume"):
            p.add_argument("--until", help="stop after this phase, e.g. 02-recon (for testing phase by phase)")
        p.set_defaults(func=func)
    p = sub.add_parser("status")
    p.add_argument("target", nargs="?")
    p.set_defaults(func=cmd_status)
    p = sub.add_parser("models")
    p.add_argument("action", nargs="?", choices=["show", "use", "role", "reset"], default="show")
    p.add_argument("values", nargs="*")
    p.set_defaults(func=cmd_models)
    p = sub.add_parser("scope")
    p.add_argument("target")
    p.add_argument("action", nargs="?", choices=["show", "check"], default="show")
    p.add_argument("value", nargs="?")
    p.set_defaults(func=cmd_scope)
    p = sub.add_parser("handle")
    p.add_argument("name", nargs="?")
    p.set_defaults(func=cmd_handle)
    p = sub.add_parser("tools")
    p.add_argument("action", nargs="?", choices=["install", "status"], default="status")
    p.add_argument("--pinned", action="store_true", help="use the tested versions, not the latest")
    p.add_argument("--force", action="store_true", help="reinstall even if present")
    p.set_defaults(func=cmd_tools)
    p = sub.add_parser("rate-cap")
    p.add_argument("value", nargs="?")
    p.set_defaults(func=cmd_rate_cap)
    p = sub.add_parser("tell")
    p.add_argument("target")
    p.add_argument("message", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_tell)
    p = sub.add_parser("chat")
    p.add_argument("target")
    p.set_defaults(func=cmd_chat)
    p = sub.add_parser("oob")
    p.add_argument("--callback-host", dest="callback_host")
    p.add_argument("--blind-xss-url", dest="blind_xss_url")
    p.add_argument("--on", action="store_true")
    p.add_argument("--off", action="store_true")
    p.set_defaults(func=cmd_oob)
    p = sub.add_parser("leads")
    p.add_argument("target")
    p.add_argument("--status", help="filter, e.g. signature-match, unverified, ai-confirmed, dismissed")
    p.set_defaults(func=cmd_leads)
    p = sub.add_parser("findings")
    p.add_argument("target")
    p.add_argument("--status", choices=["candidate", "validated", "confirmed", "disproved", "reported"])
    p.add_argument("--full", action="store_true", help="also show each finding's summary")
    p.set_defaults(func=cmd_findings)
    p = sub.add_parser("reset")
    p.add_argument("target")
    p.add_argument("phase", nargs="?", help="a phase id like 02-recon; omit to reset all phases")
    p.set_defaults(func=cmd_reset)
    sub.add_parser("update").set_defaults(func=cmd_update)
    sub.add_parser("reset-settings").set_defaults(func=cmd_reset_settings)
    sub.add_parser("version").set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help", "help"):
        _print(HELP)
        return 0
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        _print("")
        _print("Type 'hunt' alone to see all commands.")
        return int(exc.code or 2)
    if not getattr(args, "func", None):
        _print(HELP)
        return 0
    try:
        return int(args.func(args) or 0)
    except (config.ConfigError, target_mod.TargetError) as exc:
        _print(f"ERROR: {exc}")
        return 1
    except KeyboardInterrupt:
        _print("")
        _print("Cancelled.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
