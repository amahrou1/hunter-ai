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
  hunt scope <name>          what the AI read as in scope / out of scope / unclear
  hunt scope <name> check <url>      would this URL be allowed?
  hunt handle <username>     your platform username (for required headers and emails)
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
        subprocess.run(["tmux", "kill-session", "-t", session], capture_output=True)
    command = (f"{shlex.quote(HUNT)} run {shlex.quote(str(target.path))}; "
               "echo; echo 'The run has ended. Press Enter to close this window.'; read _")
    subprocess.run(["tmux", "new-session", "-d", "-s", session, "-c", str(target.path),
                    "bash", "-lc", command], check=True)
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
        width = max((len(r["phase_id"]) for r in state.phases()), default=10)
        for row in state.phases():
            _print(f"  {row['phase_id']:<{width}}  {row['status']:<15} {row['summary'] or ''}"[:200])
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


def cmd_update(_args) -> int:
    repo = paths.REPO_DIR
    _print("Downloading the newest version ...")
    pull = subprocess.run(["git", "-C", str(repo), "pull", "--ff-only"])
    if pull.returncode != 0:
        _print("ERROR: the download failed. Send the lines above to Claude.")
        return 1
    return subprocess.run(["bash", str(repo / "install.sh"), "--update"]).returncode


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
