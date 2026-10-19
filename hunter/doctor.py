"""`hunt doctor`: checks that everything a run needs is in place, and
tests a real AI session end to end with the configured models."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from typing import Callable

from . import agent, config, models, notify, paths, target as target_mod

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


class Report:
    def __init__(self, out: Callable[[str], None]):
        self.out = out
        self.results: list[tuple[str, str, str]] = []

    def add(self, status: str, name: str, detail: str = "") -> None:
        self.results.append((status, name, detail))
        self.out(f"[{status}] {name}{': ' + detail if detail else ''}")

    @property
    def failed(self) -> bool:
        return any(status == FAIL for status, _, _ in self.results)


def _version(cmd: list[str]) -> str | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None
    text = (proc.stdout or proc.stderr).strip().splitlines()
    return text[0] if proc.returncode == 0 and text else None


def check_system(report: Report) -> None:
    py = sys.version_info
    if py >= (3, 10):
        report.add(PASS, "Python", f"{py.major}.{py.minor}.{py.micro}")
    else:
        report.add(FAIL, "Python", f"{py.major}.{py.minor} is too old, 3.10 or newer is needed")

    claude_version = _version([paths.claude_bin(), "--version"])
    if claude_version:
        report.add(PASS, "Claude Code", claude_version)
    else:
        report.add(FAIL, "Claude Code", "not found. Run the installer again: bash ~/hunter-ai/install.sh")

    for tool in ("tmux", "git", "jq", "curl"):
        report.add(PASS if shutil.which(tool) else FAIL, tool,
                   "installed" if shutil.which(tool) else "missing. Run the installer again")

    usage = shutil.disk_usage(str(paths.home()))
    free_gb = usage.free / 1e9
    report.add(PASS if free_gb >= 20 else WARN, "Disk space", f"{free_gb:.0f} GB free")
    try:
        with open("/proc/meminfo", encoding="utf-8") as handle:
            info = dict(line.split(":", 1) for line in handle if ":" in line)
        total_gb = int(info["MemTotal"].split()[0]) / 1e6
        report.add(PASS if total_gb >= 3.5 else WARN, "Memory", f"{total_gb:.1f} GB total")
    except (OSError, KeyError, ValueError):
        pass

    from . import toolchain
    missing_tools = [t.name for t in toolchain.TOOLS if toolchain.installed_path(t) is None]
    if not missing_tools:
        report.add(PASS, "Recon tools", "all installed")
    else:
        report.add(WARN, "Recon tools", "missing: " + ", ".join(missing_tools) + ". Run: hunt tools install")

    skills = paths.skills_dir()
    if skills.is_dir():
        count = sum(1 for p in skills.iterdir() if (p / "SKILL.md").exists())
        report.add(PASS, "Skills folder", f"{count} skills in {skills}")
    else:
        report.add(WARN, "Skills folder", f"{skills} not found. The skills pass will be skipped")

    old = [t.name for t in target_mod.list_targets() if (t.path / "CLAUDE.md").exists()]
    if old:
        report.add(WARN, "Old CLAUDE.md files",
                   "found in targets " + ", ".join(old) + ". They are ignored in bare mode, "
                   "but it is cleaner to start new targets with: hunt new <name>")


def check_secrets(report: Report, settings: dict, secrets: dict[str, str],
                  send_test: bool, probe_fn=models.probe) -> None:
    path = paths.secrets_file()
    if not path.exists():
        report.add(FAIL, "Keys file", "not found. Run: hunt setup")
        return
    mode = stat.S_IMODE(os.stat(path).st_mode)
    report.add(PASS if mode & 0o077 == 0 else WARN, "Keys file permissions",
               "private" if mode & 0o077 == 0 else f"{oct(mode)}; fixing to 600")
    if mode & 0o077:
        os.chmod(path, 0o600)

    webhook = secrets.get("DISCORD_WEBHOOK_URL", "")
    if not webhook:
        report.add(FAIL, "Discord", "no webhook saved. Run: hunt setup")
    elif send_test:
        ok = notify.Notifier(secrets).send("Doctor check", "This is a test message from hunt doctor.", "info")
        report.add(PASS if ok else FAIL, "Discord", "test message sent" if ok else "could not send. Run: hunt setup")
    else:
        report.add(PASS, "Discord", "webhook saved")

    checked: set[str] = set()
    for role in settings["roles"]:
        choice = models.resolve(settings, role)
        if choice.profile_name in checked:
            continue
        checked.add(choice.profile_name)
        label = choice.profile.get("label", choice.profile_name)
        key = secrets.get(choice.profile["key_name"], "")
        if not key:
            report.add(FAIL, f"{label} key", f"missing ({choice.profile['key_name']}). Run: hunt setup")
            continue
        ok, message = probe_fn(choice.profile, key)
        report.add(PASS if ok else FAIL, f"{label} key", message)


def check_proxy(report: Report, settings: dict) -> None:
    """Start the scope guard with a throw-away scope and prove that it
    blocks out-of-scope traffic. Nothing leaves this server."""
    from . import scope as sc
    from .proxy import ProxyError, ScopeProxy, mitmdump_bin

    if not mitmdump_bin():
        report.add(FAIL, "Scope guard", "mitmproxy is not installed. Run: hunt update")
        return
    folder = paths.config_dir() / "doctor-proxy"
    scope_file = folder / "scope.json"
    sc.save(sc.Scope(in_scope=[sc.parse_asset("doctor-check.invalid")], rules={"effective_rps": 5}), scope_file)
    proxy = ScopeProxy(scope_file, folder / "logs", settings)
    try:
        proxy.start()
        ok, message = proxy.self_test()
    except ProxyError as exc:
        ok, message = False, str(exc)
    finally:
        proxy.stop()
    report.add(PASS if ok else FAIL, "Scope guard", message)


def check_agents(report: Report, settings: dict, secrets: dict[str, str]) -> None:
    """Run a real headless session. First try bare mode (recommended for
    scripts); if it does not work with this provider, fall back to normal
    mode and remember the decision."""
    workdir = paths.config_dir() / "doctor-work"
    workdir.mkdir(parents=True, exist_ok=True)
    detected = settings.setdefault("detected", {})

    def attempt(role: str, bare: bool) -> tuple[bool, str]:
        try:
            result = agent.smoke_test(settings, secrets, role, workdir, bare=bare)
        except agent.AgentFatalError as exc:
            return False, str(exc)
        except config.ConfigError as exc:
            return False, str(exc)
        if agent.check_ready(result):
            return True, f"{result.model} answered in {result.duration_s:.0f}s"
        return False, result.error or f"unexpected answer: {result.text[:120]!r}"

    ok_bare, msg_bare = attempt("triage", True)
    if ok_bare:
        detected["bare_ok"] = True
        report.add(PASS, "AI session (bare mode)", msg_bare)
    else:
        ok_normal, msg_normal = attempt("triage", False)
        detected["bare_ok"] = False
        if ok_normal:
            report.add(PASS, "AI session (normal mode)", msg_normal + "; bare mode did not work: " + msg_bare)
        else:
            report.add(FAIL, "AI session", msg_normal)
            config.save_settings(settings)
            return
    config.save_settings(settings)

    ok_strong, msg_strong = attempt("validator", detected["bare_ok"])
    report.add(PASS if ok_strong else FAIL, "AI session (strong model)", msg_strong)


def check_browser(report: Report, settings: dict) -> None:
    """The scope-proxied headless browser (hbrowse) is optional: the client-side
    testing phases use it when present and fall back to curl when not."""
    browser = settings.get("browser", {}) or {}
    if not browser.get("enabled", True):
        report.add(PASS, "Headless browser", "disabled in settings (browser.enabled=false)")
        return
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        report.add(WARN, "Headless browser",
                   "Playwright not installed (optional; DOM/client-side PoCs need it). Install: "
                   ".venv/bin/python -m playwright install --with-deps chromium")
        return
    try:
        with sync_playwright() as pw:
            path = pw.chromium.executable_path
        if path and os.path.exists(path):
            report.add(PASS, "Headless browser", "Playwright Chromium ready")
        else:
            report.add(WARN, "Headless browser",
                       "Chromium not downloaded. Run: .venv/bin/python -m playwright install --with-deps chromium")
    except Exception as exc:
        report.add(WARN, "Headless browser",
                   f"Playwright present but Chromium not usable ({exc}). "
                   "Run: .venv/bin/python -m playwright install --with-deps chromium")


def run_doctor(out: Callable[[str], None] = print, quick: bool = False) -> int:
    report = Report(out)
    try:
        settings = config.load_settings()
    except config.ConfigError as exc:
        report.add(FAIL, "Settings", str(exc))
        return 1
    secrets = config.load_secrets()
    out("hunter-ai doctor")
    out("")
    check_system(report)
    check_secrets(report, settings, secrets, send_test=not quick)
    check_proxy(report, settings)
    check_browser(report, settings)
    if not settings["researcher"].get("handle"):
        report.add(WARN, "Username", "not set. Some programs require it in a header. Set it with: hunt handle <name>")
    if not quick and not report.failed:
        out("")
        out("Testing a real AI session (this takes up to a few minutes) ...")
        check_agents(report, settings, secrets)
    out("")
    if report.failed:
        out("Some checks failed. Fix the lines marked FAIL, then run: hunt doctor")
        return 1
    out("All required checks passed." + (" (quick mode: AI session not tested)" if quick else ""))
    return 0
