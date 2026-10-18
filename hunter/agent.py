"""Run one AI task as a headless Claude Code session.

Design rules (lessons from the first automation):
- No interactive prompt can ever block: `-p` plus bypassed permissions.
- Output is streamed line by line to a log file, never buffered in memory.
- Every session has a turn cap and a wall-clock timeout, and the whole
  process group is stopped when the timeout hits.
- An invalid key or unknown model stops immediately instead of retrying
  for hours.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import paths
from .config import ConfigError
from .models import ModelChoice, agent_env, resolve

FATAL_API_ERRORS = {
    "authentication_failed", "billing_error", "model_not_found",
    "account_on_hold", "oauth_org_not_allowed",
}


@dataclass
class AgentResult:
    ok: bool
    text: str
    subtype: str
    exit_code: int | None
    turns: int | None
    cost_usd: float | None
    session_id: str | None
    log_path: Path
    duration_s: float
    model: str
    error: str = ""
    fatal: bool = False
    attempts: int = 1
    permission_denials: list = field(default_factory=list)


class AgentFatalError(Exception):
    """The provider rejected the key, the model name or the account.
    Retrying cannot help; the operator must fix the configuration."""


def bare_enabled(settings: dict) -> bool:
    mode = str(settings["agent"].get("bare", "auto")).lower()
    if mode == "on":
        return True
    if mode == "off":
        return False
    return bool(settings.get("detected", {}).get("bare_ok", False))


def build_command(choice: ModelChoice, *, max_turns: int, bare: bool,
                  add_dirs: Iterable[Path] = (), system_file: Path | None = None) -> list[str]:
    cmd = [
        paths.claude_bin(), "-p",
        "--dangerously-skip-permissions",
        "--output-format", "stream-json", "--verbose",
        "--max-turns", str(max_turns),
        "--model", choice.model,
        # Ignore ~/.claude/settings.json: an old env block there must never
        # override the provider chosen by the orchestrator.
        "--setting-sources", "project,local",
        "--no-session-persistence",
    ]
    if bare:
        cmd.append("--bare")
    for directory in add_dirs:
        cmd += ["--add-dir", str(directory)]
    if system_file is not None:
        cmd += ["--append-system-prompt-file", str(system_file)]
    return cmd


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-")[:60] or "task"


def run_agent(*, settings: dict, secrets: dict[str, str], role: str, prompt: str,
              workdir: Path, log_dir: Path, name: str, max_turns: int | None = None,
              timeout_minutes: float | None = None, add_dirs: Iterable[Path] = (),
              system_append: str | None = None, bare: bool | None = None,
              state=None, phase_id: str | None = None,
              retries: int | None = None, retry_delay: float = 30.0,
              base_env: dict | None = None) -> AgentResult:
    choice = resolve(settings, role)
    # base_env: the scope-proxy environment when the session may reach a
    # target, so whatever the AI sends is scope-checked and logged.
    env = agent_env(choice, secrets, base=base_env)
    agent_cfg = settings["agent"]
    max_turns = int(max_turns or agent_cfg["max_turns"])
    timeout_s = float(timeout_minutes or agent_cfg["timeout_minutes"]) * 60
    retries = int(agent_cfg["retries"] if retries is None else retries)
    bare = bare_enabled(settings) if bare is None else bare

    workdir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = log_dir / f"{stamp}-{_slug(name)}-{role}"
    prompt_file = base.with_suffix(".prompt.md")
    prompt_file.write_text(prompt, encoding="utf-8")
    system_file = None
    if system_append:
        system_file = base.with_suffix(".system.md")
        system_file.write_text(system_append, encoding="utf-8")

    cmd = build_command(choice, max_turns=max_turns, bare=bare,
                        add_dirs=add_dirs, system_file=system_file)

    result: AgentResult | None = None
    for attempt in range(1, retries + 2):
        log_path = base.with_suffix(f".try{attempt}.jsonl")
        result = _run_once(cmd, env, prompt_file, workdir, log_path, timeout_s, choice)
        result.attempts = attempt
        if state is not None:
            state.record_agent_run(
                phase_id=phase_id, role=role, profile=choice.profile_name, model=choice.model,
                ok=int(result.ok), exit_code=result.exit_code, subtype=result.subtype,
                turns=result.turns, cost_usd=result.cost_usd, duration_s=round(result.duration_s, 1),
                session_id=result.session_id, log_path=str(log_path))
        if result.ok or result.fatal or result.subtype in ("error_max_turns", "timeout"):
            break
        if attempt <= retries:
            time.sleep(retry_delay * attempt)

    assert result is not None
    if result.fatal:
        raise AgentFatalError(
            f"{choice.label}: {result.error}. Check the key with: hunt setup, then: hunt doctor")
    return result


def _run_once(cmd: list[str], env: dict[str, str], prompt_file: Path, workdir: Path,
              log_path: Path, timeout_s: float, choice: ModelChoice) -> AgentResult:
    started = time.monotonic()
    stderr_path = log_path.with_suffix(".stderr.log")
    final: dict | None = None
    fatal_error = ""
    timed_out = threading.Event()

    try:
        with prompt_file.open("rb") as stdin, \
                log_path.open("w", encoding="utf-8") as log, \
                stderr_path.open("wb") as err:
            proc = subprocess.Popen(
                cmd, cwd=str(workdir), env=env, stdin=stdin, stdout=subprocess.PIPE,
                stderr=err, text=True, encoding="utf-8", errors="replace",
                start_new_session=True, bufsize=1)

            watchdog = threading.Timer(timeout_s, _stop_group, args=(proc, timed_out))
            watchdog.daemon = True
            watchdog.start()
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    log.write(line)
                    event = _parse(line)
                    if not event:
                        continue
                    if event.get("type") == "result":
                        final = event
                    elif (event.get("type") == "system" and event.get("subtype") == "api_retry"
                          and event.get("error") in FATAL_API_ERRORS and not fatal_error):
                        fatal_error = f"provider error '{event.get('error')}' (HTTP {event.get('error_status')})"
                        _stop_group(proc, None)
                proc.wait()
            except BaseException:
                # Ctrl-C or `hunt stop` reached the orchestrator: the agent runs
                # in its own process group, so stop it explicitly.
                _stop_group(proc, None)
                raise
            finally:
                watchdog.cancel()
    except FileNotFoundError:
        return AgentResult(False, "", "not_installed", None, None, None, None, log_path,
                           time.monotonic() - started, choice.model,
                           error="Claude Code is not installed. Run the installer again.", fatal=True)

    duration = time.monotonic() - started
    exit_code = proc.returncode
    if fatal_error:
        return AgentResult(False, "", "fatal_api_error", exit_code, None, None, None, log_path,
                           duration, choice.model, error=fatal_error, fatal=True)
    if timed_out.is_set():
        return AgentResult(False, (final or {}).get("result", "") or "", "timeout", exit_code,
                           (final or {}).get("num_turns"), (final or {}).get("total_cost_usd"),
                           (final or {}).get("session_id"), log_path, duration, choice.model,
                           error=f"stopped after {int(timeout_s // 60)} minutes (timeout)")
    if final is None:
        tail = _tail(stderr_path)
        return AgentResult(False, "", "no_result", exit_code, None, None, None, log_path, duration,
                           choice.model, error=f"exited with code {exit_code} and no result. {tail}".strip())

    subtype = str(final.get("subtype", ""))
    is_error = bool(final.get("is_error"))
    ok = subtype == "success" and not is_error and exit_code == 0
    text = final.get("result") or ""
    error = "" if ok else (text[:500] if is_error else f"ended with '{subtype}'")
    return AgentResult(ok, text, subtype, exit_code, final.get("num_turns"),
                       final.get("total_cost_usd"), final.get("session_id"), log_path, duration,
                       choice.model, error=error,
                       permission_denials=final.get("permission_denials") or [])


def _parse(line: str) -> dict | None:
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _stop_group(proc: subprocess.Popen, flag: threading.Event | None) -> None:
    """SIGINT first so Claude Code can end its turn, then SIGTERM, then
    SIGKILL. Signals go to the whole process group (tools it started)."""
    if flag is not None:
        flag.set()
    for sig, wait in ((signal.SIGINT, 20), (signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _tail(path: Path, limit: int = 400) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    return data[-limit:].replace("\n", " ")


def smoke_test(settings: dict, secrets: dict[str, str], role: str, workdir: Path,
               bare: bool, timeout_minutes: float = 4) -> AgentResult:
    """Tiny end-to-end check used by `hunt doctor`."""
    return run_agent(
        settings=settings, secrets=secrets, role=role,
        prompt="Reply with exactly the single word READY and nothing else. Do not use any tools.",
        workdir=workdir, log_dir=workdir / "logs", name=f"doctor-{'bare' if bare else 'normal'}",
        max_turns=2, timeout_minutes=timeout_minutes, bare=bare, retries=0)


def check_ready(result: AgentResult) -> bool:
    return result.ok and "READY" in result.text.upper()


__all__ = ["AgentResult", "AgentFatalError", "ConfigError", "run_agent", "smoke_test",
           "check_ready", "bare_enabled", "build_command"]
