"""Run external recon/web tools safely on a small server.

Every run:
- streams stdout to a file line by line (never buffers a big result in RAM);
- has a wall-clock timeout and is stopped as a whole process group;
- can be capped in memory with a soft RLIMIT_AS so one tool cannot swap the
  8 GB box to death;
- records the exact command, exit code and output path so a phase can prove
  what actually ran.

Active tools (those that touch targets) are given the scope-proxy environment
so their traffic is scope-checked, rate-limited and logged. Passive tools run
with the normal environment and reach their data sources directly.
"""

from __future__ import annotations

import json
import os
import resource
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator


@dataclass
class ToolRun:
    tool: str
    cmd: list[str]
    returncode: int | None
    duration_s: float
    stdout_path: Path
    stderr_path: Path
    timed_out: bool = False
    out_lines: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self) -> Iterator[str]:
        if not self.stdout_path.exists():
            return iter(())
        return (line.rstrip("\n") for line in
                self.stdout_path.open(encoding="utf-8", errors="replace") if line.strip())

    def json_lines(self) -> Iterator[dict]:
        for line in self.lines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def tail(self, limit: int = 400) -> str:
        try:
            return self.stderr_path.read_text(encoding="utf-8", errors="replace").strip()[-limit:]
        except OSError:
            return ""


def _preexec(mem_mb: int | None):
    def setup():
        os.setsid()
        if mem_mb:
            soft = mem_mb * 1024 * 1024
            try:
                hard = resource.getrlimit(resource.RLIMIT_AS)[1]
                ceiling = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
                resource.setrlimit(resource.RLIMIT_AS, (ceiling, hard))
            except (ValueError, OSError):
                pass
    return setup


class ToolRunner:
    def __init__(self, work_dir: Path, log_dir: Path, env: dict | None = None,
                 mem_mb: int = 1500, log: Callable[[str], None] = lambda _m: None):
        self.work_dir = work_dir
        self.log_dir = log_dir
        self.env = env
        self.mem_mb = mem_mb
        self.log = log
        work_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)

    def run(self, tool: str, cmd: list[str], *, name: str, timeout_s: float = 1800,
            stdin_lines: Iterable[str] | None = None, env: dict | None = None,
            mem_mb: int | None = None) -> ToolRun:
        stdout_path = self.log_dir / f"{name}.out"
        stderr_path = self.log_dir / f"{name}.err"
        (self.log_dir / f"{name}.cmd").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        started = time.monotonic()
        timed_out = threading.Event()
        use_env = env if env is not None else self.env
        stdin_data = ("\n".join(stdin_lines) + "\n").encode() if stdin_lines is not None else None

        try:
            with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
                proc = subprocess.Popen(
                    cmd, cwd=str(self.work_dir), env=use_env,
                    stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                    stdout=out, stderr=err,
                    preexec_fn=_preexec(mem_mb if mem_mb is not None else self.mem_mb))
                watchdog = threading.Timer(timeout_s, self._stop, args=(proc, timed_out))
                watchdog.daemon = True
                watchdog.start()
                try:
                    if stdin_data is not None:
                        proc.stdin.write(stdin_data)
                        proc.stdin.close()
                    proc.wait()
                finally:
                    watchdog.cancel()
        except FileNotFoundError:
            return ToolRun(tool, cmd, None, 0.0, stdout_path, stderr_path,
                           error=f"{tool} is not installed. Run: hunt tools install")

        duration = time.monotonic() - started
        out_lines = sum(1 for _ in stdout_path.open(encoding="utf-8", errors="replace")) if stdout_path.exists() else 0
        run = ToolRun(tool, cmd, proc.returncode, duration, stdout_path, stderr_path,
                      timed_out=timed_out.is_set(), out_lines=out_lines)
        if timed_out.is_set():
            run.error = f"stopped after {int(timeout_s)}s (timeout)"
        elif proc.returncode != 0:
            run.error = f"exit {proc.returncode}: {run.tail(200)}"
        self.log(f"{tool} {name}: {'ok' if run.ok else run.error or 'done'} "
                 f"({out_lines} lines, {duration:.0f}s)")
        return run

    @staticmethod
    def _stop(proc: subprocess.Popen, flag: threading.Event) -> None:
        flag.set()
        for sig, wait in ((signal.SIGTERM, 8), (signal.SIGKILL, 4)):
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


def chunked(items: list[str], size: int) -> Iterator[list[str]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]
