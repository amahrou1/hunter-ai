"""Phase contract.

A phase is a small class with an id, a name, a version and a `run` method.
`run` returns a PhaseResult. It never decides on its own that the whole run
is complete, and it never waits for a human: anything it cannot do right
now becomes a blocker (the operator is notified) and the phase finishes
with BLOCKED or PARTIAL so the next phase can start.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .. import scope as sc
from .. import state as st
from ..agent import AgentResult, run_agent
from ..assets import Assets
from ..notify import Notifier
from ..proxy import ScopeProxy
from ..target import Target
from ..tools import ToolRunner


@dataclass
class PhaseResult:
    status: str
    summary: str
    gaps: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in st.PHASE_STATES or self.status == st.RUNNING:
            raise ValueError(f"A phase cannot finish with status {self.status}")


class Context:
    """Everything a phase may use. Passed in by the orchestrator."""

    def __init__(self, target: Target, state: st.State, settings: dict,
                 secrets: dict[str, str], notifier: Notifier):
        self.target = target
        self.state = state
        self.settings = settings
        self.secrets = secrets
        self.notifier = notifier
        self.phase_id: str | None = None
        self._proxy: ScopeProxy | None = None
        self._scope: sc.Scope | None = None
        self._scope_mtime: tuple = ()

    # Scope and guard -------------------------------------------------------
    def scope(self) -> sc.Scope:
        """The scope written by the intake phase (re-read when it changes)."""
        path = self.target.scope_file
        mtime = sc.stamp(path)
        if self._scope is None or mtime != self._scope_mtime:
            self._scope, self._scope_mtime = sc.load(path), mtime
        return self._scope

    def proxy(self) -> ScopeProxy:
        """The running scope proxy. Every request to a target must go
        through it: pass `proxy().env()` to tools and agents."""
        if self._proxy is None or not self._proxy.running():
            self._proxy = ScopeProxy(self.target.scope_file, self.target.logs, self.settings)
            self._proxy.start()
        return self._proxy

    def close(self) -> None:
        if self._proxy is not None:
            self._proxy.stop()
            self._proxy = None

    # Assets inventory ------------------------------------------------------
    def assets(self) -> Assets:
        """Hosts and services for this run, in the same SQLite file as the
        run state."""
        return Assets(self.state.db)

    def operator(self):
        """The operator's `hunt tell` instructions (focus, avoid, notes)."""
        from ..instructions import Operator
        return Operator(self.target, self.state)

    # Tool runners ----------------------------------------------------------
    def passive_runner(self, mem_mb: int | None = None) -> ToolRunner:
        """For tools that never touch the target (certificate logs, Shodan).
        They reach their data sources directly."""
        assert self.phase_id
        cfg = self.settings.get("tools", {})
        return ToolRunner(self.phase_dir() / "work", self.target.logs / "tools" / self.phase_id,
                          env=None, mem_mb=mem_mb or int(cfg.get("mem_mb", 1500)), log=self.log)

    def active_runner(self, mem_mb: int | None = None) -> ToolRunner:
        """For tools that touch the target. Their traffic goes through the
        scope proxy, so it is scope-checked, rate-limited and logged."""
        assert self.phase_id
        cfg = self.settings.get("tools", {})
        return ToolRunner(self.phase_dir() / "work", self.target.logs / "tools" / self.phase_id,
                          env=self.proxy().env(), mem_mb=mem_mb or int(cfg.get("mem_mb", 1500)), log=self.log)

    # Folders ---------------------------------------------------------------
    def phase_dir(self) -> Path:
        assert self.phase_id, "phase_dir() is only valid inside a phase"
        path = self.target.output / "phases" / self.phase_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, relative: str, data) -> Path:
        path = self.target.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    # Logging ---------------------------------------------------------------
    def log(self, message: str) -> None:
        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] [{self.phase_id or 'run'}] {message}"
        print(line, flush=True)
        self.target.logs.mkdir(parents=True, exist_ok=True)
        with (self.target.logs / "run.log").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def progress(self, step: str, done: int | None = None, total: int | None = None, unit: str = "") -> None:
        """Report what the phase is doing, for `hunt status` (percentage and
        time left). Cheap; call it as often as useful."""
        if self.phase_id:
            self.state.set_progress(self.phase_id, step, done, total, unit)

    def notify(self, title: str, message: str = "", level: str = "info") -> None:
        self.notifier.send(title, message, level, target=self.target.name)

    # Blockers --------------------------------------------------------------
    def block(self, need: str, detail: str = "", watch_files: Iterable[str] = ()) -> int:
        """Record something only the operator can provide. The operator is
        told once on Discord. The run carries on with other work."""
        blocker_id, created = self.state.add_blocker(self.phase_id or "run", need, detail, watch_files)
        if created:
            files = list(watch_files)
            hint = f"\nAdd or update: {', '.join(files)} in {self.target.path}" if files else ""
            self.notify(f"Blocked: {need}", f"{detail}{hint}\nThe run continues with other work.", "warn")
            self.log(f"BLOCKER #{blocker_id}: {need}")
        return blocker_id

    # Agents ----------------------------------------------------------------
    def agent(self, role: str, prompt: str, name: str, **kwargs) -> AgentResult:
        assert self.phase_id
        workdir = kwargs.pop("workdir", None) or (self.phase_dir() / "work")
        if "base_env" not in kwargs and self.target.scope_file.exists():
            # Any request the AI makes to a host goes through the guard.
            kwargs["base_env"] = self.proxy().env()
        notes = self.operator().notes_for_agents()
        if notes:
            extra = kwargs.pop("system_append", None)
            kwargs["system_append"] = notes + ("\n" + extra if extra else "")
        return run_agent(
            settings=self.settings, secrets=self.secrets, role=role, prompt=prompt,
            workdir=workdir, log_dir=self.target.logs / "agents" / self.phase_id,
            name=name, state=self.state, phase_id=self.phase_id, **kwargs)


class Phase:
    id: str = ""
    name: str = ""
    version: str = "1"
    # Build step of the plan in which the real implementation lands.
    build_step: int = 0
    # Phases that must be DONE (or NOT_APPLICABLE) before this one may run.
    # Every phase that touches a target requires 00-intake (scope + guard).
    requires: tuple[str, ...] = ()

    def run(self, ctx: Context) -> PhaseResult:  # pragma: no cover - interface
        raise NotImplementedError

    def outputs_present(self, ctx: Context) -> bool:
        """True if this phase's durable outputs still exist. A settled phase
        whose outputs were deleted (for example scope.json removed by hand)
        is rerun instead of silently leaving a dependent to crash. Default:
        nothing to check."""
        return True

    def needs_rerun(self, ctx: Context, store) -> bool:
        """A phase that is already DONE but should run again because new work
        arrived for it - e.g. validation when fresh candidate findings exist.
        Lets the validate -> disprove -> report tail pick up findings produced
        by later testing phases on a resumed run, instead of staying stale.
        Default: no."""
        return False

    def progress_metric(self, ctx: Context):
        """A number the orchestrator compares between PARTIAL attempts to decide
        whether the phase is still advancing (and worth another pass). Return
        None to use the default (total inventory rows). A phase whose real
        progress is NOT 'new rows added' overrides this - e.g. probe returns how
        many hosts it has probed, so a pass that probes many dead hosts (adding
        few service rows) still counts as progress."""
        return None


class PlannedPhase(Phase):
    """Placeholder for a phase that is designed but not built yet. It says
    so honestly instead of pretending the work was done."""

    version = "0"

    def __init__(self, phase_id: str, name: str, build_step: int):
        self.id = phase_id
        self.name = name
        self.build_step = build_step

    def run(self, ctx: Context) -> PhaseResult:
        return PhaseResult(st.NOT_BUILT, f"Not built yet (arrives in build step {self.build_step}).")
