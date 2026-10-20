"""The orchestrator: runs the phases of one target from start to end.

- One run per target at a time (file lock).
- Resumes after a crash, reboot or `hunt stop`: finished phases are skipped,
  a phase that was cut off starts again.
- Never waits for a human in the middle. Blockers are announced on Discord,
  the remaining phases run, and only at the very end does the run wait a
  limited time for the operator to add missing inputs. If they arrive, the
  affected phases run again; if not, the blockers are listed as gaps.
- A phase whose code version changed (after `hunt update`) runs again.
"""

from __future__ import annotations

import datetime as _dt
import fcntl
import json
import os
import signal
import threading
import time
import traceback
import uuid
from collections import Counter
from pathlib import Path
from typing import Callable

from . import state as st
from .agent import AgentFatalError
from .config import ConfigError
from .models import resolve
from .notify import Notifier
from .phases import Context, Phase, PhaseResult, all_phases
from .instructions import SKIPPED_SUMMARY, Operator
from .target import SCOPE_INPUTS, Target

EXIT_OK = 0
EXIT_INVALID_TARGET = 2
EXIT_ALREADY_RUNNING = 3
EXIT_CONFIG = 4
EXIT_STOPPED = 130


class _Stop(Exception):
    pass


class Orchestrator:
    def __init__(self, target: Target, settings: dict, secrets: dict[str, str],
                 notifier: Notifier | None = None, phases: list[Phase] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.target = target
        self.settings = settings
        self.secrets = secrets
        self.notifier = notifier or Notifier(secrets, settings["notify"].get("discord", True))
        self.phases = phases if phases is not None else all_phases()
        self.sleep = sleep
        self.clock = clock
        self.state: st.State | None = None
        self.ctx: Context | None = None
        self.ran: set[str] = set()
        self._rerun_due = False
        import os as _os
        self._until = (_os.environ.get("HUNTER_UNTIL") or "").strip()
        self._lock_handle = None

    # ------------------------------------------------------------------ main
    def run(self) -> int:
        problems = self.target.validate()
        if problems:
            for problem in problems:
                print(f"ERROR: {problem}")
            return EXIT_INVALID_TARGET

        self.target.output.mkdir(parents=True, exist_ok=True)
        if not self._acquire_lock():
            print(f"A run for '{self.target.name}' is already active. Watch it with: hunt watch {self.target.name}")
            return EXIT_ALREADY_RUNNING

        previous = {}
        started = self.clock()
        try:
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGTERM, signal.SIGHUP):
                    previous[sig] = signal.signal(sig, self._on_signal)
            self.state = st.State(self.target.state_db)
            self.ctx = Context(self.target, self.state, self.settings, self.secrets, self.notifier)
            self._prepare()
            self._announce_start()
            while True:
                self._pass()
                if self._until:
                    break  # a phase-by-phase run stops at its boundary, never waits on blockers
                self._operator_sync()
                if self._rerun_due:
                    self._rerun_due = False
                    continue  # the operator asked for a phase to run again
                open_blockers = self.state.open_blockers()
                if not open_blockers or not self._wait_for_inputs(open_blockers):
                    break
            self._finish(self.clock() - started)
            return EXIT_OK
        except (KeyboardInterrupt, _Stop):
            if self.state:
                self.state.interrupt_running("stopped by operator or system")
                self.state.event("run_stopped", None, "stopped")
            self._log("Run stopped. Start it again with: hunt start " + self.target.name)
            self.notifier.send("Run stopped", f"Resume any time with: hunt start {self.target.name}",
                               "warn", target=self.target.name)
            return EXIT_STOPPED
        except (AgentFatalError, ConfigError) as exc:
            if self.state:
                self.state.interrupt_running(f"configuration error: {exc}")
            self._log(f"STOPPED: {exc}")
            self.notifier.send("Run stopped: configuration problem", str(exc), "error", target=self.target.name)
            return EXIT_CONFIG
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            if self.ctx is not None:
                self.ctx.close()
            if self.state:
                self.state.close()
            self._release_lock()

    # ------------------------------------------------------------- startup
    def _prepare(self) -> None:
        assert self.state is not None
        cut_off = self.state.interrupt_running("previous run ended unexpectedly")
        if cut_off:
            self._log(f"Resuming. Phases cut off last time will start again: {', '.join(cut_off)}")
        if not self.state.get_meta("run_id"):
            self.state.set_meta("run_id", uuid.uuid4().hex[:12])
            self.state.set_meta("created_at", st.now())
        self.state.set_meta("invocations", str(int(self.state.get_meta("invocations", "0")) + 1))
        self.state.set_meta("last_started_at", st.now())

        for phase in self.phases:
            self.state.ensure_phase(phase.id, phase.name)
        removed = self.state.prune_phases([p.id for p in self.phases])
        if removed:
            self._log(f"removed {len(removed)} phase(s) no longer in the pipeline: {', '.join(removed)}")

        current = self.target.fingerprints()
        stored_raw = self.state.get_meta("input_fingerprints")
        if stored_raw:
            stored = json.loads(stored_raw)
            changed_scope = [name for name in SCOPE_INPUTS if stored.get(name) != current.get(name)]
            if changed_scope:
                self._log(f"{', '.join(changed_scope)} changed since the last run: every phase will run again.")
                self.notifier.send("Scope inputs changed", f"{', '.join(changed_scope)} changed since the last run. "
                                   "All phases will run again under the new scope.", "warn",
                                   target=self.target.name)
                for row in self.state.phases():
                    self.state.reset_phase(row["phase_id"], "policy changed", reset_attempts=True)
            else:
                changed = {name for name in current if current[name] != stored.get(name)}
                if changed:
                    self._resolve_blockers_for(changed)
        self.state.set_meta("input_fingerprints", json.dumps(current, sort_keys=True))

    def _announce_start(self) -> None:
        assert self.state is not None
        try:
            model = resolve(self.settings, "tester").label
        except ConfigError:
            model = "(model profile not configured)"
        rows = self.state.phases()
        done = sum(1 for r in rows if r["status"] in st.SETTLED)
        invocation = self.state.get_meta("invocations", "1")
        message = (f"Target folder: {self.target.path}\nModel: {model}\n"
                   f"Phases already finished: {done} of {len(rows)}\nStart number: {invocation}")
        self._log(f"Run started for {self.target.name}. {done}/{len(rows)} phases already finished.")
        self.notifier.send(f"Run started: {self.target.name}", message, "info", target=self.target.name)

    # --------------------------------------------------------------- phases
    def _outputs_ok(self, phase: Phase, row) -> bool:
        if row["status"] not in st.SETTLED:
            return True
        try:
            return phase.outputs_present(self.ctx)
        except Exception:
            return True

    def _should_run(self, phase: Phase, row) -> bool:
        if phase.id in self.ran:
            return False
        if row["status"] in st.SETTLED and row["version"] == phase.version:
            return False
        max_attempts = int(self.settings["run"]["max_phase_attempts"])
        if row["status"] == st.FAILED and row["version"] == phase.version and row["attempts"] >= max_attempts:
            return False
        return True

    def _pass(self) -> None:
        assert self.state is not None and self.ctx is not None
        for phase in self.phases:
            self._operator_sync()
            row = self.state.phase(phase.id)
            if phase.id in self._operator().skipped():
                if row["status"] not in (*st.SETTLED, st.RUNNING):
                    self.state.finish_phase(phase.id, st.NOT_APPLICABLE, SKIPPED_SUMMARY)
                    self._log(f"--- {phase.id}: skipped on your instruction")
                self.ran.add(phase.id)
                continue
            # A new build may fix whatever made a phase settle or fail on the old
            # code, so a version bump clears SETTLED and FAILED phases alike and
            # gives them their attempts back.
            if row["status"] in (*st.SETTLED, st.FAILED) and row["version"] != phase.version:
                self.state.reset_phase(phase.id, f"code updated {row['version']} -> {phase.version}",
                                       reset_attempts=True)
                row = self.state.phase(phase.id)
            if not self._outputs_ok(phase, row):
                self.state.reset_phase(phase.id, "its output files are missing; running it again",
                                       reset_attempts=True)
                self.ran.discard(phase.id)
                row = self.state.phase(phase.id)
            # A DONE phase with fresh work to do (the validate->disprove->report
            # tail when new findings exist) reopens so unattended runs do not
            # leave findings unprocessed.
            if (row["status"] in st.SETTLED and row["version"] == phase.version
                    and phase.id not in self.ran):
                try:
                    if phase.needs_rerun(self.ctx, self.ctx.assets()):
                        self.state.reset_phase(phase.id, "new findings to process", reset_attempts=True)
                        self.ran.discard(phase.id)
                        row = self.state.phase(phase.id)
                except Exception:
                    pass
            if not self._should_run(phase, row):
                if self._until and phase.id == self._until:
                    return  # already settled; stop here for a phase-by-phase run
                continue
            self._run_phase(phase)
            if self._until and phase.id == self._until:
                self._log(f"Stopping after {phase.id} (--until). Continue with: hunt start {self.target.name}")
                return

    def _operator(self) -> Operator:
        assert self.state is not None
        return Operator(self.target, self.state)

    def _operator_sync(self) -> bool:
        """Pick up `hunt tell` messages: log new ones, apply actions that were
        waiting, and queue phases the operator needs to run again (sets
        _rerun_due, which the main loop clears). Returns True if a phase was
        queued by this call."""
        operator = self._operator()
        for message in operator.unseen():
            self._log(f"[you] #{message.id}: {message.text}")
        for line in operator.apply_pending():
            self._log(f"[you] {line}")
        again = False
        for phase_id in operator.pop_reruns():
            if phase_id in operator.skipped():
                continue
            self.state.reset_phase(phase_id, "operator instruction", reset_attempts=True)
            self.ran.discard(phase_id)
            self._log(f"[you] {phase_id} will run again for your instruction")
            again = True
        if again:
            self._rerun_due = True
        return again

    def _unmet_requirements(self, phase: Phase) -> list[str]:
        assert self.state is not None
        unmet = []
        by_id = {p.id: p for p in self.phases}
        for required in getattr(phase, "requires", ()):
            row = self.state.phase(required)
            req_phase = by_id.get(required)
            if row is None or row["status"] not in st.SETTLED:
                unmet.append(required)
            elif req_phase is not None and not self._outputs_ok(req_phase, row):
                unmet.append(required)
        return unmet

    def _progress_count(self) -> int:
        """A cheap fingerprint of how much the inventory holds. If a PARTIAL
        phase increased it, the phase is still making progress and is worth
        continuing (recon on a huge program needs several passes)."""
        assert self.state is not None
        total = 0
        for table in ("hosts", "services", "endpoints", "leads", "findings"):
            try:
                total += self.state.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            except Exception:
                pass
        return total

    def _run_phase(self, phase: Phase) -> None:
        assert self.state is not None and self.ctx is not None
        unmet = self._unmet_requirements(phase)
        if unmet:
            self.ran.add(phase.id)
            self.state.finish_phase(phase.id, st.BLOCKED, f"waiting for {', '.join(unmet)}")
            self._log(f"--- {phase.id}: skipped, waiting for {', '.join(unmet)}")
            return
        self.ran.add(phase.id)
        # A re-run re-raises its own blockers; close the old ones first so they
        # do not pile up as duplicates across runs.
        self.state.clear_phase_blockers(phase.id)
        self._log(f"--- {phase.id}: {phase.name}")
        # Keep working a PARTIAL phase in the same run while it still adds to the
        # inventory, so a big phase (recon on a huge program) finishes instead of
        # stranding everything that depends on it. Bounded by a hard cap and by
        # "no new progress", and never loops on a phase waiting for the operator.
        hard_cap = 12
        for attempt in range(1, hard_cap + 1):
            self.ctx.phase_id = phase.id
            before = self._progress_count()
            self.state.start_phase(phase.id, phase.version)
            started = self.clock()
            try:
                result = phase.run(self.ctx)
                if not isinstance(result, PhaseResult):
                    raise TypeError(f"{phase.id} returned {type(result).__name__}, expected PhaseResult")
            except (KeyboardInterrupt, _Stop, AgentFatalError, ConfigError):
                raise
            except Exception as exc:  # a bug or tool crash in one phase must not end the run
                trace = traceback.format_exc()
                self._write_trace(phase.id, trace)
                result = PhaseResult(st.FAILED, f"{type(exc).__name__}: {exc}")
                self.notifier.send(f"Phase failed: {phase.id}",
                                   f"{type(exc).__name__}: {exc}\nThe run continues with the next phase. "
                                   f"Details: {self.target.logs / 'errors'}", "error", target=self.target.name)
            finally:
                self.ctx.phase_id = None
            self.state.finish_phase(phase.id, result.status, result.summary)
            minutes = (self.clock() - started) / 60
            self._log(f"    {phase.id} -> {result.status} ({minutes:.1f} min): {result.summary}")
            if result.status != st.PARTIAL:
                return
            if any(b["phase_id"] == phase.id for b in self.state.open_blockers()):
                return  # needs the operator; the end-of-run blocker wait handles it
            after = self._progress_count()
            if after <= before:
                return  # partial and not advancing: stop, do not spin
            if attempt < hard_cap:
                self._log(f"    {phase.id}: partial but still finding things ({before} -> {after}); continuing")

    def _write_trace(self, phase_id: str, trace: str) -> None:
        folder = self.target.logs / "errors"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        (folder / f"{stamp}-{phase_id}.txt").write_text(trace, encoding="utf-8")

    # ------------------------------------------------------------- blockers
    def _resolve_blockers_for(self, changed_files: set[str]) -> bool:
        assert self.state is not None
        reopened = False
        for blocker in self.state.open_blockers():
            watched = set(json.loads(blocker["watch_files"] or "[]"))
            if watched & changed_files:
                self.state.close_blocker(blocker["id"], "RESOLVED")
                self.state.reset_phase(blocker["phase_id"], "input added: " + ", ".join(sorted(watched & changed_files)),
                                       reset_attempts=True)
                self.ran.discard(blocker["phase_id"])
                self._log(f"Blocker #{blocker['id']} answered ({', '.join(sorted(watched & changed_files))}). "
                          f"{blocker['phase_id']} will run again.")
                reopened = True
        return reopened

    def _wait_for_inputs(self, open_blockers) -> bool:
        """Wait a limited time for the operator to add missing inputs.
        Returns True if something changed and phases must run again. Only
        blockers that a file in the target folder can resolve are worth
        waiting for; a blocker with no watched file (for example a missing
        tool) is reported and the run finishes instead of waiting."""
        assert self.state is not None
        file_backed = [b for b in open_blockers if json.loads(b["watch_files"] or "[]")]
        if not file_backed:
            needs = "\n".join(f"- {b['need']} ({b['phase_id']})" for b in open_blockers)
            self._log("Open blockers cannot be resolved by adding a file; finishing and listing them as gaps.")
            self.notifier.send("Finished with open blockers",
                               f"These need action on the server, not a file:\n{needs}", "warn",
                               target=self.target.name)
            for blocker in open_blockers:
                self.state.close_blocker(blocker["id"], "UNRESOLVED")
            return False
        open_blockers = file_backed
        import os
        wait_minutes = float(os.environ.get("HUNTER_BLOCKER_WAIT_MINUTES",
                                             self.settings["run"]["blocker_wait_minutes"]))
        poll = max(5.0, float(self.settings["run"]["poll_seconds"]))
        needs = "\n".join(f"- {b['need']} ({b['phase_id']})" for b in open_blockers)
        if wait_minutes > 0:
            self._log(f"All runnable work is done. Waiting up to {wait_minutes:.0f} minutes for blocked items.")
            self.notifier.send(
                "Waiting for your input",
                f"Everything else is finished. These items are still blocked:\n{needs}\n\n"
                f"Add the missing files in {self.target.path} within {wait_minutes:.0f} minutes and the run "
                f"continues by itself. Otherwise they are listed as gaps.", "warn", target=self.target.name)
        deadline = self.clock() + wait_minutes * 60
        baseline = self.target.fingerprints()
        while self.clock() < deadline:
            self.sleep(min(poll, max(0.0, deadline - self.clock())))
            self._operator_sync()
            if self._rerun_due:
                self._rerun_due = False
                return True
            current = self.target.fingerprints()
            changed = {name for name in current if current[name] != baseline.get(name)}
            if changed:
                self.state.set_meta("input_fingerprints", json.dumps(current, sort_keys=True))
                if changed & set(SCOPE_INPUTS):
                    self._log(f"{', '.join(sorted(changed))} changed: re-reading the scope and running again.")
                    for row in self.state.phases():
                        self.state.reset_phase(row["phase_id"], "scope inputs changed", reset_attempts=True)
                    for blocker in self.state.open_blockers():
                        self.state.close_blocker(blocker["id"], "RESOLVED")
                    self.ran.clear()
                    return True
                if self._resolve_blockers_for(changed):
                    return True
                baseline = current
        for blocker in self.state.open_blockers():
            self.state.close_blocker(blocker["id"], "UNRESOLVED")
        return False

    # --------------------------------------------------------------- finish
    def _finish(self, seconds: float) -> None:
        assert self.state is not None
        rows = self.state.phases()
        counts = Counter(r["status"] for r in rows)
        gaps = [f"{r['phase_id']}: {r['status']} - {r['summary'] or ''}" for r in rows
                if r["status"] not in st.SETTLED]
        unresolved = [f"{b['phase_id']}: {b['need']}" for b in self.state.blockers() if b["status"] == "UNRESOLVED"]
        totals = self.state.agent_totals()
        summary = {
            "target": self.target.name,
            "run_id": self.state.get_meta("run_id"),
            "finished_at": st.now(),
            "duration_minutes": round(seconds / 60, 1),
            "phase_counts": dict(counts),
            "gaps": gaps,
            "unresolved_blockers": unresolved,
            "agent_runs": totals,
        }
        (self.target.output / "run_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        (self.target.output / "run_summary.md").write_text(render_summary(self.target, self.state), encoding="utf-8")
        self.state.set_meta("last_finished_at", st.now())
        self.state.event("run_finished", None, json.dumps(dict(counts)))

        status_line = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
        message = (f"Duration: {seconds / 60:.0f} min\nPhases: {status_line}\n"
                   f"Open gaps: {len(gaps)}\nUnresolved blockers: {len(unresolved)}\n"
                   f"Summary: {self.target.output / 'run_summary.md'}")
        level = "success" if not gaps else "warn"
        self._log(f"Run finished. {status_line}")
        self.notifier.send(f"Run finished: {self.target.name}", message, level, target=self.target.name)

    # ---------------------------------------------------------------- utils
    def _log(self, message: str) -> None:
        if self.ctx is not None:
            saved = self.ctx.phase_id
            self.ctx.phase_id = None
            self.ctx.log(message)
            self.ctx.phase_id = saved
        else:
            print(message, flush=True)

    def _on_signal(self, signum, _frame) -> None:
        raise _Stop(signal.Signals(signum).name)

    def _acquire_lock(self) -> bool:
        path = self.target.output / ".lock"
        handle = path.open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return False
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        self._lock_handle = handle
        return True

    def _release_lock(self) -> None:
        if self._lock_handle is not None:
            try:
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock_handle.close()
                self._lock_handle = None


def is_running(target: Target) -> bool:
    path = target.output / ".lock"
    if not path.exists():
        return False
    with path.open("a+") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return False


def render_summary(target: Target, state: st.State) -> str:
    lines = [f"# Run summary: {target.name}", "",
             f"- Run id: {state.get_meta('run_id')}",
             f"- Last started: {state.get_meta('last_started_at')}",
             f"- Last finished: {state.get_meta('last_finished_at') or '(not finished)'}", "",
             "## Phases", "", "| Phase | Status | Attempts | Summary |", "|---|---|---|---|"]
    for row in state.phases():
        summary = (row["summary"] or "").replace("|", "/").replace("\n", " ")
        lines.append(f"| {row['phase_id']} {row['name']} | {row['status']} | {row['attempts']} | {summary} |")
    blockers = state.blockers()
    lines += ["", "## Blockers", ""]
    if not blockers:
        lines.append("None.")
    for b in blockers:
        lines.append(f"- #{b['id']} [{b['status']}] {b['phase_id']}: {b['need']}. {b['detail'] or ''}")
    totals = state.agent_totals()
    lines += ["", "## AI usage", "", f"- Agent sessions: {totals['runs']} ({totals['ok']} succeeded)",
              f"- Estimated cost reported by the CLI: {totals['cost']:.2f} USD", ""]
    return "\n".join(lines)
