import json
import threading

import pytest

from hunter import state as st
from hunter.agent import AgentFatalError
from hunter.orchestrator import (EXIT_ALREADY_RUNNING, EXIT_CONFIG, EXIT_INVALID_TARGET, EXIT_OK,
                                 Orchestrator, is_running)
from hunter.phases import Phase, PhaseResult, all_phases


class Recorder(Phase):
    def __init__(self, phase_id, status=st.DONE, version="1", log=None):
        self.id, self.name, self.version = phase_id, f"phase {phase_id}", version
        self.status, self.log = status, log if log is not None else []

    def run(self, ctx):
        self.log.append(self.id)
        return PhaseResult(self.status, f"{self.id} ok")


class NeedsAccounts(Phase):
    id, name, version = "07-accounts", "accounts", "1"

    def __init__(self, log):
        self.log = log

    def run(self, ctx):
        self.log.append(self.id)
        if not ctx.target.has_input("test-credentials.txt"):
            ctx.block("Two test accounts", "Create user A and user B", ["test-credentials.txt"])
            return PhaseResult(st.BLOCKED, "waiting for accounts")
        return PhaseResult(st.DONE, "accounts ready")


class Boom(Phase):
    id, name, version = "03-boom", "boom", "1"

    def run(self, ctx):
        raise RuntimeError("tool crashed")


class FatalPhase(Phase):
    id, name, version = "02-fatal", "fatal", "1"

    def run(self, ctx):
        raise AgentFatalError("GLM: provider error 'authentication_failed'")


def _orch(target, settings_secrets, notifier, phases, **kw):
    settings, secrets = settings_secrets
    settings["run"]["blocker_wait_minutes"] = kw.pop("wait", 0)
    return Orchestrator(target, settings, secrets, notifier=notifier, phases=phases, **kw)


def test_default_pipeline_runs_and_is_honest(make_target, settings_secrets, notifier):
    target = make_target()
    assert _orch(target, settings_secrets, notifier, all_phases()).run() == EXIT_OK
    state = st.State(target.state_db)
    rows = {r["phase_id"]: r for r in state.phases()}
    assert rows["00-intake"]["status"] == st.DONE
    assert all(r["status"] == st.NOT_BUILT for pid, r in rows.items() if pid != "00-intake")
    manifest = json.loads((target.output / "inputs" / "manifest.json").read_text())
    assert manifest["policy.txt"]["present"] and not manifest["reports.txt"]["present"]
    assert (target.output / "run_summary.md").exists()
    assert notifier.titles()[0] == "Run started: acme"
    assert notifier.titles()[-1] == "Run finished: acme"
    assert notifier.sent[-1][2] == "warn"  # not-built phases are reported as gaps


def test_resume_skips_finished_and_reruns_updated(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    phases = [Recorder("00-a", log=log), Recorder("01-b", log=log)]
    _orch(target, settings_secrets, notifier, phases).run()
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-a", "01-b"]
    phases[1] = Recorder("01-b", version="2", log=log)
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-a", "01-b", "01-b"]


def test_crashed_phase_does_not_stop_run(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    code = _orch(target, settings_secrets, notifier, [Boom(), Recorder("04-after", log=log)]).run()
    assert code == EXIT_OK
    assert log == ["04-after"]
    state = st.State(target.state_db)
    assert state.phase("03-boom")["status"] == st.FAILED
    assert list((target.logs / "errors").iterdir())
    assert "Phase failed: 03-boom" in notifier.titles()


def test_failed_phase_retried_until_limit(make_target, settings_secrets, notifier):
    target = make_target()
    for _ in range(5):
        _orch(target, settings_secrets, notifier, [Boom()]).run()
    assert st.State(target.state_db).phase("03-boom")["attempts"] == 3


def test_blocker_unresolved_becomes_gap(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    code = _orch(target, settings_secrets, notifier, [NeedsAccounts(log), Recorder("08-next", log=log)]).run()
    assert code == EXIT_OK
    assert log == ["07-accounts", "08-next"]  # the run did not wait in the middle
    state = st.State(target.state_db)
    assert [b["status"] for b in state.blockers()] == ["UNRESOLVED"]
    assert "Blocked: Two test accounts" in notifier.titles()
    summary = json.loads((target.output / "run_summary.json").read_text())
    assert summary["unresolved_blockers"] == ["07-accounts: Two test accounts"]


def test_blocker_resolved_while_waiting(make_target, settings_secrets, notifier):
    target = make_target()
    log = []

    def fake_sleep(_seconds):
        (target.path / "test-credentials.txt").write_text("attacker | a@x.test | pw\nvictim | b@x.test | pw\n")

    code = _orch(target, settings_secrets, notifier, [NeedsAccounts(log)], wait=30, sleep=fake_sleep).run()
    assert code == EXIT_OK
    assert log == ["07-accounts", "07-accounts"]
    state = st.State(target.state_db)
    assert state.phase("07-accounts")["status"] == st.DONE
    assert [b["status"] for b in state.blockers()] == ["RESOLVED"]
    assert "Waiting for your input" in notifier.titles()


def test_blocker_answered_between_runs(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    _orch(target, settings_secrets, notifier, [NeedsAccounts(log)]).run()
    # A blocker left OPEN by a crash is picked up when the file appears.
    state = st.State(target.state_db)
    state.db.execute("UPDATE blockers SET status='OPEN'")
    state.close()
    (target.path / "test-credentials.txt").write_text("attacker | a@x.test | pw\n")
    _orch(target, settings_secrets, notifier, [NeedsAccounts(log)]).run()
    assert st.State(target.state_db).phase("07-accounts")["status"] == st.DONE


def test_policy_change_resets_everything(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    phases = [Recorder("00-a", log=log)]
    _orch(target, settings_secrets, notifier, phases).run()
    (target.path / "policy.txt").write_text("A completely different program policy with a new scope list.")
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-a", "00-a"]
    assert "Policy changed" in notifier.titles()


def test_config_error_stops_run(make_target, settings_secrets, notifier):
    target = make_target()
    code = _orch(target, settings_secrets, notifier, [FatalPhase(), Recorder("03-x")]).run()
    assert code == EXIT_CONFIG
    assert st.State(target.state_db).phase("02-fatal")["status"] == st.PENDING
    assert "Run stopped: configuration problem" in notifier.titles()


def test_invalid_target(make_target, settings_secrets, notifier):
    target = make_target(policy="")
    assert _orch(target, settings_secrets, notifier, []).run() == EXIT_INVALID_TARGET


def test_only_one_run_per_target(make_target, settings_secrets, notifier):
    target = make_target()
    started, release = threading.Event(), threading.Event()

    class Slow(Phase):
        id, name, version = "00-slow", "slow", "1"

        def run(self, ctx):
            started.set()
            release.wait(10)
            return PhaseResult(st.DONE, "ok")

    first = _orch(target, settings_secrets, notifier, [Slow()])
    thread = threading.Thread(target=first.run)
    thread.start()
    started.wait(5)
    assert is_running(target)
    second = _orch(target, settings_secrets, notifier, [Slow()])
    assert second.run() == EXIT_ALREADY_RUNNING
    release.set()
    thread.join(10)
    assert not is_running(target)


def test_interrupted_phase_restarts(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    state = st.State(target.state_db)
    state.ensure_phase("00-a", "a")
    state.start_phase("00-a", "1")  # simulate a crash in the middle of the phase
    state.close()
    _orch(target, settings_secrets, notifier, [Recorder("00-a", log=log)]).run()
    assert log == ["00-a"]
    assert st.State(target.state_db).phase("00-a")["attempts"] == 1


def test_phase_result_rejects_running():
    with pytest.raises(ValueError):
        PhaseResult(st.RUNNING, "x")
