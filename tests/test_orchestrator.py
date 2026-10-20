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


def test_default_pipeline_runs_and_is_honest(make_target, settings_secrets, notifier, monkeypatch):
    """The whole AI pipeline runs from one call: intake builds the scope (code
    + the policy-reader AI), then every phase is an AI agent. With a fake agent
    that does nothing, phases reach honest non-PENDING states and the run still
    finishes cleanly end to end."""
    from pathlib import Path
    from hunter.proxy import mitmdump_bin
    if mitmdump_bin() is None:
        pytest.skip("mitmproxy not installed")
    policies = Path(__file__).parent / "policies"
    # Intake reads a real draft; the later AI phases get the fake agent too and
    # simply produce no findings (handoff not written) -> PARTIAL/BLOCKED.
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "draft")
    monkeypatch.setenv("FAKE_CLAUDE_DRAFTS", str(policies / "intigriti_acme.draft.json"))
    settings_secrets[0]["researcher"]["handle"] = "amahrou1"
    settings_secrets[0]["run"]["blocker_wait_minutes"] = 0
    target = make_target(policy=(policies / "intigriti_acme.txt").read_text())
    assert _orch(target, settings_secrets, notifier, all_phases()).run() == EXIT_OK
    state = st.State(target.state_db)
    rows = {r["phase_id"]: r for r in state.phases()}
    assert rows["00-intake"]["status"] == st.DONE
    # Every phase is built now: nothing is left NOT_BUILT or PENDING.
    assert not [pid for pid, r in rows.items() if r["status"] in (st.NOT_BUILT, st.PENDING)]
    assert len(rows) == 18
    assert (target.output / "run_summary.md").exists()
    assert notifier.titles()[0] == "Run started: acme"
    assert "Scope ready" in notifier.titles()
    assert notifier.titles()[-1] == "Run finished: acme"


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
    assert "Scope inputs changed" in notifier.titles()


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


class WritesOutput(Phase):
    """A settled phase whose output is a file that can vanish."""
    id, name, version = "00-intake", "intake", "1"

    def __init__(self, log):
        self.log = log

    def run(self, ctx):
        self.log.append(self.id)
        (ctx.target.output).mkdir(parents=True, exist_ok=True)
        ctx.target.scope_file.write_text('{"in_scope":[]}')
        return PhaseResult(st.DONE, "ok")

    def outputs_present(self, ctx):
        return ctx.target.scope_file.exists()


class NeedsScope(Phase):
    id, name, version = "02-recon", "recon", "1"
    requires = ("00-intake",)

    def __init__(self, log):
        self.log = log

    def run(self, ctx):
        self.log.append(self.id)
        assert ctx.target.scope_file.exists(), "scope.json must exist when recon runs"
        return PhaseResult(st.DONE, "ok")


def test_missing_output_reruns_phase(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    phases = [WritesOutput(log), NeedsScope(log)]
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-intake", "02-recon"]
    assert target.scope_file.exists()
    # Delete the output and run again: intake must rerun (recon already DONE
    # keeps its DB result, but the file is restored and nothing crashes).
    target.scope_file.unlink()
    code = _orch(target, settings_secrets, notifier, phases).run()
    assert code == EXIT_OK
    assert log[2] == "00-intake"            # intake reran first
    assert target.scope_file.exists()       # output restored
    state = st.State(target.state_db)
    assert state.phase("02-recon")["status"] == st.DONE  # dependent not broken


def test_dependent_blocks_if_required_output_gone(make_target, settings_secrets, notifier):
    """If the required phase cannot rebuild its output, the dependent waits
    rather than crashing."""
    target = make_target()
    log = []

    class CannotRebuild(WritesOutput):
        def run(self, ctx):
            self.log.append(self.id)
            return PhaseResult(st.DONE, "ok but writes nothing")

    phases = [CannotRebuild(log), NeedsScope(log)]
    code = _orch(target, settings_secrets, notifier, phases).run()
    assert code == EXIT_OK
    state = st.State(target.state_db)
    assert state.phase("02-recon")["status"] == st.BLOCKED


def test_failed_phase_cleared_on_code_update(make_target, settings_secrets, notifier):
    target = make_target()
    for _ in range(4):  # exhaust attempts on version 1
        _orch(target, settings_secrets, notifier, [Boom()]).run()
    assert st.State(target.state_db).phase("03-boom")["attempts"] == 3
    log = []

    class Fixed(Recorder):
        pass

    fixed = Fixed("03-boom", version="2", log=log)
    _orch(target, settings_secrets, notifier, [fixed]).run()
    assert log == ["03-boom"]
    assert st.State(target.state_db).phase("03-boom")["status"] == st.DONE


def test_until_stops_after_named_phase(make_target, settings_secrets, notifier, monkeypatch):
    target = make_target()
    log = []
    phases = [Recorder("00-intake", log=log), Recorder("02-recon", log=log), Recorder("03-probe", log=log)]
    monkeypatch.setenv("HUNTER_UNTIL", "02-recon")
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-intake", "02-recon"]            # stopped before probe
    state = st.State(target.state_db)
    assert state.phase("03-probe")["status"] == st.PENDING
    # Without --until it continues from where it stopped.
    monkeypatch.delenv("HUNTER_UNTIL")
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-intake", "02-recon", "03-probe"]


# --- in-run retry of a PARTIAL phase while it is still making progress --------
from hunter import assets as A  # noqa: E402


class Progressing(Phase):
    """PARTIAL while it keeps adding hosts, then DONE - like recon on a big
    program that needs several passes."""
    id, name, version = "02-prog", "progressing", "1"

    def __init__(self, log):
        self.log = log

    def run(self, ctx):
        self.log.append("run")
        n = len(self.log)
        if n <= 2:
            ctx.assets().add_host(f"h{n}.example.com", A.IN, "test")
            return PhaseResult(st.PARTIAL, f"added host {n}")
        return PhaseResult(st.DONE, "done")


class StuckPartial(Phase):
    id, name, version = "02-stuck", "stuck", "1"

    def __init__(self, log):
        self.log = log

    def run(self, ctx):
        self.log.append("run")
        return PhaseResult(st.PARTIAL, "no progress")


def test_partial_phase_retried_while_progressing(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    assert _orch(target, settings_secrets, notifier, [Progressing(log)]).run() == EXIT_OK
    assert len(log) == 3                                  # retried in-run until it finished
    assert st.State(target.state_db).phase("02-prog")["status"] == st.DONE


def test_partial_phase_not_retried_without_progress(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    _orch(target, settings_secrets, notifier, [StuckPartial(log)]).run()
    assert len(log) == 1                                  # no inventory growth -> moves on, no spin
    assert st.State(target.state_db).phase("02-stuck")["status"] == st.PARTIAL


def test_clear_phase_blockers_dedupes(tmp_path):
    s = st.State(tmp_path / "s.db")
    s.add_blocker("00-intake", "assets owned by TikTok or its subsidiaries")
    s.add_blocker("00-intake", "assets owned by TikTok (and its subsidiaries)")  # the duplicate-wording bug
    assert len(s.open_blockers()) == 2
    assert s.clear_phase_blockers("00-intake") == 2
    assert s.open_blockers() == []


# --- the validate/disprove/report tail reopens when new findings appear -------
class Producer(Phase):
    def __init__(self, phase_id, log, add, version="1"):
        self.id, self.name, self.version = phase_id, "producer", version
        self.log, self.add = log, add

    def run(self, ctx):
        self.log.append("prod")
        if self.add:
            ctx.assets().add_finding(self.id, "x", status="candidate")
        return PhaseResult(st.DONE, "done")


class Tail(Phase):
    id, name, version = "11-validate", "validate", "1"

    def __init__(self, log):
        self.log = log

    def run(self, ctx):
        self.log.append("val")
        for f in ctx.assets().findings("candidate"):
            ctx.assets().set_finding(f["id"], status="validated")
        return PhaseResult(st.DONE, "done")

    def needs_rerun(self, ctx, store):
        return len(store.findings("candidate")) > 0


def test_tail_reopens_when_new_candidates_appear(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    _orch(target, settings_secrets, notifier, [Producer("08-x", log, add=False), Tail(log)]).run()
    assert log == ["prod", "val"]                       # first run: nothing to validate
    # a re-run of the producer (version bump) now yields a candidate; the
    # already-DONE tail must reopen and validate it in the same pass.
    _orch(target, settings_secrets, notifier,
          [Producer("08-x", log, add=True, version="2"), Tail(log)]).run()
    assert log == ["prod", "val", "prod", "val"]
    rows = st.State(target.state_db).db.execute(
        "select 1 from findings where status='validated'").fetchall()
    assert len(rows) == 1


def test_tail_phase_needs_rerun_signals(make_target, settings_secrets, notifier):
    from hunter.phases.ai_validate import AIValidatePhase
    from hunter.phases.ai_disprove import AIDisprovePhase
    from hunter.phases.ai_report import AIReportPhase
    from hunter.phases.base import Context
    target = make_target()
    state = st.State(target.state_db)
    store = A.Assets(state.db)
    ctx = Context(target, state, settings_secrets[0], settings_secrets[1], notifier)
    assert not AIValidatePhase().needs_rerun(ctx, store)
    store.add_finding("x", "c", status="candidate")
    assert AIValidatePhase().needs_rerun(ctx, store)
    store.add_finding("x", "v", status="validated")
    assert AIDisprovePhase().needs_rerun(ctx, store)
    store.add_finding("x", "f", status="confirmed")
    assert AIReportPhase().needs_rerun(ctx, store)
