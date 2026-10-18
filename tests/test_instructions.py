import json

import pytest

from hunter import assets as A
from hunter import cli
from hunter import scope as sc
from hunter import state as st
from hunter.instructions import DONE, PENDING, REFUSED, SKIPPED_SUMMARY, Operator, parse
from hunter.orchestrator import Orchestrator
from hunter.phases import Phase, PhaseResult


@pytest.mark.parametrize("text,expected", [
    ("api.bol.com looks juicy, test it harder", [("focus", "api.bol.com")]),
    ("please add 91.195.1.5 to the list", [("add", "91.195.1.5")]),
    ("focus on *.bol.io", [("focus", "*.bol.io")]),
    ("don't test admin.bol.com it's fragile", [("avoid", "admin.bol.com")]),
    ("please don't forget to test login.bol.com deeper", [("focus", "login.bol.com")]),
    ("skip the javascript phase", [("skip", "06-js")]),
    ("skip phase 6", [("skip", "06-js")]),
    ("skip the js phase on api.bol.com", []),
    ("unskip javascript", [("unskip", "06-js")]),
    ("you can test admin.bol.com again", [("unavoid", "admin.bol.com")]),
    ("the login looks weak, try harder on password reset", []),
    ("account.bol.com registration needs a phone", [("focus", "account.bol.com")]),
    ("avoid https://www.bol.com/checkout", [("avoid", "https://www.bol.com/checkout")]),
    ("note api.bol.com uses graphql", []),
    ("forget 3", [("forget", "3")]),
])
def test_parse(text, expected):
    assert [(a["kind"], a["arg"]) for a in parse(text)] == expected


@pytest.fixture
def scoped(make_target):
    target = make_target()
    scope = sc.Scope(
        in_scope=[sc.parse_asset("*.acme.test"), sc.parse_asset("10.0.0.0/24")],
        out_of_scope=[sc.parse_asset("legacy.acme.test")],
        rules={"effective_rps": 10})
    sc.save(scope, target.scope_file)
    state = st.State(target.state_db)
    yield target, state, Operator(target, state)
    state.close()


def _actions(instruction):
    return [(a["kind"], a["arg"], a["status"]) for a in instruction.actions]


def test_add_ip_in_scope_and_refuse_out_of_scope(scoped):
    target, state, op = scoped
    got = op.submit("please add 10.0.0.7 and 10.9.9.9")
    assert _actions(got) == [("add", "10.0.0.7", DONE), ("add", "10.9.9.9", REFUSED)]
    assert "not allowed" in got.actions[1]["reply"]
    store = A.Assets(state.db)
    assert store.unprobed_hosts() == ["10.0.0.7"]
    assert not state.db.execute("SELECT 1 FROM hosts WHERE host='10.9.9.9'").fetchone()


def test_add_refuses_explicit_out_of_scope_and_ranges(scoped):
    _, _, op = scoped
    assert op.submit("add legacy.acme.test").actions[0]["status"] == REFUSED
    assert op.submit("add 10.0.0.0/24").actions[0]["status"] == REFUSED


def test_add_waits_for_scope_then_applies(make_target):
    target = make_target()
    state = st.State(target.state_db)
    op = Operator(target, state)
    got = op.submit("add 10.0.0.9")
    assert got.actions[0]["status"] == PENDING
    sc.save(sc.Scope(in_scope=[sc.parse_asset("10.0.0.0/24")], rules={"effective_rps": 5}), target.scope_file)
    assert op.apply_pending() and op.get(got.id).actions[0]["status"] == DONE
    state.close()


def test_focus_raises_priority_and_is_shown_to_agents(scoped):
    _, state, op = scoped
    store = A.Assets(state.db)
    store.add_host("api.acme.test", A.IN, "test")
    store.upsert_service("api.acme.test", 443, "https", priority=50)
    got = op.submit("api.acme.test looks juicy, test it harder")
    assert _actions(got) == [("focus", "api.acme.test", DONE)]
    assert store.services()[0]["priority"] == 100
    assert op.is_focus("api.acme.test")
    notes = op.notes_for_agents()
    assert "Focus first on: api.acme.test" in notes and "looks juicy" in notes
    assert op.submit("focus *.other.test").actions[0]["status"] == REFUSED


def test_avoid_is_enforced_by_scope_and_undo(scoped):
    target, _, op = scoped
    assert sc.load(target.scope_file).decide("shop.acme.test").allowed
    op.submit("don't touch shop.acme.test")
    decision = sc.load(target.scope_file).decide("shop.acme.test")
    assert not decision.allowed and decision.reason == "you told it to avoid this"
    # A fresh policy read rewrites scope.json; the avoid list survives it.
    sc.save(sc.load(target.scope_file), target.scope_file)
    assert "shop.acme.test" not in target.scope_file.read_text()
    assert not sc.load(target.scope_file).decide("shop.acme.test").allowed
    op.submit("unavoid shop.acme.test")
    assert sc.load(target.scope_file).decide("shop.acme.test").allowed


def test_skip_protected_phase_refused(scoped):
    _, _, op = scoped
    got = op.submit("skip validation")
    assert got.actions[0]["status"] == REFUSED and "cannot be skipped" in got.actions[0]["reply"]


def test_forget_withdraws_note(scoped):
    _, _, op = scoped
    first = op.submit("the login looks weak")
    op.submit(f"forget {first.id}")
    assert "login looks weak" not in op.notes_for_agents()


class Rec(Phase):
    def __init__(self, phase_id, log, version="1"):
        self.id, self.name, self.version, self.log = phase_id, phase_id, version, log

    def run(self, ctx):
        self.log.append(self.id)
        return PhaseResult(st.DONE, "ok")


def _orch(target, settings_secrets, notifier, phases):
    settings, secrets = settings_secrets
    settings["run"]["blocker_wait_minutes"] = 0
    return Orchestrator(target, settings, secrets, notifier=notifier, phases=phases)


def test_orchestrator_skips_and_unskips_phase(make_target, settings_secrets, notifier):
    target = make_target()
    log = []
    phases = [Rec("00-intake", log), Rec("06-js", log), Rec("07-accounts", log)]
    state = st.State(target.state_db)
    Operator(target, state).submit("skip the javascript phase")
    state.close()
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-intake", "07-accounts"]
    state = st.State(target.state_db)
    assert state.phase("06-js")["summary"] == SKIPPED_SUMMARY
    Operator(target, state).submit("unskip javascript")
    state.close()
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["00-intake", "07-accounts", "06-js"]


def test_added_host_reruns_probe_in_the_same_run(make_target, settings_secrets, notifier):
    """A host added while the run is past probe makes probe run once more,
    before the run finishes, without restarting everything."""
    target = make_target()
    sc.save(sc.Scope(in_scope=[sc.parse_asset("10.0.0.0/24")], rules={"effective_rps": 5}), target.scope_file)
    log = []

    class LaterPhase(Phase):
        id, name, version = "08-authz-logic", "authz", "1"

        def run(self, ctx):
            log.append(self.id)
            if log.count(self.id) == 1:   # operator speaks up while this runs
                Operator(ctx.target, ctx.state).submit("add 10.0.0.42")
            return PhaseResult(st.DONE, "ok")

    phases = [Rec("03-probe", log), LaterPhase()]
    _orch(target, settings_secrets, notifier, phases).run()
    assert log == ["03-probe", "08-authz-logic", "03-probe"]
    assert any("10.0.0.42" in line for line in (target.logs / "run.log").read_text().splitlines())


def test_agent_sessions_get_operator_notes(make_target, settings_secrets, notifier, monkeypatch):
    from hunter.phases import base
    target = make_target()
    seen = {}
    monkeypatch.setattr(base, "run_agent", lambda **kw: seen.update(kw))
    state = st.State(target.state_db)
    Operator(target, state).submit("the password reset looks weak")
    ctx = base.Context(target, state, *settings_secrets, notifier)
    ctx.phase_id = "08-authz-logic"
    ctx.agent("tester", "test it", "t1", system_append="phase rules")
    assert "password reset looks weak" in seen["system_append"]
    assert seen["system_append"].rstrip().endswith("phase rules")
    state.close()


def test_assets_migration_marks_probed(tmp_path):
    import sqlite3
    db = sqlite3.connect(str(tmp_path / "s.db"), isolation_level=None)
    db.row_factory = sqlite3.Row
    db.executescript(A.SCHEMA.replace("    notes TEXT\n", "    notes TEXT\n").replace(
        "CREATE INDEX", "--"))
    # Old layout: no probed column.
    db.execute("DROP TABLE hosts")
    db.execute("CREATE TABLE hosts (host TEXT PRIMARY KEY, scope TEXT NOT NULL, source TEXT, resolved INTEGER "
               "NOT NULL DEFAULT 0, addresses TEXT, cname TEXT, third_party_reason TEXT, takeover_candidate "
               "INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, notes TEXT)")
    for host in ("live.a.test", "dead.a.test"):
        db.execute("INSERT INTO hosts(host, scope, resolved, first_seen, last_seen) VALUES(?, ?, 1, 'x', 'x')",
                   (host, A.IN))
    db.execute("INSERT INTO services(host, port, scheme, url, first_seen, last_seen) "
               "VALUES('live.a.test', 443, 'https', 'https://live.a.test', 'x', 'x')")
    store = A.Assets(db)
    assert store.unprobed_hosts() == ["dead.a.test"]


def test_cli_tell_and_list(make_target, capsys):
    target = make_target()
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.acme.test")], rules={"effective_rps": 5}), target.scope_file)
    assert cli.main(["tell", "acme", "avoid", "admin.acme.test"]) == 0
    out = capsys.readouterr().out
    assert "Saved as message #1" in out and "OK" in out and "unavoid" in out
    assert cli.main(["tell", "acme"]) == 0
    out = capsys.readouterr().out
    assert "Avoid:   admin.acme.test" in out


def test_cli_chat_launches_claude_in_target(make_target, monkeypatch, tmp_path, capsys):
    from hunter import config
    target = make_target()
    secrets = {"GLM_API_KEY": "glm-test-key-123456"}
    monkeypatch.setattr(config, "load_secrets", lambda: secrets)
    fake = tmp_path / "claude"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("HUNTER_CLAUDE_BIN", str(fake))
    seen = {}

    def fake_exec(path, argv, env):
        seen.update(path=path, argv=argv, env=env)
        raise SystemExit(0)

    monkeypatch.setattr(cli.os, "execvpe", fake_exec)
    monkeypatch.setattr(cli.os, "chdir", lambda p: seen.update(cwd=str(p)))
    with pytest.raises(SystemExit):
        cli.main(["chat", "acme"])
    assert seen["cwd"] == str(target.path)
    assert seen["env"]["ANTHROPIC_AUTH_TOKEN"] == "glm-test-key-123456"
    prompt = seen["argv"][seen["argv"].index("--append-system-prompt") + 1]
    assert "hunt tell acme" in prompt and "Do NOT send any request" in prompt
    assert "-p" not in seen["argv"]  # interactive, not headless
