import json

from hunter import cli, config, doctor, paths, target as target_mod
from hunter.setup_wizard import run_setup

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/" + "x" * 68


class StubNotifier:
    sent = []

    def __init__(self, secrets):
        self.secrets = secrets

    def send(self, *args, **kwargs):
        StubNotifier.sent.append(args)
        return True


def _scripted(answers):
    answers = list(answers)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return answers.pop(0)
    return ask, prompts


def test_setup_saves_keys_and_validates(env):
    probes = []

    def probe(profile, key):
        probes.append((profile["key_name"], key))
        return (key != "bad-key-12345", "the key works" if key != "bad-key-12345" else "rejected")

    visible, _ = _scripted(["not a url", WEBHOOK, "n", "n"])
    hidden, _ = _scripted(["bad-key-12345", " 'glm-good-key-1234' ", "", ""])
    out = []
    code = run_setup(input_fn=visible, secret_fn=hidden, out=out.append,
                     probe_fn=probe, notifier_factory=StubNotifier)
    assert code == 0
    secrets = config.load_secrets()
    assert secrets["DISCORD_WEBHOOK_URL"] == WEBHOOK
    assert secrets["GLM_API_KEY"] == "glm-good-key-1234"
    assert "DEEPSEEK_API_KEY" not in secrets
    assert ("GLM_API_KEY", "bad-key-12345") in probes
    assert any("does not look like a Discord webhook" in line for line in out)


def test_setup_keeps_existing_values(env):
    config.save_secrets({"DISCORD_WEBHOOK_URL": WEBHOOK, "GLM_API_KEY": "glm-existing-123"})
    visible, _ = _scripted(["", "n"])
    hidden, _ = _scripted(["", "", ""])
    code = run_setup(input_fn=visible, secret_fn=hidden, out=lambda _l: None,
                     probe_fn=lambda p, k: (True, "ok"), notifier_factory=StubNotifier)
    assert code == 0
    assert config.load_secrets()["GLM_API_KEY"] == "glm-existing-123"


def test_cli_new_creates_templates(env, capsys):
    assert cli.main(["new", "acme"]) == 0
    folder = env["targets"] / "acme"
    assert (folder / "policy.txt").exists()
    t = target_mod.Target(folder)
    assert t.validate()  # template only -> still invalid
    assert "nano" in capsys.readouterr().out


def test_cli_rejects_bad_name(env, capsys):
    assert cli.main(["new", "../etc"]) == 1
    assert "not a valid target name" in capsys.readouterr().out


def test_cli_models_switch(env, capsys):
    assert cli.main(["models", "use", "deepseek"]) == 0
    assert config.load_settings()["active_profile"] == "deepseek"
    assert "no DEEPSEEK_API_KEY saved" in capsys.readouterr().out
    assert cli.main(["models", "role", "disprover", "claude"]) == 0
    assert config.load_settings()["roles"]["disprover"] == "claude:max"
    assert cli.main(["models", "role", "disprover", "nope:max"]) == 1
    assert cli.main(["models"]) == 0


def test_cli_run_and_status(env, make_target, capsys, monkeypatch):
    from pathlib import Path
    policies = Path(__file__).parent / "policies"
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "draft")
    monkeypatch.setenv("FAKE_CLAUDE_DRAFTS", str(policies / "intigriti_acme.draft.json"))
    monkeypatch.setenv("HUNTER_BLOCKER_WAIT_MINUTES", "0")  # do not wait for inputs in the test
    make_target(policy=(policies / "intigriti_acme.txt").read_text())
    assert cli.main(["handle", "amahrou1"]) == 0
    config.save_secrets({"GLM_API_KEY": "glm-test-1234567"})  # no webhook -> notifier only logs
    rc = cli.main(["run", "acme"])
    assert rc == 0
    capsys.readouterr()
    assert cli.main(["status", "acme"]) == 0
    out = capsys.readouterr().out
    assert "00-intake" in out and "phases finished" in out
    assert cli.main(["status"]) == 0
    assert "1/16 phases finished" in capsys.readouterr().out
    assert cli.main(["scope", "acme", "check", "https://app.acme-test.com/x"]) == 0
    assert "ALLOWED" in capsys.readouterr().out
    assert cli.main(["scope", "acme", "check", "https://status.acme-test.io/"]) == 3
    assert "BLOCKED" in capsys.readouterr().out
    assert cli.main(["scope", "acme"]) == 0
    assert "## In scope" in capsys.readouterr().out


def test_cli_help_and_unknown(env, capsys):
    assert cli.main([]) == 0
    assert "hunt setup" in capsys.readouterr().out
    assert cli.main(["frobnicate"]) == 2


def test_doctor_secrets_and_agents(env):
    config.save_secrets({"DISCORD_WEBHOOK_URL": WEBHOOK, "GLM_API_KEY": "glm-test-1234567"})
    settings = config.load_settings()
    report = doctor.Report(lambda _l: None)
    doctor.check_secrets(report, settings, config.load_secrets(), send_test=False,
                         probe_fn=lambda p, k: (True, "the key works"))
    assert not report.failed
    doctor.check_agents(report, settings, config.load_secrets())
    assert not report.failed
    assert config.load_settings()["detected"]["bare_ok"] is True


def test_doctor_falls_back_to_normal_mode(env, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "barefail")
    config.save_secrets({"GLM_API_KEY": "glm-test-1234567"})
    settings = config.load_settings()
    settings["agent"]["retries"] = 0
    report = doctor.Report(lambda _l: None)
    doctor.check_agents(report, settings, config.load_secrets())
    assert not report.failed
    assert config.load_settings()["detected"]["bare_ok"] is False


def test_doctor_reports_missing_key(env):
    config.save_secrets({"DISCORD_WEBHOOK_URL": WEBHOOK})
    report = doctor.Report(lambda _l: None)
    doctor.check_secrets(report, config.load_settings(), config.load_secrets(), send_test=False,
                         probe_fn=lambda p, k: (True, "ok"))
    assert report.failed
    assert any("GLM_API_KEY" in detail for _, _, detail in report.results)


def test_doctor_system_checks_run(env):
    report = doctor.Report(lambda _l: None)
    doctor.check_system(report)
    names = [name for _, name, _ in report.results]
    assert "Claude Code" in names and "Python" in names


def test_cli_handle(env, capsys):
    assert cli.main(["handle"]) == 0
    assert "(not set)" in capsys.readouterr().out
    assert cli.main(["handle", "bad name"]) == 1
    assert cli.main(["handle", "amahrou1"]) == 0
    assert config.load_settings()["researcher"]["handle"] == "amahrou1"


def test_doctor_proxy_check(env):
    from hunter.proxy import mitmdump_bin
    if mitmdump_bin() is None:
        return
    report = doctor.Report(lambda _l: None)
    doctor.check_proxy(report, config.load_settings())
    assert not report.failed, report.results


def test_cli_reset_clears_stuck_phase(env, capsys):
    from hunter import state as st
    assert cli.main(["new", "acme"]) == 0
    t = target_mod.Target(env["targets"] / "acme")
    state = st.State(t.state_db)
    for pid in ("00-intake", "02-recon"):
        state.ensure_phase(pid, pid)
    state.start_phase("02-recon", "1.0")
    state.finish_phase("02-recon", st.FAILED, "FileNotFoundError")
    state.db.execute("UPDATE phases SET attempts=3 WHERE phase_id='02-recon'")
    state.close()

    assert cli.main(["reset", "acme", "02-nope"]) == 1
    assert cli.main(["reset", "acme", "02-recon"]) == 0
    row = st.State(t.state_db).phase("02-recon")
    assert row["status"] == st.PENDING and row["attempts"] == 0
    assert "hunt start acme" in capsys.readouterr().out


def test_cli_start_replaces_leftover_window(env, capsys, monkeypatch, tmp_path):
    """A window left at the 'press Enter' prompt must not swallow the new run."""
    import shutil
    import subprocess
    import time
    import pytest
    if not shutil.which("tmux"):
        pytest.skip("tmux not installed")
    marker = tmp_path / "ran.txt"
    fake = tmp_path / "fake-hunt"
    fake.write_text(f"#!/bin/sh\necho \"$@\" >> {marker}\n")
    fake.chmod(0o755)
    monkeypatch.setattr(cli, "HUNT", str(fake))
    monkeypatch.setenv("TMUX_TMPDIR", str(tmp_path))  # private tmux server
    folder = env["targets"] / "acme"
    folder.mkdir(parents=True)
    (folder / "policy.txt").write_text("Acme bug bounty. In scope: *.acme.test. Out of scope: none. " * 3)
    t = target_mod.Target(folder)
    session = t.tmux_session()
    # The leftover: a finished run sitting at its "press Enter" prompt.
    subprocess.run(["tmux", "new-session", "-d", "-s", session, "bash", "-c", "read _"], check=True)
    try:
        assert cli.main(["start", "acme"]) == 0
        for _ in range(50):
            if marker.exists():
                break
            time.sleep(0.1)
        assert marker.exists(), "the new run never started"
        assert "run" in marker.read_text()
        assert cli._tmux_has(session)  # fresh window still open for hunt watch
    finally:
        subprocess.run(["tmux", "kill-server"], capture_output=True)


def test_cli_findings_lists_and_points_to_reports(env, make_target, capsys):
    from hunter import assets as A
    from hunter import state as st
    make_target("acme")
    t = target_mod.Target(env["targets"] / "acme")
    t.output.mkdir(parents=True, exist_ok=True)
    state = st.State(t.state_db)
    store = A.Assets(state.db)
    store.add_finding("08-authz", "IDOR on /api/orders", kind="idor", severity="high",
                      url="https://acme.test/api/orders/1", status="confirmed")
    store.add_finding("10-misconfig", "Verbose error", kind="info-leak", severity="low", status="confirmed")
    state.close()
    (t.output / "reports").mkdir()
    (t.output / "reports" / "1-idor.md").write_text("# IDOR\n")
    assert cli.main(["findings", "acme"]) == 0
    out = capsys.readouterr().out
    assert "IDOR on /api/orders" in out and "high" in out
    assert out.index("high") < out.index("low")        # sorted by severity
    assert "1-idor.md" in out


def test_cli_leads_groups_by_kind(env, make_target, capsys):
    from hunter import assets as A
    from hunter import state as st
    make_target("acme")
    t = target_mod.Target(env["targets"] / "acme")
    t.output.mkdir(parents=True, exist_ok=True)
    state = st.State(t.state_db)
    store = A.Assets(state.db)
    store.add_lead("exposed-service", "tcp://10.0.0.2:6379", "03-probe", "Redis answers PING", "signature-match")
    store.add_lead("takeover", "https://events.acme.test/", "02-recon", "CNAME dangling", "signature-match")
    store.add_lead("api-docs", "https://acme.test/swagger.json", "05-discover", "OpenAPI doc", "signature-match")
    state.close()
    assert cli.main(["leads", "acme"]) == 0
    out = capsys.readouterr().out
    assert "3 lead(s)" in out and "exposed-service (1)" in out and "events.acme.test" in out
    assert "Redis answers PING" in out


def test_cli_reset_phase_clears_per_service_progress(env, make_target, capsys):
    from hunter import assets as A
    from hunter import state as st
    make_target("acme")
    t = target_mod.Target(env["targets"] / "acme")
    t.output.mkdir(parents=True, exist_ok=True)
    state = st.State(t.state_db)
    state.ensure_phase("05-discover", "discover")
    state.finish_phase("05-discover", st.DONE, "done")
    store = A.Assets(state.db)
    store.upsert_service("a.acme.test", 443, "https", status=200)
    store.mark_service(store.services()[0]["id"], "discovered")
    state.close()
    assert cli.main(["reset", "acme", "05-discover"]) == 0
    assert "re-runs fully" in capsys.readouterr().out
    state = st.State(t.state_db)
    assert state.phase("05-discover")["status"] == st.PENDING
    assert A.Assets(state.db).services()[0]["discovered"] == 0   # flag cleared -> will re-fuzz
    state.close()
