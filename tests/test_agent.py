import time

import pytest

from hunter import agent, config
from hunter.state import State
from tests.conftest import calls


def _run(env, settings_secrets, **kwargs):
    settings, secrets = settings_secrets
    params = dict(settings=settings, secrets=secrets, role="tester", prompt="Do the thing.",
                  workdir=env["tmp"] / "work", log_dir=env["tmp"] / "logs", name="unit test",
                  retry_delay=0)
    params.update(kwargs)
    return agent.run_agent(**params)


def test_success_parses_result_and_passes_prompt_on_stdin(env, settings_secrets):
    result = _run(env, settings_secrets)
    assert result.ok and result.text == "READY"
    assert result.cost_usd == pytest.approx(0.0123)
    call = calls(env["record"])[0]
    assert call["prompt"] == "Do the thing."
    argv = call["argv"]
    for flag in ("-p", "--dangerously-skip-permissions", "--no-session-persistence"):
        assert flag in argv
    assert argv[argv.index("--output-format") + 1] == "stream-json"
    assert argv[argv.index("--setting-sources") + 1] == "project,local"
    assert argv[argv.index("--model") + 1] == "glm-5.3"
    assert call["env"]["ANTHROPIC_BASE_URL"] == "https://api.z.ai/api/anthropic"
    assert call["env"]["ANTHROPIC_AUTH_TOKEN"] == "glm-test-key-123456"
    assert result.log_path.exists()


def test_system_prompt_and_add_dirs(env, settings_secrets):
    _run(env, settings_secrets, system_append="RULES", add_dirs=[env["skills"]], bare=True)
    argv = calls(env["record"])[0]["argv"]
    assert "--bare" in argv
    assert argv[argv.index("--add-dir") + 1] == str(env["skills"])
    system_file = argv[argv.index("--append-system-prompt-file") + 1]
    assert open(system_file).read() == "RULES"


def test_fatal_auth_error_stops_fast(env, settings_secrets, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "auth")
    started = time.monotonic()
    with pytest.raises(agent.AgentFatalError, match="authentication_failed"):
        _run(env, settings_secrets)
    assert time.monotonic() - started < 40
    assert len(calls(env["record"])) == 1  # no retries on a bad key


def test_timeout_kills_session(env, settings_secrets, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "hang")
    started = time.monotonic()
    result = _run(env, settings_secrets, timeout_minutes=0.03)
    assert not result.ok and result.subtype == "timeout"
    assert time.monotonic() - started < 40


def test_no_result_is_retried_then_reported(env, settings_secrets, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "noresult")
    state = State(env["tmp"] / "s.db")
    result = _run(env, settings_secrets, retries=2, state=state, phase_id="x")
    assert not result.ok and result.subtype == "no_result"
    assert "boom" in result.error
    assert len(calls(env["record"])) == 3
    assert state.agent_totals()["runs"] == 3


def test_max_turns_not_retried(env, settings_secrets, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "maxturns")
    result = _run(env, settings_secrets, retries=2)
    assert result.subtype == "error_max_turns"
    assert len(calls(env["record"])) == 1


def test_missing_cli_is_fatal(env, settings_secrets, monkeypatch):
    monkeypatch.setenv("HUNTER_CLAUDE_BIN", str(env["tmp"] / "does-not-exist"))
    with pytest.raises(agent.AgentFatalError, match="not installed"):
        _run(env, settings_secrets)


def test_bare_setting(env):
    settings = config.load_settings()
    assert agent.bare_enabled(settings) is False
    settings["detected"]["bare_ok"] = True
    assert agent.bare_enabled(settings) is True
    settings["agent"]["bare"] = "off"
    assert agent.bare_enabled(settings) is False
