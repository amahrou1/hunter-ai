import json
import os
import stat

import pytest

from hunter import config, models, notify, paths


def test_secrets_roundtrip_is_private(env):
    config.save_secrets({"GLM_API_KEY": "abc12345678", "EMPTY": ""})
    path = paths.secrets_file()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert config.load_secrets() == {"GLM_API_KEY": "abc12345678"}


def test_secret_with_newline_rejected(env):
    with pytest.raises(config.ConfigError):
        config.save_secrets({"GLM_API_KEY": "abc\ndef"})


@pytest.mark.parametrize("raw,expected", [
    ("  abc123  ", "abc123"),
    ("'abc123'", "abc123"),
    ('"abc123"', "abc123"),
    ("GLM_API_KEY=abc123", "abc123"),
    ("export GLM_API_KEY='abc123'", "abc123"),
    ("​abc123", "abc123"),
])
def test_clean_secret_value(raw, expected):
    assert config.clean_secret_value(raw) == expected


def test_settings_store_only_overrides(env):
    settings = config.load_settings()
    settings["active_profile"] = "deepseek"
    config.save_settings(settings)
    stored = json.loads(paths.settings_file().read_text())
    assert stored == {"active_profile": "deepseek"}
    assert config.load_settings()["profiles"]["glm"]["strong"] == "glm-5.3"


def test_damaged_settings_explains_fix(env):
    paths.settings_file().write_text("{not json")
    with pytest.raises(config.ConfigError, match="hunt reset-settings"):
        config.load_settings()


def test_resolve_roles_follow_active_profile(env):
    settings = config.load_settings()
    assert models.resolve(settings, "triage").model == "glm-5.3-flash"
    assert models.resolve(settings, "validator").model == "glm-5.3"
    settings["active_profile"] = "claude"
    assert models.resolve(settings, "validator").model == "claude-opus-5-5"
    settings["roles"]["disprover"] = "deepseek:max"
    assert models.resolve(settings, "disprover").profile_name == "deepseek"


def test_agent_env_glm_uses_bearer_and_strips_inherited(env):
    settings = config.load_settings()
    choice = models.resolve(settings, "tester")
    result = models.agent_env(choice, {"GLM_API_KEY": "k-123456789"},
                              base={"ANTHROPIC_API_KEY": "old", "ANTHROPIC_BASE_URL": "https://evil", "PATH": "/bin"})
    assert result["ANTHROPIC_AUTH_TOKEN"] == "k-123456789"
    assert "ANTHROPIC_API_KEY" not in result
    assert result["ANTHROPIC_BASE_URL"] == "https://api.z.ai/api/anthropic"
    assert result["ANTHROPIC_MODEL"] == "glm-5.3"
    assert result["CLAUDE_CODE_SUBAGENT_MODEL"] == "glm-5.3-flash"
    assert result["DISABLE_AUTOUPDATER"] == "1"


def test_agent_env_claude_uses_api_key(env):
    settings = config.load_settings()
    settings["active_profile"] = "claude"
    choice = models.resolve(settings, "triage")
    result = models.agent_env(choice, {"ANTHROPIC_API_KEY": "sk-ant-123456"}, base={"ANTHROPIC_AUTH_TOKEN": "x"})
    assert result["ANTHROPIC_API_KEY"] == "sk-ant-123456"
    assert "ANTHROPIC_AUTH_TOKEN" not in result
    assert "ANTHROPIC_BASE_URL" not in result


def test_agent_env_missing_key_is_clear(env):
    settings = config.load_settings()
    with pytest.raises(config.ConfigError, match="hunt setup"):
        models.agent_env(models.resolve(settings, "tester"), {})


def test_notifier_posts_and_redacts(env, discord):
    secrets = {"DISCORD_WEBHOOK_URL": discord.url, "GLM_API_KEY": "supersecretvalue"}
    sent = notify.Notifier(secrets).send("Found supersecretvalue", "body supersecretvalue", "finding", target="acme")
    assert sent
    embed = discord.messages[0]["embeds"][0]
    assert "supersecretvalue" not in json.dumps(discord.messages)
    assert "[redacted]" in embed["title"]
    assert embed["footer"]["text"].endswith("acme")


def test_notifier_retries_on_rate_limit(env):
    from tests.conftest import FakeDiscord
    server = FakeDiscord(fail_first_with=429)
    try:
        assert notify.Notifier({"DISCORD_WEBHOOK_URL": server.url}).send("hello")
        assert len(server.messages) == 1
    finally:
        server.close()


def test_notifier_without_webhook_only_logs(env):
    assert notify.Notifier({}).send("hello") is False
    assert "hello" in paths.notify_log().read_text()


def test_notifier_unreachable_does_not_raise(env):
    n = notify.Notifier({"DISCORD_WEBHOOK_URL": "http://127.0.0.1:9/api/webhooks/x"}, timeout=0.5)
    n._post.__func__  # exists
    assert n._post({"content": "x"}, attempts=1) is False


def test_valid_webhook():
    assert notify.valid_webhook("https://discord.com/api/webhooks/123456789012345678/" + "a" * 60)
    assert not notify.valid_webhook("https://example.com/hook")
    assert not notify.valid_webhook("https://discord.com/api/webhooks/1")
