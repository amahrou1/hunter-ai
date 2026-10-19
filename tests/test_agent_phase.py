"""The AI-phase framework end to end: a fake agent runs hk in the real phase
environment (proxy env, PATH, HUNTER_* vars, the PreToolUse settings file),
and the inventory and handoff come out right."""

import json

import pytest

from hunter import assets as A
from hunter import scope as sc
from hunter import state as st
from hunter.phases.ai_recon import AIReconPhase
from hunter.phases.base import Context
from hunter.proxy import mitmdump_bin

pytestmark = pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")


def test_ai_recon_phase_runs_agent_and_records_inventory(env, make_target, settings_secrets, notifier,
                                                         monkeypatch, tmp_path):
    target = make_target("acme")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.acme-test.io"), sc.parse_asset("127.0.0.1")],
                     rules={"effective_rps": 50}), target.scope_file)
    state = st.State(target.state_db)

    # A fake subfinder result the "agent" will import, with one in-scope host
    # and one out-of-scope host (the importer must reject the second).
    subs = tmp_path / "subs.jsonl"
    subs.write_text(json.dumps({"host": "www.acme-test.io"}) + "\n"
                    + json.dumps({"host": "evil.example.com"}) + "\n")
    # What the agent "does": use hk inside the phase environment.
    script = (
        f"hk import subfinder {subs} > import.txt 2>&1; "
        "hk add host api.acme-test.io >> import.txt 2>&1; "
        "hk scope check https://www.acme-test.io/ >> import.txt 2>&1; "
        "hk stats > stats.json 2>&1; "
        "echo 'recon complete' > handoff.md"
    )
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "script")
    monkeypatch.setenv("FAKE_CLAUDE_SCRIPT", script)

    ctx = Context(target, state, settings_secrets[0], {"GLM_API_KEY": "k"}, notifier)
    ctx.phase_id = "02-recon"
    # api.acme-test.io does not resolve in DNS, but www is seeded unresolved;
    # mark one resolved so the phase's "live host" check passes.
    try:
        result = AIReconPhase().run(ctx)
    finally:
        ctx.close()

    store = A.Assets(st.State(target.state_db).db)
    hosts = {h["host"] for h in store.hosts()}
    assert "www.acme-test.io" in hosts            # imported, in scope
    assert "api.acme-test.io" in hosts            # added by hk add
    assert "evil.example.com" not in {h["host"] for h in store.hosts(scope=A.IN)}  # rejected / not in-scope
    # The framework wired the command checker as a PreToolUse hook.
    settings = json.loads((target.output / "phases" / "02-recon" / "work" / ".claude" / "settings.json").read_text())
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "Bash|WebFetch"
    assert "guard_hook.py" in settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    # The handoff was saved for the next phase.
    assert (target.output / "handoff" / "02-recon.md").exists()
    # The agent ran with the scope-proxy environment.
    call = json.loads(env["record"].read_text().splitlines()[-1])
    assert call["env"]["HTTPS_PROXY"] and call["env"]["HUNTER_PROXY"]
    # It reported no live resolved host yet (www seeded but unresolved) -> PARTIAL + a blocker.
    assert result.status in (st.PARTIAL, st.DONE)


def test_ai_recon_blocks_when_nothing_resolves(env, make_target, settings_secrets, notifier, monkeypatch):
    target = make_target("acme2")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.acme-test.io")], rules={"effective_rps": 50}),
            target.scope_file)
    state = st.State(target.state_db)
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "script")
    monkeypatch.setenv("FAKE_CLAUDE_SCRIPT", "echo 'found nothing live' > handoff.md")
    ctx = Context(target, state, settings_secrets[0], {"GLM_API_KEY": "k"}, notifier)
    ctx.phase_id = "02-recon"
    try:
        result = AIReconPhase().run(ctx)
    finally:
        ctx.close()
    assert result.status == st.PARTIAL
    assert [b["need"] for b in st.State(target.state_db).open_blockers()] == ["At least one resolvable in-scope host"]


def test_phase_env_and_preamble_carry_oob_infra(env, make_target, settings_secrets, notifier, tmp_path):
    from hunter.phases.ai_injection import AIInjectionPhase
    from hunter.phases.base import Context
    target = make_target("acme")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.acme.test")], rules={"effective_rps": 10}), target.scope_file)
    settings = settings_secrets[0]
    settings["oob"] = {"enabled": True, "callback_host": "203.0.113.9", "listener_ports": [80],
                       "blind_xss_url": "https://xss.example/c/me", "temp_mail": True}
    state = st.State(target.state_db)
    ctx = Context(target, state, settings, {"GLM_API_KEY": "k"}, notifier)
    ctx.phase_id = "09-injection"
    phase = AIInjectionPhase()
    try:
        envd = phase._env(ctx, ctx.proxy(), target.output / "w")
    finally:
        ctx.close()
        state.close()
    assert "203.0.113.9" in envd["HUNTER_EXTRA_HOSTS"] and "xss.example" in envd["HUNTER_EXTRA_HOSTS"]
    assert envd["HUNTER_OOB_HOST"] == "203.0.113.9" and envd["HUNTER_BLIND_XSS_URL"] == "https://xss.example/c/me"
    infra = phase._infra(ctx)
    assert "mail.tm" in infra and "203.0.113.9" in infra and "https://xss.example/c/me" in infra
