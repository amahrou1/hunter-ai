import json
import os
from pathlib import Path

import pytest

from hunter import config, policy, scope as sc
from hunter import state as st
from hunter.orchestrator import EXIT_OK, Orchestrator
from hunter.phases.p00_intake import IntakePhase
from hunter.proxy import mitmdump_bin

POL = Path(__file__).parent / "policies"


def _draft(name):
    return json.loads((POL / f"{name}.draft.json").read_text())


def _settings(handle=""):
    settings = config.load_settings()
    settings["researcher"]["handle"] = handle
    return settings


def test_validate_draft_catches_structure_errors():
    bad = json.loads((POL / "bugcrowd_shopco.bad.json").read_text())
    problems = policy.validate_draft(bad)
    assert any("type 'website'" in p for p in problems)
    assert any("automated_scanning" in p for p in problems)
    assert policy.validate_draft(_draft("bugcrowd_shopco")) == []
    assert policy.validate_draft([]) == ["the top level must be a JSON object"]


def test_intigriti_policy(env):
    text = (POL / "intigriti_acme.txt").read_text()
    build = policy.build_scope(_draft("intigriti_acme"), text, "", _settings("amahrou1"))
    s = build.scope
    assert s.decide("app.acme-test.com").allowed
    assert s.decide("x.acme-test.io").allowed
    assert not s.decide("acme-test.io").allowed                     # invented apex rejected
    assert any(a["item"] == "acme-test.io" for a in s.ambiguities)
    assert not s.decide("status.acme-test.io").allowed              # out of scope wins
    assert not s.decide("a.staging.acme-test.io").allowed
    assert s.decide("api.acme-test.com", "/v2/users").allowed
    assert not s.decide("api.acme-test.com", "/v1/users").allowed   # path-limited asset
    assert s.rules["effective_rps"] == 10
    assert s.rules["required_headers"] == {"X-Intigriti-Username": "amahrou1"}
    assert s.rules["researcher_email"] == "amahrou1@intigriti.me"
    assert "Self-XSS" in s.excluded_vulnerabilities
    assert any(a.kind == "mobile" for a in s.in_scope)


def test_header_placeholder_without_handle_is_a_problem(env):
    text = (POL / "intigriti_acme.txt").read_text()
    build = policy.build_scope(_draft("intigriti_acme"), text, "", _settings(""))
    assert build.scope.rules["unresolved_headers"]
    assert any("hunt handle" in p for p in build.problems)
    fixed = policy.build_scope(_draft("intigriti_acme"), text, "header X-Intigriti-Username: someone\n", _settings(""))
    assert fixed.scope.rules["required_headers"]["X-Intigriti-Username"] == "someone"
    assert not fixed.scope.rules["unresolved_headers"]


def test_bugcrowd_policy_limited_scanning(env):
    text = (POL / "bugcrowd_shopco.txt").read_text()
    s = policy.build_scope(_draft("bugcrowd_shopco"), text, "", _settings("amahrou1")).scope
    assert s.decide("www.shopco-demo.com").allowed
    assert s.decide("pay.shopco-demo.net").allowed
    assert s.decide("203.0.113.5").allowed and not s.decide("203.0.113.20").allowed
    assert not s.decide("blog.shopco-demo.com").allowed
    assert s.rules["low_automation"] and s.rules["effective_rps"] == 2   # 300/min, then limited scanning cap
    assert s.rules["researcher_email"] == "amahrou1@bugcrowdninja.com"


def test_external_policy_with_boilerplate(env):
    text = (POL / "external_telco.txt").read_text()
    build = policy.build_scope(_draft("external_telco"), text, "", _settings())
    s = build.scope
    assert s.decide("shop.telco-demo.de").allowed
    assert s.decide("auth.cloud.telco-demo.com").allowed
    assert not s.decide("x.reverse.telco-cloud-demo.com").allowed      # ❌ row
    assert s.decide("api.telco-cloud-demo.com").allowed
    assert not s.decide("a.lab.internal.telco-demo.de").allowed
    assert not s.decide("www.telco-demo.com").allowed                  # nav link broadened by the AI: rejected
    assert any(a["item"] == "*.telco-demo.com" for a in s.ambiguities)
    assert "telco-us-demo.com" in s.unclassified_hosts                 # other program, never tested
    assert s.rules["effective_rps"] == 5                               # no limit stated -> default


def test_overrides(env):
    text = (POL / "external_telco.txt").read_text()
    s = policy.build_scope(_draft("external_telco"), text,
                           "in *.extra-demo.de\nout shop.telco-demo.de\n", _settings()).scope
    assert s.decide("a.extra-demo.de").allowed
    assert not s.decide("shop.telco-demo.de").allowed


def test_review_render(env):
    text = (POL / "intigriti_acme.txt").read_text()
    build = policy.build_scope(_draft("intigriti_acme"), text, "", _settings("amahrou1"))
    review = policy.render_review(build.scope, build, "acme")
    assert "## In scope" in review and "acme-test.io" in review and "Unclear" in review


# --------------------------------------------------------------------- intake

@pytest.fixture
def acme(make_target):
    return make_target("acme", policy=(POL / "intigriti_acme.txt").read_text())


def _run_intake(target, notifier, settings, monkeypatch, drafts):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "draft")
    monkeypatch.setenv("FAKE_CLAUDE_DRAFTS", os.pathsep.join(str(d) for d in drafts))
    settings["run"]["blocker_wait_minutes"] = 0
    secrets = {"GLM_API_KEY": "glm-test-1234567"}
    return Orchestrator(target, settings, secrets, notifier=notifier, phases=[IntakePhase()]).run()


@pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")
def test_intake_end_to_end(env, acme, notifier, monkeypatch):
    settings = _settings("amahrou1")
    code = _run_intake(acme, notifier, settings, monkeypatch, [POL / "intigriti_acme.draft.json"])
    assert code == EXIT_OK
    state = st.State(acme.state_db)
    row = state.phase("00-intake")
    assert row["status"] == st.DONE, row["summary"]
    assert "guard verified" in row["summary"]
    loaded = sc.load(acme.scope_file)
    assert loaded.decide("app.acme-test.com").allowed
    assert acme.scope_review.exists()
    assert "Scope ready" in notifier.titles()


@pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")
def test_intake_repairs_a_bad_draft(env, make_target, notifier, monkeypatch):
    target = make_target("shopco", policy=(POL / "bugcrowd_shopco.txt").read_text())
    code = _run_intake(target, notifier, _settings("amahrou1"), monkeypatch,
                       [POL / "bugcrowd_shopco.bad.json", POL / "bugcrowd_shopco.draft.json"])
    assert code == EXIT_OK
    assert st.State(target.state_db).phase("00-intake")["status"] == st.DONE
    prompts = [json.loads(l)["prompt"] for l in env["record"].read_text().splitlines()]
    assert len(prompts) == 2 and "has these problems" in prompts[1] and "type 'website'" in prompts[1]


def test_intake_gives_up_after_three_attempts(env, acme, notifier, monkeypatch):
    code = _run_intake(acme, notifier, _settings("amahrou1"), monkeypatch, ["NOFILE"])
    assert code == EXIT_OK
    row = st.State(acme.state_db).phase("00-intake")
    assert row["status"] == st.FAILED and "was not written" in row["summary"]
    assert "Policy could not be read" in notifier.titles()


@pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")
def test_missing_handle_blocks_until_override(env, acme, notifier, monkeypatch):
    code = _run_intake(acme, notifier, _settings(""), monkeypatch, [POL / "intigriti_acme.draft.json"])
    assert code == EXIT_OK
    state = st.State(acme.state_db)
    assert state.phase("00-intake")["status"] == st.BLOCKED
    assert "Blocked: Value for a required header" in notifier.titles()
    state.close()
    (acme.path / "scope-overrides.txt").write_text("header X-Intigriti-Username: amahrou1\n")
    _run_intake(acme, notifier, _settings(""), monkeypatch, [POL / "intigriti_acme.draft.json"])
    assert st.State(acme.state_db).phase("00-intake")["status"] == st.DONE


def test_rule_questions_are_not_held_back_assets(env):
    text = (POL / "external_telco.txt").read_text()
    s = policy.build_scope(_draft("external_telco"), text, "", _settings()).scope
    assert [q["item"] for q in s.questions] == ["reward tiers per domain"]
    assert all(policy.looks_like_asset(a["item"]) for a in s.ambiguities)
    assert policy.looks_like_asset("*.foo.example.com")
    assert policy.looks_like_asset("api.example.com (staging?)")
    assert not policy.looks_like_asset("Report submission channel")
    assert not policy.looks_like_asset("T Mobile US boundary: which telekom.com hosts belong to T-Mobile US")
