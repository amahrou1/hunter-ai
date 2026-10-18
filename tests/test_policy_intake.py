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
    # 300/min = 5/s is an explicit number, so it is honoured (not dropped to the
    # limited-scanning floor), and automation counts as allowed.
    assert s.rules["effective_rps"] == 5 and s.rules["low_automation"] is False
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


def test_explicit_rate_is_honored_not_clamped(env):
    """A program that states a high rate (and cautious wording) must use the
    stated rate, capped only by the hardware ceiling -- not dropped to 2/s."""
    text = ("In scope: *.bol-demo.com\n"
            "Automated tools and scanners are allowed up to 600 requests per second.\n"
            "Please test carefully on production.\n")
    draft = {
        "program_name": "bol demo", "platform": "intigriti",
        "in_scope": [{"asset": "*.bol-demo.com", "type": "wildcard", "quote": "In scope: *.bol-demo.com"}],
        "out_of_scope": [], "excluded_vulnerabilities": [], "forbidden_actions": [],
        "automated_scanning": "limited",   # the AI under-read it; the number must still win
        "rate_limit": {"requests_per_second": 600, "quote": "up to 600 requests per second"},
        "required_headers": [], "user_agent": None,
        "account_rules": {"self_registration": "not_mentioned", "email_requirement": None, "quote": None},
        "ambiguities": [], "other_rules": [],
    }
    settings = _settings("amahrou1")
    s = policy.build_scope(draft, text, "", settings).scope
    assert s.rules["policy_rps"] == 600
    assert s.rules["effective_rps"] == 200           # hardware ceiling (default max_rps)
    assert s.rules["rate_source"] == "policy"
    assert s.rules["low_automation"] is False         # a stated number means automation is allowed

    settings["scope"]["max_rps"] = 600
    s2 = policy.build_scope(draft, text, "", settings).scope
    assert s2.rules["effective_rps"] == 600           # raised ceiling: full policy rate


def test_rate_override_wins(env):
    text = "In scope: *.ex.com\nRate: 300 per second."
    draft = {"program_name": "x", "platform": "external",
             "in_scope": [{"asset": "*.ex.com", "type": "wildcard", "quote": "In scope: *.ex.com"}],
             "out_of_scope": [], "automated_scanning": "allowed",
             "rate_limit": {"requests_per_second": 300, "quote": "300 per second"},
             "required_headers": [], "user_agent": None, "account_rules": {}, "ambiguities": [], "other_rules": []}
    s = policy.build_scope(draft, text, "rate 50\n", _settings()).scope
    assert s.rules["effective_rps"] == 50 and s.rules["rate_source"] == "your override"


def test_forbidden_and_limited_without_number(env):
    base = {"program_name": "x", "platform": "external",
            "in_scope": [{"asset": "*.ex.com", "type": "wildcard", "quote": "*.ex.com"}],
            "out_of_scope": [], "required_headers": [], "user_agent": None,
            "account_rules": {}, "ambiguities": [], "other_rules": [],
            "rate_limit": {"requests_per_second": None, "quote": None}}
    forb = dict(base, automated_scanning="forbidden")
    s = policy.build_scope(forb, "*.ex.com no automated scanning", "", _settings()).scope
    assert s.rules["effective_rps"] == 1.0 and s.rules["low_automation"] is True
    lim = dict(base, automated_scanning="limited")
    s2 = policy.build_scope(lim, "*.ex.com limited scanning", "", _settings()).scope
    assert s2.rules["effective_rps"] == 2 and s2.rules["low_automation"] is True


def test_ownership_scope_is_recorded_not_expanded(env):
    text = (POL / "ownership_fincorp.txt").read_text()
    build = policy.build_scope(_draft("ownership_fincorp"), text, "", _settings())
    s = build.scope
    assert s.rules["ownership_scope"] == {
        "owner": "FinCorp Global", "quote_found": True,
        "quote": "Any system or application owned and operated by FinCorp Global is in scope."}
    assert [a.raw for a in s.in_scope] == ["www.fincorp-demo.com"]   # nothing guessed
    assert not s.decide("api.fincorp-demo.com").allowed
    assert "Ownership scope: assets owned by FinCorp Global" in policy.render_review(s, build, "fincorp")


@pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")
def test_ownership_scope_asks_operator_then_uses_confirmed(env, make_target, notifier, monkeypatch):
    target = make_target("fincorp", policy=(POL / "ownership_fincorp.txt").read_text())
    _run_intake(target, notifier, _settings(), monkeypatch, [POL / "ownership_fincorp.draft.json"])
    state = st.State(target.state_db)
    assert state.phase("00-intake")["status"] == st.DONE      # the named host is tested meanwhile
    assert "Blocked: Assets you confirm belong to FinCorp Global" in notifier.titles()
    state.close()
    (target.path / "scope-overrides.txt").write_text("in *.fincorp-demo.com\n")
    notifier.sent.clear()
    _run_intake(target, notifier, _settings(), monkeypatch, [POL / "ownership_fincorp.draft.json"])
    assert not any(t.startswith("Blocked:") for t in notifier.titles())
    assert sc.load(target.scope_file).decide("api.fincorp-demo.com").allowed


def test_ownership_only_scope_blocks_with_clear_request(env, make_target, notifier, monkeypatch):
    target = make_target("fincorp2", policy=(POL / "ownership_fincorp.txt").read_text())
    _run_intake(target, notifier, _settings(), monkeypatch, [POL / "ownership_only.draft.json"])
    assert st.State(target.state_db).phase("00-intake")["status"] == st.BLOCKED
    assert "Blocked: Assets you confirm belong to FinCorp Global" in notifier.titles()
    assert "Blocked: A clear scope" not in notifier.titles()


def test_apex_only_scope_does_not_expand(env):
    s = sc.Scope(in_scope=[sc.parse_asset("dell-demo.com")])
    assert s.decide("dell-demo.com").allowed
    assert not s.decide("www.dell-demo.com").allowed
    assert s.wildcard_roots() == []                 # recon will not enumerate subdomains
