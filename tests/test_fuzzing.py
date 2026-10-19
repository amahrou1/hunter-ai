"""Tech-aware wordlist/extension selection and hk fuzzplan."""

import argparse
import json

import pytest

from hunter import assets as A
from hunter import fuzzing
from hunter import scope as sc
from hunter import state as st


@pytest.fixture
def lists(tmp_path):
    d = tmp_path / "myLists"
    d.mkdir()
    for name in ("asp.txt", "php.txt", "api.txt", "onelistforallshort.txt", "params.txt", "myList.txt"):
        (d / name).write_text("admin\nlogin\nconfig\n")
    return {"wordlists": {"dirs": [str(d)]}}


@pytest.mark.parametrize("server,tech,host,expected", [
    ("Microsoft-IIS/10.0", "ASP.NET", "www.x.test", "aspnet"),
    ("nginx", "PHP/8.2", "shop.x.test", "php"),
    ("Apache-Coyote/1.1", "Apache Tomcat", "portal.x.test", "java"),
    ("", "", "api.x.test", "api"),
    ("nginx", "", "www.x.test", "general"),
])
def test_detect_profile(server, tech, host, expected):
    assert fuzzing.detect(server, tech, host) == expected


def test_plan_picks_operator_lists_and_extensions(lists):
    plan = fuzzing.plan(lists, server="Microsoft-IIS/10.0", tech="ASP.NET", host="www.x.test")
    assert plan["profile"] == "aspnet"
    assert plan["wordlists"][0].endswith("asp.txt")               # operator list chosen
    assert "aspx" in plan["extensions"] and "asmx" in plan["extensions"]
    assert plan["params_wordlist"].endswith("params.txt")
    assert plan["big_wordlist"].endswith("myList.txt")
    # a general pass is always included as well
    assert any(w.endswith("onelistforallshort.txt") for w in plan["wordlists"])


def test_plan_falls_back_to_builtin_when_no_lists():
    plan = fuzzing.plan({"wordlists": {"dirs": ["/nonexistent"]}}, server="nginx", tech="PHP")
    assert plan["profile"] == "php"
    assert plan["wordlists"][0].endswith("discover.txt")          # built-in fallback


def test_hk_fuzzplan_reads_service_fingerprint(env, make_target, lists, monkeypatch, capsys):
    from hunter import kit, config
    target = make_target("acme")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.acme.test")], rules={"effective_rps": 5}), target.scope_file)
    monkeypatch.setattr(config, "load_settings", lambda: {**config.DEFAULT_SETTINGS, **lists})
    state = st.State(target.state_db)
    store = A.Assets(state.db)
    store.upsert_service("www.acme.test", 443, "https", url="https://www.acme.test", status=200,
                         server="Microsoft-IIS/10.0", tech=json.dumps(["ASP.NET", "IIS"]))
    sid = store.services()[0]["id"]
    state.close()
    monkeypatch.setenv("HUNTER_TARGET_DIR", str(target.path))
    monkeypatch.setenv("HUNTER_PHASE", "05-discover")
    k = kit.Kit()
    try:
        assert kit.cmd_fuzzplan(k, argparse.Namespace(service_id=str(sid))) == 0
    finally:
        k.state.close()
    out = json.loads(capsys.readouterr().out)
    assert out["profile"] == "aspnet" and "aspx" in out["extensions"]
    assert out["service"]["url"] == "https://www.acme.test"
