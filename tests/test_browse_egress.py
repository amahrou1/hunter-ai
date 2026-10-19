"""Tests for the two system additions:
- the scope-proxied headless browser helper (hunter/browse.py), and
- the residential/upstream egress proxy (proxy upstream mode + `hunt egress`).
"""

from __future__ import annotations

import io
import contextlib
from pathlib import Path

from hunter import browse, cli, config
from hunter.agent_phase import AgentPhase
from hunter.proxy import ScopeProxy


# --------------------------------------------------------------- browse plan
BROWSE_ENV = {
    "HUNTER_PROXY": "http://127.0.0.1:8080",
    "HUNTER_USER_AGENT": "UA/1",
    "SSL_CERT_FILE": "/x/ca.pem",
    "HUNTER_OOB_HOST": "38.242.235.206",
    "HUNTER_BLIND_XSS_URL": "https://xss.report/c/abdalah336",
    "HUNTER_BROWSER": "1",
}


def test_build_plan_parses_everything():
    p = browse.build_plan(
        ["https://t.example/x?q=1", "--window-name", "INSPECTOR_abc",
         "--cookie", "sid=xyz; t=1", "--header", "X-Test: 1",
         "--eval", "document.title", "--click", "#go", "--wait", "500", "--screenshot"],
        BROWSE_ENV)
    assert p["proxy"] == "http://127.0.0.1:8080" and p["user_agent"] == "UA/1"
    assert p["window_name"] == "INSPECTOR_abc"
    assert {"name": "sid", "value": "xyz", "domain": "t.example", "path": "/"} in p["cookies"]
    assert p["headers"] == {"X-Test": "1"}
    assert p["eval_js"] == "document.title" and p["click"] == "#go" and p["screenshot"] is True
    assert "38.242.235.206" in p["oob_hosts"] and "xss.report" in p["oob_hosts"]


def _run_capture(plan: dict):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = browse.run(plan)
    return rc, buf.getvalue()


def test_browser_refuses_without_scope_proxy():
    """Safety: it must never browse a target un-proxied."""
    plan = browse.build_plan(["https://t.example/"], {k: v for k, v in BROWSE_ENV.items() if k != "HUNTER_PROXY"})
    rc, out = _run_capture(plan)
    assert rc == 3 and "un-proxied" in out


def test_browser_refuses_when_disabled():
    env = dict(BROWSE_ENV, HUNTER_BROWSER="0")
    plan = browse.build_plan(["https://t.example/"], env)
    rc, out = _run_capture(plan)
    assert rc == 3 and "disabled" in out


# ------------------------------------------------------------- upstream proxy
def _proxy(upstream: str) -> ScopeProxy:
    return ScopeProxy(Path("/tmp/s.json"), Path("/tmp/logs"), {"proxy": {"upstream": upstream}})


def test_upstream_args_with_credentials():
    args = _proxy("http://user:pass@gate.prov.com:7000")._upstream_args()
    assert args == ["--mode", "upstream:http://gate.prov.com:7000", "--set", "upstream_auth=user:pass"]


def test_upstream_args_bare_hostport_defaults_to_http():
    assert _proxy("gate2.prov.com:7001")._upstream_args() == ["--mode", "upstream:http://gate2.prov.com:7001"]


def test_upstream_empty_is_direct():
    assert _proxy("")._upstream_args() == []


# ------------------------------------------------------------- hunt egress CLI
def test_egress_set_and_clear(env):
    assert cli.main(["egress", "http://u:p@h.example:7000"]) == 0
    assert config.load_settings()["proxy"]["upstream"] == "http://u:p@h.example:7000"
    assert cli.main(["egress", "off"]) == 0
    assert config.load_settings()["proxy"]["upstream"] == ""
    assert cli.main(["egress"]) == 0  # show-only


# ------------------------------------------------------- agent sees the browser
class _Ctx:
    def __init__(self, settings):
        self.settings = settings


def test_infra_includes_browser_when_enabled():
    text = AgentPhase()._infra(_Ctx({"oob": {"enabled": True, "temp_mail": True},
                                     "browser": {"enabled": True}}))
    assert "hbrowse" in text and "mail.tm" in text


def test_infra_browser_only_when_oob_off():
    text = AgentPhase()._infra(_Ctx({"oob": {"enabled": False}, "browser": {"enabled": True}}))
    assert "hbrowse" in text and "mail.tm" not in text


def test_infra_empty_when_both_off():
    assert AgentPhase()._infra(_Ctx({"oob": {"enabled": False}, "browser": {"enabled": False}})) == ""
