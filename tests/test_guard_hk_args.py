"""The command checker must NOT scope-block in-scope hostnames that appear only
as DATA in an `hk` argument (hk note / hk progress / hk finding), because `hk`
scope-checks its own contact and fetches through the scope proxy. Blocking them
stopped the probe agent recording progress and findings and burned its turns.
Raw network tools (curl, nc, dnsx, python) keep their full host scope-check."""

from __future__ import annotations

import pytest

from hunter import scope as sc
from hunter.guard_hook import Verdict, check_command


@pytest.fixture
def scope():
    # Mercedes-shaped: a wildcard root whose subdomains are in scope.
    return sc.Scope(
        in_scope=[sc.parse_asset("*.corpinter.net"), sc.parse_asset("*.mercedes-benz.com")],
        out_of_scope=[],
    )


# --- the exact commands the Mercedes probe agent got blocked on must now pass -

def test_hk_note_with_in_scope_host_is_allowed(scope):
    check_command(
        'hk note "Step-6 sanity check: acf-nonprod.query.api.dvb.corpinter.net -> 307 oauth gate"',
        scope, [])


def test_hk_progress_then_hk_note_pipeline_is_allowed(scope):
    check_command(
        'hk progress "baseline pass" 1238 4778 services 2>&1 | head -2; '
        'hk note "M3 baselines: har.dvb.corpinter.net.cn -> 307" 2>&1 | tail -1',
        scope, [])


def test_hk_finding_with_in_scope_url_is_allowed(scope):
    check_command(
        'hk finding add --host salt-dev.azure.mercedes-benz.com '
        '--url https://salt-dev.azure.mercedes-benz.com/#/CreateAccount --title "No password policy"',
        scope, [])


def test_hk_note_mentioning_out_of_scope_host_still_allowed_as_data(scope):
    # Even an OUT-of-scope hostname quoted inside an hk note is just text being
    # recorded; hk never contacts it. (If hk were asked to fetch it, hk's own
    # scope check refuses.) So recording it must not be blocked.
    check_command('hk note "rejected vhost on 51.138.28.234 (raw IP, no CIDR basis)"', scope, [])


# --- raw network tools keep their full scope enforcement ---------------------

def test_curl_to_out_of_scope_host_still_blocked(scope):
    with pytest.raises(Verdict):
        check_command("curl -s https://evil.example.org/", scope, [])


def test_curl_after_hk_in_same_line_is_still_checked(scope):
    # A network segment chained after an hk segment is still scanned.
    with pytest.raises(Verdict):
        check_command('hk note "ok"; curl -s https://evil.example.org/', scope, [])


def test_python_request_to_out_of_scope_host_still_blocked(scope):
    with pytest.raises(Verdict):
        check_command(
            'python3 -c "import requests; requests.get(\'https://evil.example.org/\')"',
            scope, [])


def test_hk_does_not_disarm_the_other_guards(scope):
    # scanners / proxy-bypass / control rules fire regardless of the leader.
    with pytest.raises(Verdict):
        check_command("hk note \"x\" && nmap -p- 10.0.0.1", scope, [])
    with pytest.raises(Verdict):
        check_command("HTTPS_PROXY= hk services", scope, [])


def test_in_scope_curl_through_proxy_is_allowed(scope):
    # Contacting an in-scope host directly with curl is fine (goes via proxy).
    check_command("curl -s https://api.corpinter.net/", scope, [])


def test_awk_system_is_not_exempt(scope):
    # awk can run commands; it must not hide a host from the checker
    with pytest.raises(Verdict):
        check_command("awk 'BEGIN{system(\"curl https://evil.example.org/\")}'", scope, [])


def test_echo_pipe_to_network_tool_is_checked(scope):
    # the host sits in the echo segment; it must still be checked
    with pytest.raises(Verdict):
        check_command("echo out-of-scope.mercedes-benz.com.cn | xargs -I{} nc {} 80",
                      sc.Scope(in_scope=[sc.parse_asset("*.mercedes-benz.com")],
                               out_of_scope=[sc.parse_asset("*.mercedes-benz.com.cn")]), [])
