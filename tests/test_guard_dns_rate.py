"""The command checker caps the dnsx query rate (public resolvers bypass the
scope proxy, so this is the only place DNS load can be bounded)."""

from __future__ import annotations

import pytest

from hunter import scope as sc
from hunter.guard_hook import Verdict, check_command


@pytest.fixture
def scope():
    return sc.Scope(in_scope=[sc.parse_asset("*.bol.com")], out_of_scope=[])


def test_no_ceiling_means_no_dns_enforcement(monkeypatch, scope):
    monkeypatch.delenv("HUNTER_DNS_MAX_RPS", raising=False)
    # Without a configured ceiling, dnsx with no rate limit is allowed.
    check_command("dnsx -l hosts.txt -json -a", scope, [])


def test_dnsx_without_rate_limit_is_allowed(monkeypatch, scope):
    # A missing -rl must NEVER block dnsx: blocking a core recon tool over one
    # flag kills recon (0 hosts). dnsx's own default rate is modest.
    monkeypatch.setenv("HUNTER_DNS_MAX_RPS", "150")
    check_command("dnsx -l hosts.txt -json -a -cname", scope, [])
    # the exact command that broke the Mercedes run must now pass:
    check_command('printf "a.dvb.corpinter.net" | dnsx -silent -a -t A', scope, [])


def test_reasonable_rate_is_allowed(monkeypatch, scope):
    monkeypatch.setenv("HUNTER_DNS_MAX_RPS", "150")
    check_command("dnsx -l hosts.txt -rl 150 -json -a", scope, [])
    check_command("dnsx -l hosts.txt -rate-limit 50 -json", scope, [])
    check_command("dnsx -l hosts.txt -rl 300 -json", scope, [])  # 2x ceiling: fine


def test_only_reckless_rate_is_blocked(monkeypatch, scope):
    # block only a rate far above the ceiling (> 4x, min 200)
    monkeypatch.setenv("HUNTER_DNS_MAX_RPS", "150")
    with pytest.raises(Verdict):
        check_command("dnsx -l hosts.txt -rl 5000 -json", scope, [])


def test_other_tools_unaffected_by_dns_ceiling(monkeypatch, scope):
    monkeypatch.setenv("HUNTER_DNS_MAX_RPS", "150")
    # subfinder/httpx are not dnsx; the rule must not touch them.
    check_command("subfinder -d bol.com -silent -o subs.txt", scope, [])
    check_command("httpx -l hosts.txt -json -o out.jsonl", scope, [])


def test_low_automation_missing_flag_still_allowed(monkeypatch, scope):
    # even on a low-automation program, a missing flag must not break recon
    monkeypatch.setenv("HUNTER_DNS_MAX_RPS", "25")
    check_command("dnsx -l hosts.txt -json -a", scope, [])
    check_command("dnsx -l hosts.txt -rl 25 -json", scope, [])
    # only a reckless rate is refused
    with pytest.raises(Verdict):
        check_command("dnsx -l hosts.txt -rl 9000 -json", scope, [])
