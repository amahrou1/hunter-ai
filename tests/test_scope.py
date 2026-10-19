import pytest

from hunter import scope as sc
from hunter.scope import Scope, parse_asset


@pytest.mark.parametrize("raw,kind,host,path,port", [
    ("*.example.com", "wildcard", "example.com", "", None),
    ("example.com", "domain", "example.com", "", None),
    ("https://app.example.com", "domain", "app.example.com", "", None),
    ("https://app.example.com/", "domain", "app.example.com", "", None),
    ("https://app.example.com/api/v2/", "url", "app.example.com", "/api/v2", None),
    ("app.example.com/api", "url", "app.example.com", "/api", None),
    ("https://app.example.com:8443", "url", "app.example.com", "", 8443),
    ("https://*.example.com", "wildcard", "example.com", "", None),
    (".example.com", "wildcard", "example.com", "", None),
    ("`api.example.com`", "domain", "api.example.com", "", None),
    ("API.Example.COM.", "domain", "api.example.com", "", None),
    ("10.0.0.1", "ip", "10.0.0.1", "", None),
    ("10.0.0.0/24", "cidr", "10.0.0.0/24", "", None),
    ("shop.example.com (production)", "domain", "shop.example.com", "", None),
    # Glued wildcard (HackerOne form): the domain itself and its subdomains.
    ("*us.tiktokv.com", "wildcard", "us.tiktokv.com", "", None),
])
def test_parse_asset(raw, kind, host, path, port):
    asset = parse_asset(raw)
    assert (asset.kind, asset.host, asset.path, asset.port) == (kind, host, path, port)


@pytest.mark.parametrize("raw", ["example.*", "ftp://x.example.com", "not a host", "", "*.*.example.com"])
def test_unclear_entries_rejected(raw):
    with pytest.raises(sc.AssetError):
        parse_asset(raw)


def test_mobile_kept_as_non_network():
    asset = parse_asset("com.example.app", "mobile")
    assert asset.kind == "mobile" and not asset.is_network


def _scope(ins, outs=()):
    return Scope(in_scope=[parse_asset(x) for x in ins], out_of_scope=[parse_asset(x) for x in outs])


def test_wildcard_excludes_apex_and_out_wins():
    s = _scope(["*.example.com"], ["admin.example.com", "*.internal.example.com"])
    assert s.decide("www.example.com").allowed
    assert s.decide("a.b.example.com").allowed
    assert not s.decide("example.com").allowed
    assert not s.decide("admin.example.com").allowed
    assert not s.decide("x.internal.example.com").allowed
    assert not s.decide("evilexample.com").allowed
    assert not s.decide("example.com.evil.net").allowed


def test_url_scope_path_and_port():
    s = _scope(["https://app.example.com/api", "https://pay.example.com:8443"])
    assert s.decide("app.example.com", "/api").allowed
    assert s.decide("app.example.com", "/api/users?id=1").allowed
    assert not s.decide("app.example.com", "/apix").allowed
    assert not s.decide("app.example.com", "/").allowed
    assert s.decide("pay.example.com", "/", 8443).allowed
    assert not s.decide("pay.example.com", "/", 443).allowed
    assert s.host_in_scope("app.example.com")


def test_out_of_scope_path_only_blocks_that_path():
    s = _scope(["app.example.com"], ["https://app.example.com/admin"])
    assert s.decide("app.example.com", "/home").allowed
    assert not s.decide("app.example.com", "/admin/users").allowed
    assert s.host_in_scope("app.example.com")


def test_ip_rules():
    s = _scope(["10.0.0.0/30", "api.example.com"])
    assert s.decide("10.0.0.2").allowed
    assert not s.decide("10.0.0.9").allowed
    assert not s.decide("93.184.216.34").allowed  # an IP is never in scope through a hostname


def test_decide_url_and_host_normalisation():
    s = _scope(["api.example.com"])
    assert s.decide_url("https://API.example.com:443/x").allowed
    assert s.decide("api.example.com:443").allowed
    assert not s.decide("").allowed


def test_roundtrip(tmp_path):
    s = _scope(["*.example.com", "https://app.example.com/api"], ["admin.example.com"])
    s.rules = {"effective_rps": 3}
    sc.save(s, tmp_path / "scope.json")
    loaded = sc.load(tmp_path / "scope.json")
    assert loaded.decide("x.example.com").allowed and not loaded.decide("admin.example.com").allowed
    assert loaded.rate_limit_rps == 3


POLICY = """In scope: *.shop.example.org, api.example.net, https://portal.example.io/app
Also 10.20.30.0/24. Contact us at security@example.org. Use intigriti.me emails.
See https://www.intigriti.com/terms and logo.png."""


def test_appears_in_policy():
    assert sc.appears_in_policy(parse_asset("*.shop.example.org"), POLICY)
    assert sc.appears_in_policy(parse_asset("api.example.net"), POLICY)
    assert sc.appears_in_policy(parse_asset("portal.example.io/app"), POLICY)
    assert sc.appears_in_policy(parse_asset("10.20.30.0/24"), POLICY)
    # Hallucinated or broadened entries are caught:
    assert not sc.appears_in_policy(parse_asset("shop.example.org"), POLICY)   # apex of a wildcard
    assert not sc.appears_in_policy(parse_asset("*.example.net"), POLICY)   # broadened to a wildcard
    assert not sc.appears_in_policy(parse_asset("evil.example.net"), POLICY)
    assert not sc.appears_in_policy(parse_asset("other.com"), POLICY)


def test_mentioned_hosts():
    hosts = sc.mentioned_hosts(POLICY)
    assert "*.shop.example.org" in hosts and "api.example.net" in hosts
    assert "logo.png" not in hosts


def test_overrides():
    ins, outs, problems = sc.parse_overrides("# note\nin *.a.com\nout b.a.com\n+ c.com\nbogus line\n")
    assert ins == ["*.a.com", "c.com"] and outs == ["b.a.com"] and len(problems) == 1


def test_parse_override_rate():
    assert sc.parse_override_rate("rate 120\n") == 120
    assert sc.parse_override_rate("rate 2.5") == 2.5
    assert sc.parse_override_rate("in *.a.com\nrate 10\nrate 30\n") == 30  # last wins
    assert sc.parse_override_rate("in *.a.com") is None
    ins, outs, _ = sc.parse_overrides("rate 50\nin *.a.com\nheader X: y\n")
    assert ins == ["*.a.com"] and outs == []  # rate/header lines not treated as scope
