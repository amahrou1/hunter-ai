"""Origin-IP discovery: find candidate real-origin IPs behind a WAF/CDN from
passive data, confirm an in-scope one serves the app directly. Offline - DNS and
crt.sh are stubbed."""

from __future__ import annotations

from hunter import origin


def test_candidate_ips_excludes_edge(monkeypatch):
    # host resolves to a Cloudflare edge IP; a cert sibling resolves to the origin
    resolved = {
        "app.example.com": {"104.16.0.1"},          # edge
        "origin.example.com": {"203.0.113.5"},      # real origin (from cert sibling)
        "www.example.com": {"104.16.0.1"},          # also edge
    }
    monkeypatch.setattr(origin, "_edge_ips", lambda h: resolved.get(h, set()))
    monkeypatch.setattr(origin, "crtsh_hosts",
                        lambda domain, opener, **k: ["app.example.com", "origin.example.com", "www.example.com"])
    disc = origin.candidate_ips("app.example.com", opener=None)
    assert disc["edge_ips"] == ["104.16.0.1"]
    # the origin IP is a candidate; the edge IP is not
    assert "203.0.113.5" in disc["candidates"]
    assert "104.16.0.1" not in disc["candidates"]


def test_no_candidates_when_everything_is_edge(monkeypatch):
    monkeypatch.setattr(origin, "_edge_ips", lambda h: {"104.16.0.1"})
    monkeypatch.setattr(origin, "crtsh_hosts", lambda domain, opener, **k: ["x.example.com", "y.example.com"])
    disc = origin.candidate_ips("app.example.com", opener=None)
    assert disc["candidates"] == {}


def test_confirm_flags_non_cdn_origin():
    # a fake opener returning a plain nginx response (not behind a CDN)
    class FakeResp:
        status = 200
        headers = {"Server": "nginx/1.18"}
        def read(self, n): return b"<html>the real app</html>"
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class FakeOpener:
        def open(self, req, timeout=0): return FakeResp()
    res = origin.confirm("app.example.com", "203.0.113.5", FakeOpener())
    assert res["on_cdn"] is False and res["status"] == 200
    assert res["server"] == "nginx/1.18"


def test_confirm_marks_cdn_server():
    class FakeResp:
        status = 403
        headers = {"Server": "cloudflare"}
        def read(self, n): return b"blocked"
        def __enter__(self): return self
        def __exit__(self, *a): return False
    class FakeOpener:
        def open(self, req, timeout=0): return FakeResp()
    res = origin.confirm("app.example.com", "104.16.0.1", FakeOpener())
    assert res["on_cdn"] is True   # still behind the CDN, not the origin


def test_root_two_level_suffix():
    assert origin._root("a.b.example.co.uk") == "example.co.uk"
    assert origin._root("app.example.com") == "example.com"
