"""hk unlock: 403/401 bypass prober. Only a genuine flip (gated baseline -> 2xx
with a different body) counts; blocked/same-body/error variants do not."""

from __future__ import annotations

import hashlib

from hunter import unlock


class FakeOpener:
    """Returns a scripted response per URL+headers. Mimics webprobe.fetch's
    dict shape via unlock._fetch, which we drive through the Request path."""

    def __init__(self, responses):
        # responses: dict keyed by url -> {"status":, "body": bytes, "blocked":}
        self.responses = responses
        self.default = {"status": 403, "body": b"forbidden"}

    def open(self, req_or_url, timeout=20):
        url = req_or_url if isinstance(req_or_url, str) else req_or_url.full_url
        spec = self.responses.get(url, self.default)
        return _Resp(spec)


class _Resp:
    def __init__(self, spec):
        self.spec = spec
        self.status = spec["status"]
        self.headers = {}

    def read(self, n=0):
        return self.spec.get("body", b"")

    def __enter__(self):
        if self.status >= 400:
            import urllib.error
            err = urllib.error.HTTPError(
                "u", self.status, "err", {}, None)
            err.read = lambda n=0: self.spec.get("body", b"")  # type: ignore
            raise err
        return self

    def __exit__(self, *a):
        return False


def _body(s):
    return s.encode()


def test_no_bypass_when_baseline_is_open():
    url = "https://x.test/ok"
    opener = FakeOpener({url: {"status": 200, "body": _body("hello")}})
    res = unlock.probe(url, opener)
    assert res["bypasses"] == []
    assert "not 401/403" in res["note"]


def test_detects_a_real_bypass():
    url = "https://x.test/admin"
    # baseline 403; one variant (/admin/) returns 200 with different body
    responses = {url: {"status": 403, "body": _body("denied")},
                 "https://x.test/admin/": {"status": 200, "body": _body("SECRET ADMIN PANEL")}}
    opener = FakeOpener(responses)  # everything else defaults to 403
    res = unlock.probe(url, opener)
    hows = [b["url"] for b in res["bypasses"]]
    assert "https://x.test/admin/" in hows
    assert all(b["status"] == 200 for b in res["bypasses"])


def test_same_body_is_not_a_bypass():
    url = "https://x.test/admin"
    same = _body("same page")
    # a 200 whose body equals the baseline's hash should NOT count (soft-200)
    base = {"status": 403, "body": same}
    responses = {url: base, "https://x.test/admin/": {"status": 200, "body": same}}
    opener = FakeOpener(responses)
    res = unlock.probe(url, opener)
    # the /admin/ 200 has the SAME hash as baseline -> filtered out
    assert all(b["url"] != "https://x.test/admin/" for b in res["bypasses"])


def test_proxy_blocked_variant_is_ignored():
    url = "https://x.test/admin"
    # simulate the scope proxy 403 with the X-Hunter-Blocked marker on a variant
    responses = {url: {"status": 403, "body": _body("denied")}}
    opener = FakeOpener(responses)

    # monkeypatch _fetch to mark one variant as proxy-blocked
    real = unlock._fetch

    def fake_fetch(op, u, headers):
        if u == "https://x.test/admin/":
            return {"status": 403, "len": 5, "hash": "zzz", "blocked": True}
        return real(op, u, headers)

    unlock._fetch = fake_fetch
    try:
        res = unlock.probe(url, opener)
    finally:
        unlock._fetch = real
    assert all(b["url"] != "https://x.test/admin/" for b in res["bypasses"])


def test_variants_stay_on_the_same_host():
    for _, u, _ in unlock._variants("https://target.test/a/b/admin"):
        assert u.startswith("https://target.test/")


def test_header_variants_present():
    hsets = [h for _, _, h in unlock._variants("https://x.test/admin") if h]
    keys = {k for h in hsets for k in h}
    assert "X-Original-URL" in keys
    assert "X-Forwarded-For" in keys
