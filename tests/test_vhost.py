"""Virtual-host enumeration: flags a Host whose response differs from a random
baseline, bails on host-insensitive or noisy servers, never on proxy-blocks."""

from __future__ import annotations

import hashlib

from hunter import vhost


class FakeOpener:
    """Maps Host header -> response body/status. Unknown hosts get the default
    page (simulates the server's catch-all)."""

    def __init__(self, by_host, default_body=b"default page", default_status=200,
                 noisy=False):
        self.by_host = by_host
        self.default = (default_status, default_body)
        self.noisy = noisy
        self._n = 0

    def open(self, req, timeout=15):
        host = req.headers.get("Host") or req.headers.get("host")
        if host in self.by_host:
            status, body = self.by_host[host]
        else:
            status, body = self.default
            if self.noisy:
                self._n += 1
                body = body + str(self._n).encode()   # different every time
        return _Resp(status, body)


class _Resp:
    def __init__(self, status, body):
        self.status = status
        self._body = body
        self.headers = {}

    def read(self, n=0):
        return self._body

    def __enter__(self):
        if self.status >= 400:
            import urllib.error
            err = urllib.error.HTTPError("u", self.status, "e", {}, None)
            err.read = lambda n=0: self._body  # type: ignore
            raise err
        return self

    def __exit__(self, *a):
        return False


def test_detects_a_distinct_vhost():
    opener = FakeOpener({"internal.target.test": (200, b"SECRET INTERNAL APP")})
    res = vhost.probe("http://10.0.0.1/", ["internal.target.test", "api.target.test"], opener)
    hosts = [v["host"] for v in res["vhosts"]]
    assert "internal.target.test" in hosts
    # api.target.test returns the default page -> not flagged
    assert "api.target.test" not in hosts


def test_host_insensitive_server_yields_nothing():
    # every host (including the two random baselines) gets the SAME default page
    opener = FakeOpener({})
    res = vhost.probe("http://10.0.0.1/", ["a.target.test", "b.target.test"], opener)
    assert res["vhosts"] == []


def test_noisy_server_bails_with_a_note():
    opener = FakeOpener({}, noisy=True)   # random hosts differ from each other
    res = vhost.probe("http://10.0.0.1/", ["a.target.test"], opener)
    assert res["vhosts"] == []
    assert "unreliable" in res["note"]


def test_proxy_blocked_candidate_is_ignored(monkeypatch):
    opener = FakeOpener({})

    real_get = vhost._get

    def fake_get(op, url, host):
        if host == "blocked.target.test":
            return {"status": 403, "len": 3, "hash": "x", "blocked": True}
        return real_get(op, url, host)

    monkeypatch.setattr(vhost, "_get", fake_get)
    res = vhost.probe("http://10.0.0.1/", ["blocked.target.test"], opener)
    assert res["vhosts"] == []
