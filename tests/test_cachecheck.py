"""Web-cache poisoning/deception probe: flags unkeyed-header reflection and
static-suffix deception, detect-only, honours proxy blocks."""

from __future__ import annotations

import hashlib

from hunter import cachecheck


class FakeOpener:
    """handler(url, headers) -> (status, resp_headers, body)."""

    def __init__(self, handler):
        self.handler = handler

    def open(self, req, timeout=15):
        status, headers, body = self.handler(req.full_url, dict(req.headers))
        return _Resp(status, headers, body)


class _Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self._body = body

    def read(self, n=0):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_unkeyed_header_reflection_into_cacheable_response():
    def handler(url, headers):
        # reflect any X-Forwarded-Host marker, mark the response cacheable
        xfh = headers.get("X-Forwarded-Host") or headers.get("X-forwarded-host") or ""
        body = f"<html>home {xfh}</html>".encode()
        return 200, {"X-Cache": "HIT", "Content-Type": "text/html"}, body

    opener = FakeOpener(handler)
    res = cachecheck.probe("https://x.test/", opener)
    assert res["poisoning"], "should flag the reflected unkeyed header"
    assert any(p["cacheable"] for p in res["poisoning"])


def test_no_reflection_no_poisoning():
    def handler(url, headers):
        return 200, {"Cache-Control": "no-store"}, b"<html>static</html>"

    res = cachecheck.probe("https://x.test/", FakeOpener(handler))
    assert res["poisoning"] == []


def test_cache_deception_detected():
    page = b"<html>your private dashboard</html>"

    def handler(url, headers):
        # the base and the .css variant return the SAME page; .css makes it cacheable
        if url.rstrip("?").split("?")[0].endswith(".css") or ".css?" in url:
            return 200, {"X-Cache": "HIT"}, page
        return 200, {"Cache-Control": "private"}, page

    res = cachecheck.probe("https://x.test/account", FakeOpener(handler))
    assert res["deception"], "same dynamic page cacheable under .css should be flagged"


def test_proxy_block_is_ignored():
    def handler(url, headers):
        import urllib.error
        err = urllib.error.HTTPError(url, 403, "blocked", {"X-Hunter-Blocked": "scope"}, None)
        err.read = lambda n=0: b"blocked"
        raise err

    res = cachecheck.probe("https://x.test/", FakeOpener(handler))
    assert res["poisoning"] == [] and res["deception"] == []
