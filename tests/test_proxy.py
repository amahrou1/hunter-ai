"""Real end-to-end tests of the scope proxy: mitmdump is started with the
addon and real HTTP/HTTPS requests are sent through it to local servers."""

import json
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunter import config, scope as sc
from hunter.proxy import ScopeProxy, mitmdump_bin

pytestmark = pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")


class Target:
    """Local stand-in for a target web server; records request headers."""

    def __init__(self, tls_dir=None):
        self.seen = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.seen.append((self.path, dict(self.headers)))
                body = b"hello from target"
                self.send_response(200)
                self.send_header("content-type", "text/plain")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls_dir is not None:
            cert, key = tls_dir / "cert.pem", tls_dir / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=127.0.0.1", "-keyout", str(key), "-out", str(cert)],
                           check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def proxy_env(env, tmp_path):
    scope = sc.Scope(
        in_scope=[sc.parse_asset("127.0.0.1")],
        out_of_scope=[],
        rules={"effective_rps": 50, "required_headers": {"X-Bug-Bounty": "amahrou1"}},
    )
    scope_file = tmp_path / "out" / "scope.json"
    sc.save(scope, scope_file)
    settings = config.load_settings()
    proxy = ScopeProxy(scope_file, tmp_path / "out" / "logs", settings)
    proxy.start()
    yield proxy, scope_file
    proxy.stop()


def _opener(proxy, cafile=None):
    handlers = [urllib.request.ProxyHandler({"http": proxy.url, "https": proxy.url})]
    if cafile:
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))
    return urllib.request.build_opener(*handlers)


def _log(proxy):
    deadline = time.time() + 5
    while time.time() < deadline:
        if proxy.traffic_log.exists() and proxy.traffic_log.read_text().strip():
            break
        time.sleep(0.1)
    return [json.loads(line) for line in proxy.traffic_log.read_text().splitlines() if line.strip()]


def test_self_test_passes(proxy_env):
    proxy, _ = proxy_env
    ok, message = proxy.self_test()
    assert ok, message


def test_in_scope_request_passes_with_required_header(proxy_env):
    proxy, _ = proxy_env
    target = Target()
    try:
        body = _opener(proxy).open(f"http://127.0.0.1:{target.port}/hello?x=1", timeout=10).read()
        assert body == b"hello from target"
        path, headers = target.seen[0]
        assert path == "/hello?x=1"
        assert headers.get("X-Bug-Bounty") == "amahrou1"
    finally:
        target.close()
    entry = [e for e in _log(proxy) if e["host"] == "127.0.0.1"][0]
    assert entry["status"] == 200 and entry["blocked"] is None
    assert entry["resp_body"] == "hello from target"


def test_out_of_scope_http_never_reaches_target(proxy_env):
    proxy, _ = proxy_env
    target = Target()
    try:
        with pytest.raises(urllib.error.HTTPError) as exc:
            _opener(proxy).open(f"http://localhost:{target.port}/secret", timeout=10)
        assert exc.value.code == 403
        assert exc.value.headers["X-Hunter-Blocked"] == "not in scope"
        assert target.seen == []
    finally:
        target.close()
    assert any(e["blocked"] for e in _log(proxy))


def test_https_in_and_out_of_scope(proxy_env, tmp_path):
    proxy, _ = proxy_env
    target = Target(tls_dir=tmp_path)
    try:
        body = _opener(proxy, cafile=str(proxy.ca_bundle)).open(
            f"https://127.0.0.1:{target.port}/tls", timeout=15).read()
        assert body == b"hello from target"
        assert target.seen[0][1].get("X-Bug-Bounty") == "amahrou1"
        with pytest.raises(urllib.error.URLError) as exc:
            _opener(proxy, cafile=str(proxy.ca_bundle)).open(f"https://localhost:{target.port}/", timeout=15)
        assert "403" in str(exc.value)
        assert len(target.seen) == 1
    finally:
        target.close()


def test_scope_change_is_picked_up_live(proxy_env):
    proxy, scope_file = proxy_env
    target = Target()
    try:
        _opener(proxy).open(f"http://127.0.0.1:{target.port}/a", timeout=10).read()
        new = sc.Scope(in_scope=[sc.parse_asset("10.9.9.9")], rules={"effective_rps": 50})
        time.sleep(1.1)  # make sure the file time changes
        sc.save(new, scope_file)
        with pytest.raises(urllib.error.HTTPError) as exc:
            _opener(proxy).open(f"http://127.0.0.1:{target.port}/b", timeout=10)
        assert exc.value.code == 403
        assert [p for p, _ in target.seen] == ["/a"]
    finally:
        target.close()


def test_rate_limit_is_enforced(env, tmp_path):
    scope = sc.Scope(in_scope=[sc.parse_asset("127.0.0.1")], rules={"effective_rps": 4})
    scope_file = tmp_path / "scope.json"
    sc.save(scope, scope_file)
    target = Target()
    with ScopeProxy(scope_file, tmp_path / "logs", config.load_settings()) as proxy:
        opener = _opener(proxy)
        started = time.monotonic()
        for i in range(12):
            opener.open(f"http://127.0.0.1:{target.port}/{i}", timeout=10).read()
        elapsed = time.monotonic() - started
    target.close()
    # 4 burst + 8 more at 4/s = at least 2 seconds.
    assert elapsed >= 1.8, elapsed


def test_env_routes_tools_through_proxy(proxy_env):
    proxy, _ = proxy_env
    env = proxy.env(base={"PATH": "/bin"})
    assert env["HTTPS_PROXY"] == proxy.url and env["http_proxy"] == proxy.url
    assert "api.z.ai" in env["NO_PROXY"]
    assert env["SSL_CERT_FILE"] == str(proxy.ca_bundle)
    assert "BEGIN CERTIFICATE" in proxy.ca_bundle.read_text()


def test_curl_through_proxy_with_bundle(proxy_env, tmp_path):
    """The way real tools will use it: curl with only the proxy env set."""
    proxy, _ = proxy_env
    target = Target(tls_dir=tmp_path)
    try:
        env = proxy.env()
        out = subprocess.run(["curl", "-sS", f"https://127.0.0.1:{target.port}/curl"],
                             env=env, capture_output=True, text=True, timeout=30)
        assert out.stdout == "hello from target", out.stderr
        blocked = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                                  f"http://localhost:{target.port}/"], env=env,
                                 capture_output=True, text=True, timeout=30)
        assert blocked.stdout == "403"
    finally:
        target.close()


def test_operator_avoid_is_enforced_live(proxy_env):
    """`hunt tell ... avoid x` writes avoid.json; the running guard blocks x
    at once, without restarting the run or rewriting scope.json."""
    proxy, scope_file = proxy_env
    target = Target()
    try:
        _opener(proxy).open(f"http://127.0.0.1:{target.port}/before", timeout=10).read()
        sc.save_avoid(scope_file.parent, ["127.0.0.1"])
        with pytest.raises(urllib.error.HTTPError) as exc:
            _opener(proxy).open(f"http://127.0.0.1:{target.port}/after", timeout=10)
        assert exc.value.code == 403
        assert exc.value.headers["X-Hunter-Blocked"].startswith("you told it to avoid this")
        sc.save_avoid(scope_file.parent, [])
        _opener(proxy).open(f"http://127.0.0.1:{target.port}/again", timeout=10).read()
        assert [p for p, _ in target.seen] == ["/before", "/again"]
    finally:
        target.close()


def test_user_agent_tag_is_appended_not_replaced(env, tmp_path):
    """bol: "append <username>@intigriti.me to the User-Agent header". The
    tag is added to a browser agent; library agents get a browser agent."""
    scope = sc.Scope(in_scope=[sc.parse_asset("127.0.0.1")],
                     rules={"effective_rps": 50, "required_headers": {"User-Agent": "amahrou1@intigriti.me"}})
    scope_file = tmp_path / "out" / "scope.json"
    sc.save(scope, scope_file)
    proxy = ScopeProxy(scope_file, tmp_path / "out" / "logs", config.load_settings())
    proxy.start()
    target = Target()
    try:
        opener = _opener(proxy)
        opener.open(f"http://127.0.0.1:{target.port}/lib", timeout=10).read()
        opener.addheaders = [("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Firefox/130.0")]
        opener.open(f"http://127.0.0.1:{target.port}/browser", timeout=10).read()
        agents = [h.get("User-Agent") for _, h in target.seen]
        assert agents[0].startswith("Mozilla/5.0") and agents[0].endswith(" amahrou1@intigriti.me")
        assert "Python-urllib" not in agents[0]
        assert agents[1] == "Mozilla/5.0 (Windows NT 10.0) Firefox/130.0 amahrou1@intigriti.me"
        # exact mode, picked up live
        scope.rules["user_agent_mode"] = "exact"
        time.sleep(1.1)
        sc.save(scope, scope_file)
        opener.open(f"http://127.0.0.1:{target.port}/exact", timeout=10).read()
        assert target.seen[-1][1].get("User-Agent") == "amahrou1@intigriti.me"
    finally:
        target.close()
        proxy.stop()
