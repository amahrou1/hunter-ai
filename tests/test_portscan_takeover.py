import json
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunter import assets as A
from hunter import portscan, takeover
from hunter import scope as sc
from hunter import state as st


def test_plan_respects_scope_and_avoid(tmp_path):
    scope = sc.Scope(in_scope=[sc.parse_asset("10.0.0.0/29"), sc.parse_asset("10.9.9.9")],
                     out_of_scope=[sc.parse_asset("10.0.0.3")])
    scope.operator_out = [sc.parse_asset("10.0.0.4")]
    work = portscan.plan(scope, extra_ips=["10.0.0.5", "192.0.2.1", "not-an-ip"])
    assert work.addresses == ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6", "10.9.9.9"]
    assert "192.0.2.1" not in work.addresses          # seed outside scope: never touched
    assert work.ports[:2] == [443, 80] and not work.reduced


def test_plan_reduces_ports_for_large_ranges():
    scope = sc.Scope(in_scope=[sc.parse_asset("10.0.0.0/16")])
    work = portscan.plan(scope, max_probes=200_000)
    assert len(work.addresses) == 65534
    assert len(work.ports) == 3 and "large range" in work.reduced


def test_plan_ignores_domain_only_scope():
    scope = sc.Scope(in_scope=[sc.parse_asset("*.acme.test"), sc.parse_asset("www.acme.test")])
    assert portscan.plan(scope).addresses == []


def test_scan_finds_open_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        found = portscan.scan(["127.0.0.1"], [closed_port, port], rate=100)
    finally:
        listener.close()
    assert found == {"127.0.0.1": [port]}


class Page:
    def __init__(self, status, body, location=""):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(status)
                if location:
                    self.send_header("location", location)
                data = body.encode()
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), takeover._NoRedirect())


@pytest.mark.parametrize("status,body,location,verdict", [
    (404, "<h1>Sorry, this shop is currently unavailable.</h1>", "", "candidate"),
    (302, "", "/password", "cleared"),            # bol lowlands: password-protected shop, in use
    (200, "<html>Welcome to our store</html>", "", "cleared"),
])
def test_takeover_check(status, body, location, verdict, monkeypatch):
    page = Page(status, body, location)
    monkeypatch.setattr(takeover, "resolves", lambda name: True)
    try:
        got, reason = takeover.check(f"127.0.0.1:{page.port}", "shops.myshopify.com", _opener())
    finally:
        page.close()
    assert got == verdict, reason
    if location:
        assert "/password" in reason


def test_takeover_cname_target_gone(monkeypatch):
    monkeypatch.setattr(takeover, "resolves", lambda name: False)
    got, reason = takeover.check("old.acme.test", "acme-legacy.trafficmanager.net", _opener())
    assert got == "candidate" and "does not resolve" in reason


def test_probe_scans_ip_scope_and_probes_open_ports(env, make_target, settings_secrets, notifier, tmp_path,
                                                    monkeypatch):
    """IP-only program: the port scan finds a web server on an unusual port,
    probe fingerprints it, and a sensitive open port becomes a lead."""
    from hunter.phases import ProbePhase
    from hunter.phases.base import Context
    from hunter.proxy import mitmdump_bin
    if mitmdump_bin() is None:
        pytest.skip("mitmproxy not installed")
    page = Page(200, "<html><title>ip app</title>ok</html>")
    redis = socket.socket()
    redis.bind(("127.0.0.1", 0))
    redis.listen(4)
    target = make_target("ipcorp", policy="In scope: 127.0.0.1 (single IP). Nothing else.")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("127.0.0.1")], rules={"effective_rps": 100}), target.scope_file)
    tools = tmp_path / "tools"
    tools.mkdir()
    httpx = tools / "httpx"
    httpx.write_text(
        "#!/usr/bin/env python3\nimport sys, json, os, urllib.request\n"
        "op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': os.environ.get('HTTPS_PROXY')}))\n"
        "for line in sys.stdin:\n"
        "    t = line.strip()\n"
        "    if not t: continue\n"
        "    try: r = op.open('http://' + t + '/', timeout=5); body = r.read()\n"
        "    except Exception: continue\n"
        "    host, port = t.split(':')\n"
        "    print(json.dumps({'input': t, 'url': 'http://' + t, 'port': int(port), 'status_code': r.status,\n"
        "                      'title': 'ip app'}))\n")
    httpx.chmod(0o755)
    monkeypatch.setenv("HUNTER_TOOLS_DIR", str(tools))
    settings = settings_secrets[0]
    redis_port = redis.getsockname()[1]
    settings["portscan"] = {"ports": [page.port, redis_port]}
    monkeypatch.setitem(portscan.SENSITIVE_PORTS, redis_port, "Redis (test)")
    state = st.State(target.state_db)
    ctx = Context(target, state, settings, {"GLM_API_KEY": "k"}, notifier)
    ctx.phase_id = "03-probe"
    try:
        result = ProbePhase().run(ctx)
    finally:
        ctx.close()
        page.close()
        redis.close()
    assert result.status == st.DONE, result.summary
    store = A.Assets(state.db)
    assert [(s["host"], s["port"]) for s in store.services()] == [("127.0.0.1", page.port)]
    assert store.host_note("127.0.0.1")["open_ports"] == sorted([page.port, redis_port])
    assert [l["kind"] for l in store.leads()] == ["exposed-service"]
    assert "Port scan done" in notifier.titles()
    state.close()
