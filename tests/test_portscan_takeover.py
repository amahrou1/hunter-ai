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


def test_accepts_everything_heuristic():
    assert portscan.accepts_everything(list(range(43)), 61)       # bol 79.170.100.x pattern
    assert not portscan.accepts_everything([22, 80, 443, 3306], 61)
    assert not portscan.accepts_everything(list(range(10)), 12)   # few ports scanned: not enough signal


def test_verify_silent_port_is_not_a_service():
    """A port that accepts the connection but never answers (firewall) is
    not reported as a service."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()
    try:
        assert portscan._exchange("127.0.0.1", srv.getsockname()[1], b"PING\r\n", timeout=2) == b""
    finally:
        srv.close()


def test_verify_checks_by_protocol(monkeypatch):
    replies = {6379: b"+PONG\r\n", 9200: b'HTTP/1.0 200 OK\r\n\r\n{"cluster_name": "x"}', 2375: b"HTTP/1.0 404\r\n\r\n",
               3306: b"\x4a\x00\x00\x00\x0a8.0.36\x00", 23: b"\xff\xfd\x18"}
    monkeypatch.setattr(portscan, "_exchange", lambda a, port, payload, timeout=4.0: replies[port])
    assert portscan.verify("10.0.0.1", 6379) == "Redis answers PING without a password"
    assert portscan.verify("10.0.0.1", 9200) == "Elasticsearch cluster info returned"
    assert portscan.verify("10.0.0.1", 2375) is None               # open, but not a Docker API
    assert portscan.verify("10.0.0.1", 3306).startswith("MySQL greeting: 8.0.36")
    assert portscan.verify("10.0.0.1", 23) == "Telnet banner"
    assert portscan.verify("10.0.0.1", 445) is None                # no check: stays unverified


def test_work_services_collapses_identical_pages(tmp_path):
    import sqlite3
    db = sqlite3.connect(str(tmp_path / "s.db"), isolation_level=None)
    db.row_factory = sqlite3.Row
    store = A.Assets(db)
    for i in range(20):                                             # LB default page on 20 IP:ports
        store.upsert_service(f"10.0.0.{i}", 8000 + i, "http", status=200, body_hash="same", priority=50)
    store.upsert_service("app.acme.test", 443, "https", status=200, body_hash="unique", priority=50)
    scope = sc.Scope(in_scope=[sc.parse_asset("10.0.0.0/24"), sc.parse_asset("*.acme.test")])
    chosen = store.work_services(scope, "crawled")
    assert len(chosen) == 3 and "app.acme.test" in {r["host"] for r in chosen}


def test_catch_all_address_gives_no_leads(make_target, settings_secrets, notifier, monkeypatch):
    """bol: 79.170.100.2 "had" Telnet, SMB, MS SQL, Oracle, Docker... open.
    An address answering on most ports is a firewall: no leads, and web
    services found on its other ports are dropped."""
    from hunter.phases import ProbePhase
    from hunter.phases.base import Context
    target = make_target("ipcorp")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("10.0.0.0/30")], rules={"effective_rps": 100}), target.scope_file)
    everything = list(portscan.PORTS)
    monkeypatch.setattr(portscan, "scan", lambda addrs, ports, rate, **kw: {
        "10.0.0.1": [p for p in everything if p in ports],      # answers everything
        "10.0.0.2": [443, 6379]})                                # a real host
    monkeypatch.setattr(portscan, "verify", lambda a, p, ua="": "Redis answers PING without a password"
                        if p == 6379 else None)
    state = st.State(target.state_db)
    store = A.Assets(state.db)
    store.add_host("10.0.0.1", A.IN, "portscan")
    store.upsert_service("10.0.0.1", 5432, "http", status=200)  # junk from an earlier scan
    store.add_lead("exposed-service", "tcp://10.0.0.1:23", "03-probe", "port 23 open (Telnet)")
    ctx = Context(target, state, settings_secrets[0], {"GLM_API_KEY": "k"}, notifier)
    ctx.phase_id = "03-probe"
    gaps = []
    ProbePhase()._portscan(ctx, store, sc.load(target.scope_file), gaps)
    leads = [(l["url"], l["status"]) for l in store.leads()]
    assert leads == [("tcp://10.0.0.2:6379", "signature-match")]
    assert store.host_note("10.0.0.1")["accepts_all"] is True
    assert store.host_note("10.0.0.1")["open_ports"] == [443, 80, 8443, 8080]
    assert not [s for s in store.services() if s["host"] == "10.0.0.1" and s["port"] == 5432]
    message = notifier.sent[-1][1]
    assert "accept a connection on every port" in message and "Redis answers PING" in message
    state.close()
