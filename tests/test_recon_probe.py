"""Recon and probe phases, plus the tool runner, assets store and toolchain
resolver, with fake recon tools and a local HTTP target."""

import hashlib
import json
import socket
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from hunter import assets as A
from hunter import config, scope as sc
from hunter import state as st
from hunter.assets import Assets, classify_cname
from hunter.tools import ToolRunner, chunked


# --------------------------------------------------------------- tool runner

def _script(tmp_path, name, body):
    path = tmp_path / name
    path.write_text("#!/usr/bin/env python3\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_tool_runner_streams_and_times_out(tmp_path):
    runner = ToolRunner(tmp_path / "w", tmp_path / "l")
    printer = _script(tmp_path, "printer",
                      "import sys\n[print(f'line {i}') for i in range(5)]\n")
    run = runner.run("printer", ["python3", str(printer)], name="p1", timeout_s=30)
    assert run.ok and run.out_lines == 5
    assert list(run.lines())[0] == "line 0"

    hanger = _script(tmp_path, "hanger", "import time\nprint('started')\ntime.sleep(60)\n")
    slow = runner.run("hanger", ["python3", str(hanger)], name="p2", timeout_s=1)
    assert slow.timed_out and not slow.ok


def test_tool_runner_reports_missing_binary(tmp_path):
    run = ToolRunner(tmp_path / "w", tmp_path / "l").run("nope", ["/no/such/bin"], name="x")
    assert not run.ok and "not installed" in run.error


def test_tool_runner_stdin_and_json(tmp_path):
    echo = _script(tmp_path, "echo",
                   "import sys,json\n[print(json.dumps({'host': l.strip()})) for l in sys.stdin if l.strip()]\n")
    run = ToolRunner(tmp_path / "w", tmp_path / "l").run(
        "echo", ["python3", str(echo)], name="e", stdin_lines=["a.com", "b.com"])
    assert [r["host"] for r in run.json_lines()] == ["a.com", "b.com"]


def test_chunked():
    assert list(chunked([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


# ------------------------------------------------------------- assets store

def _assets(tmp_path):
    db = st.State(tmp_path / "s.db").db
    return Assets(db)


def test_classify_cname():
    assert classify_cname("foo.zendesk.com") == ("zendesk.com", True)
    assert classify_cname("x.cloudfront.net")[0] == "cloudfront.net"
    assert classify_cname("origin.acme.com") == (None, False)


def test_assets_hosts_and_scope(tmp_path):
    store = _assets(tmp_path)
    assert store.add_host("a.acme.com", A.IN, "subfinder") is True
    assert store.add_host("a.acme.com", A.IN, "subfinder") is False  # dedup
    store.set_resolution("a.acme.com", ["1.2.3.4"], cname="")
    store.add_host("help.acme.com", A.IN, "subfinder")
    store.set_resolution("help.acme.com", ["5.6.7.8"], cname="acme.zendesk.com")
    assert store.host_counts()[A.THIRD_PARTY] == 1
    assert store.hosts(scope=A.IN, resolved=True)[0]["host"] == "a.acme.com"
    store.add_host("dangling.acme.com", A.IN, "subfinder")
    store.set_resolution("dangling.acme.com", [], cname="unclaimed.github.io")
    assert [r["host"] for r in store.takeover_candidates()] == ["dangling.acme.com", "help.acme.com"]


def test_assets_services(tmp_path):
    store = _assets(tmp_path)
    store.upsert_service("a.acme.com", 443, "https", status=200, title="Home", priority=70)
    store.upsert_service("a.acme.com", 443, "https", status=301)  # update
    assert store.service_count() == 1
    assert store.services()[0]["status"] == 301
    store.set_baseline(store.services()[0]["id"], {"kind": "soft_404"})
    assert json.loads(store.services()[0]["baseline"])["kind"] == "soft_404"


# ----------------------------------------------------------------- toolchain

def test_toolchain_asset_names():
    from hunter import toolchain
    sub = toolchain.TOOLS_BY_NAME["subfinder"]
    assert sub.asset.format(v="2.6.6", os="linux", arch="amd64") == "subfinder_2.6.6_linux_amd64.zip"
    assert toolchain.TOOLS_BY_NAME["ffuf"].archive == "tar.gz"


def test_toolchain_pick_member():
    from hunter.toolchain import _pick_member
    assert _pick_member(["subfinder", "LICENSE"], "subfinder") == "subfinder"
    assert _pick_member(["dist/httpx", "README"], "httpx") == "dist/httpx"
    with pytest.raises(RuntimeError):
        _pick_member(["README"], "ffuf")


# ------------------------------------------------------- recon & probe phases

class LocalTarget:
    """Serves a home page, a stable 404, and a gate path, so baselines can be
    classified. Records which paths were requested."""

    def __init__(self, tls_dir=None):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.seen.append(self.path)
                if self.path == "/":
                    body, code = b"<html>home page of acme</html>", 200
                elif self.path.startswith("/gate"):
                    body, code = b"forbidden", 403
                else:
                    body, code = b"<html>not found, sorry</html>", 404
                self.send_response(code)
                self.send_header("content-type", "text/html")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        if tls_dir is not None:
            import ssl
            import subprocess
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


def _fake_tools(tmp_path, host, port):
    """Create fake subfinder/dnsx/httpx that behave like the real ones for
    one host that lives at 127.0.0.1:<port>."""
    d = tmp_path / "tools"
    d.mkdir()
    sub = d / "subfinder"
    sub.write_text("#!/usr/bin/env python3\n"
                   "import sys, json\n"
                   f"print(json.dumps({{'host': '{host}'}}))\n")
    dnsx = d / "dnsx"
    dnsx.write_text("#!/usr/bin/env python3\n"
                    "import sys, json\n"
                    "for line in sys.stdin:\n"
                    "    h = line.strip()\n"
                    "    if not h: continue\n"
                    "    cname = ['acme.zendesk.com'] if h.startswith('help') else []\n"
                    "    print(json.dumps({'host': h, 'a': ['127.0.0.1'], 'cname': cname}))\n")
    httpx = d / "httpx"
    # Ignores ports/flags; probes 127.0.0.1:<port> for each stdin host via the proxy env.
    httpx.write_text("#!/usr/bin/env python3\n"
                     "import sys, json, urllib.request, os\n"
                     f"PORT = {port}\n"
                     "proxy = os.environ.get('HTTPS_PROXY')\n"
                     "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy}) if proxy else urllib.request.ProxyHandler({}))\n"
                     "for line in sys.stdin:\n"
                     "    h = line.strip()\n"
                     "    if not h: continue\n"
                     "    url = f'http://127.0.0.1:{PORT}/'\n"
                     "    try:\n"
                     "        r = opener.open(url, timeout=10); body = r.read(); status = r.status\n"
                     "    except Exception: status, body = 0, b''\n"
                     "    import hashlib\n"
                     "    print(json.dumps({'input': h, 'url': url, 'host': '127.0.0.1', 'port': PORT,\n"
                     "        'status_code': status, 'title': 'acme', 'webserver': 'test',\n"
                     "        'tech': ['Flask'], 'content_type': 'text/html', 'content_length': len(body),\n"
                     "        'hash': {'body_sha256': hashlib.sha256(body).hexdigest()}}))\n")
    for f in (sub, dnsx, httpx):
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return d


@pytest.fixture
def recon_target(env, make_target, tmp_path, monkeypatch):
    from hunter.proxy import mitmdump_bin
    if mitmdump_bin() is None:
        pytest.skip("mitmproxy not installed")
    target = make_target("acme", policy="In scope: *.acme-test.io and 127.0.0.1\nOut of scope: none")
    # Scope written directly (skip the intake AI): wildcard + loopback for the local target.
    scope = sc.Scope(
        in_scope=[sc.parse_asset("*.acme-test.io"), sc.parse_asset("127.0.0.1")],
        rules={"effective_rps": 50, "required_headers": {}},
        program={"name": "Acme", "platform": "intigriti"},
    )
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(scope, target.scope_file)
    state = st.State(target.state_db)
    state.ensure_phase("00-intake", "intake")
    state.finish_phase("00-intake", st.DONE, "scope ready")
    state.close()
    tools = _fake_tools(tmp_path, "www.acme-test.io", 0)
    monkeypatch.setenv("HUNTER_TOOLS_DIR", str(tools))
    return target, tools


def _ctx(target, settings, notifier):
    from hunter.phases.base import Context
    state = st.State(target.state_db)
    settings["run"]["blocker_wait_minutes"] = 0
    return Context(target, state, settings, {"GLM_API_KEY": "k"}, notifier)


def test_recon_classifies_and_resolves(recon_target, settings_secrets, notifier, tmp_path, monkeypatch):
    target, tools = recon_target
    # subfinder returns a third-party host too.
    (tools / "subfinder").write_text(
        "#!/usr/bin/env python3\nimport json\n"
        "print(json.dumps({'host': 'www.acme-test.io'}))\n"
        "print(json.dumps({'host': 'help.acme-test.io'}))\n")
    (tools / "subfinder").chmod(0o755)
    from hunter.phases import ReconPhase
    ctx = _ctx(target, settings_secrets[0], notifier)
    ctx.phase_id = "02-recon"
    result = ReconPhase().run(ctx)
    ctx.close()
    store = Assets(st.State(target.state_db).db)
    assert result.status in (st.DONE, st.PARTIAL)
    counts = store.host_counts()
    assert counts.get(A.IN, 0) >= 1
    assert counts.get(A.THIRD_PARTY, 0) == 1           # help.* -> zendesk
    assert [r["host"] for r in store.takeover_candidates()] == ["help.acme-test.io"]
    recon = json.loads((target.output / "recon.json").read_text())
    assert "www.acme-test.io" in recon["in_scope_resolved"]
    assert "Recon done" in notifier.titles()


def test_probe_builds_services_and_baselines(recon_target, settings_secrets, notifier, tmp_path):
    target, tools = recon_target
    local = LocalTarget()
    # Point the fake httpx at the live local port.
    httpx = (tools / "httpx").read_text().replace("PORT = 0", f"PORT = {local.port}")
    (tools / "httpx").write_text(httpx)
    (tools / "httpx").chmod(0o755)
    try:
        store = Assets(st.State(target.state_db).db)
        store.add_host("www.acme-test.io", A.IN, "seed")
        store.set_resolution("www.acme-test.io", ["127.0.0.1"], "")
        store.db.commit()
        from hunter.phases import ProbePhase
        ctx = _ctx(target, settings_secrets[0], notifier)
        ctx.phase_id = "03-probe"
        result = ProbePhase().run(ctx)
        ctx.close()
    finally:
        local.close()
    assert result.status == st.DONE, result.summary
    store = Assets(st.State(target.state_db).db)
    svc = store.services()[0]
    assert svc["status"] == 200 and svc["server"] == "test"
    baseline = json.loads(svc["baseline"])
    assert baseline["kind"] in ("hard_404", "soft_404", "soft_404_like_root")
    assert "/" in local.seen and any("hunter-" in p for p in local.seen)  # baseline probes happened
    assert (target.output / "services.txt").exists()
    assert "Probe done" in notifier.titles()


def test_probe_is_incremental_and_focus_first(recon_target, settings_secrets, notifier, tmp_path):
    """A second probe only touches hosts not probed yet (a resumed run or a
    host added with hunt tell), keeps old baselines, and ranks focus hosts first."""
    from hunter.instructions import Operator
    from hunter.phases import ProbePhase
    target, tools = recon_target
    local = LocalTarget()
    asked = tmp_path / "asked.txt"
    httpx = (tools / "httpx").read_text().replace("PORT = 0", f"PORT = {local.port}").replace(
        "    if not h: continue\n",
        f"    if not h: continue\n    open('{asked}', 'a').write(h + '\\n')\n", 1)
    (tools / "httpx").write_text(httpx)
    (tools / "httpx").chmod(0o755)

    def probe():
        ctx = _ctx(target, settings_secrets[0], notifier)
        ctx.phase_id = "03-probe"
        try:
            return ProbePhase().run(ctx)
        finally:
            ctx.close()
            ctx.state.close()

    try:
        state = st.State(target.state_db)
        store = Assets(state.db)
        store.add_host("www.acme-test.io", A.IN, "seed")
        store.set_resolution("www.acme-test.io", ["127.0.0.1"], "")
        state.close()
        assert probe().status == st.DONE
        first_baselines = len([p for p in local.seen if "hunter-" in p])

        state = st.State(target.state_db)
        store = Assets(state.db)
        store.add_host("api.acme-test.io", A.IN, "seed")
        store.set_resolution("api.acme-test.io", ["127.0.0.1"], "")
        Operator(target, state).submit("focus api.acme-test.io")
        state.close()
        assert probe().status == st.DONE
    finally:
        local.close()
    assert asked.read_text().split() == ["www.acme-test.io", "api.acme-test.io"]
    # Two baseline requests per service: only the new service got them.
    assert len([p for p in local.seen if "hunter-" in p]) == first_baselines + 2
    top = Assets(st.State(target.state_db).db).services()[0]
    assert top["host"] == "api.acme-test.io" and top["priority"] == 100


def test_https_baseline_through_guard(recon_target, settings_secrets, notifier, tmp_path):
    """HTTPS baselines go through the guard, which re-signs TLS. They must
    reach the target (bol run: every HTTPS service came back 'unknown')."""
    from hunter.phases import ProbePhase
    target, _ = recon_target
    local = LocalTarget(tls_dir=tmp_path)
    try:
        state = st.State(target.state_db)
        store = Assets(state.db)
        store.upsert_service("127.0.0.1", local.port, "https", url=f"https://127.0.0.1:{local.port}",
                             baseline=json.dumps({"kind": "unknown"}))   # left by the old bug
        state.close()
        ctx = _ctx(target, settings_secrets[0], notifier)
        ctx.phase_id = "03-probe"
        try:
            done = ProbePhase()._baselines(ctx, Assets(ctx.state.db))
        finally:
            ctx.close()
            ctx.state.close()
    finally:
        local.close()
    assert done == 1
    svc = Assets(st.State(target.state_db).db).services()[0]
    assert json.loads(svc["baseline"])["kind"] == "hard_404"
    assert any("hunter-" in p for p in local.seen)


def test_migration_after_finished_probe_marks_all_probed(tmp_path):
    import sqlite3
    db = sqlite3.connect(str(tmp_path / "s.db"), isolation_level=None)
    db.row_factory = sqlite3.Row
    st_schema = st.SCHEMA
    db.executescript(st_schema)
    db.execute("INSERT INTO phases(phase_id, name, status) VALUES('03-probe', 'probe', 'DONE')")
    db.execute("CREATE TABLE hosts (host TEXT PRIMARY KEY, scope TEXT NOT NULL, source TEXT, resolved INTEGER "
               "NOT NULL DEFAULT 0, addresses TEXT, cname TEXT, third_party_reason TEXT, takeover_candidate "
               "INTEGER NOT NULL DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, notes TEXT)")
    for host in ("live.a.test", "dead.a.test"):
        db.execute("INSERT INTO hosts(host, scope, resolved, first_seen, last_seen) VALUES(?, ?, 1, 'x', 'x')",
                   (host, A.IN))
    assert Assets(db).unprobed_hosts() == []
