"""Phases 04 (crawl) and 05 (content discovery), end to end through the
real scope proxy against a local site. Uses the real katana/ffuf binaries
when HUNTER_REAL_TOOLS points at a folder holding them; otherwise small
fakes that speak the same JSON."""

import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from hunter import assets as A
from hunter import scope as sc
from hunter import state as st
from hunter.assets import Assets

SECRET = "s3cr3t-value-never-copied"


class Site:
    """index -> /products?id=1, a login form, /static/app.js, robots.txt;
    an exposed .git/HEAD and .env; everything else a stable 404."""

    def __init__(self):
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.seen.append(self.path)
                port = outer.port
                pages = {
                    "/": ("text/html", f'<html><a href="/products?id=1">p</a>'
                          f'<a href="http://localhost:{port}/elsewhere">out</a>'
                          '<form action="/login" method="post"><input name="user"><input name="pass"></form>'
                          '<script src="/static/app.js"></script></html>'),
                    "/products?id=1": ("text/html", "<html>products</html>"),
                    "/static/app.js": ("text/javascript", 'fetch("/api/v1/orders")'),
                    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\n"),
                    "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
                    "/.env": ("text/plain", f"DB_PASSWORD={SECRET}\nAPI_KEY={SECRET}\n"),
                    "/admin": ("text/html", "<html>admin login</html>"),
                }
                ctype, body = pages.get(self.path, ("text/html", "<html>not found</html>"))
                code = 200 if self.path in pages else 404
                data = body.encode()
                self.send_response(code)
                self.send_header("content-type", ctype)
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


def _fake_tools(folder: Path, port: int):
    folder.mkdir()
    katana = folder / "katana"
    katana.write_text(
        "#!/usr/bin/env python3\nimport sys, json, urllib.request\n"
        "args = sys.argv; proxy = args[args.index('-proxy') + 1]\n"
        "op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy}))\n"
        "for line in sys.stdin:\n"
        "    base = line.strip().rstrip('/')\n"
        "    if not base: continue\n"
        f"    for path in ['/', '/products?id=1', '/static/app.js', 'http://localhost:{port}/elsewhere']:\n"
        "        url = path if path.startswith('http') else base + path\n"
        "        try: r = op.open(url, timeout=10); code = r.status; ct = r.headers.get('content-type')\n"
        "        except Exception as e: code = getattr(e, 'code', 0); ct = ''\n"
        "        rec = {'request': {'method': 'GET', 'endpoint': url, 'tag': 'script' if path.endswith('.js') else 'a'},\n"
        "               'response': {'status_code': code, 'headers': {'content-type': ct}}}\n"
        "        if path == '/':\n"
        "            rec['response']['forms'] = [{'method': 'POST', 'action': base + '/login', 'parameters': ['user', 'pass']}]\n"
        "        print(json.dumps(rec), flush=True)\n")
    ffuf = folder / "ffuf"
    ffuf.write_text(
        "#!/usr/bin/env python3\nimport sys, json, urllib.request\n"
        "a = sys.argv; base = a[a.index('-u') + 1]; words = open(a[a.index('-w') + 1]).read().split()\n"
        "proxy = a[a.index('-x') + 1]\n"
        "op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy}))\n"
        "for w in words:\n"
        "    url = base.replace('FUZZ', w)\n"
        "    try: r = op.open(url, timeout=10); code = r.status; body = r.read()\n"
        "    except Exception as e: code = getattr(e, 'code', 0); body = b''\n"
        "    if code == 200:\n"
        "        print(json.dumps({'url': url, 'status': code, 'length': len(body), 'content-type': ''}), flush=True)\n")
    for f in (katana, ffuf):
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return folder


@pytest.fixture
def site_target(env, make_target, tmp_path, monkeypatch):
    from hunter.proxy import mitmdump_bin
    if mitmdump_bin() is None:
        pytest.skip("mitmproxy not installed")
    site = Site()
    target = make_target("acme", policy="In scope: 127.0.0.1 only. Out of scope: everything else.")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("127.0.0.1")], rules={"effective_rps": 50}), target.scope_file)
    state = st.State(target.state_db)
    store = Assets(state.db)
    store.add_host("127.0.0.1", A.IN, "test")
    store.set_resolution("127.0.0.1", ["127.0.0.1"])
    store.upsert_service("127.0.0.1", site.port, "http", url=f"http://127.0.0.1:{site.port}", status=200,
                         baseline=json.dumps({"kind": "hard_404", "sample": {"status": 404, "len": 22}}))
    state.close()
    real = os.environ.get("HUNTER_REAL_TOOLS")
    tools = Path(real) if real else _fake_tools(tmp_path / "tools", site.port)
    monkeypatch.setenv("HUNTER_TOOLS_DIR", str(tools))
    yield target, site
    site.close()


def _run(phase, target, settings, notifier):
    from hunter.phases.base import Context
    state = st.State(target.state_db)
    ctx = Context(target, state, settings, {"GLM_API_KEY": "k"}, notifier)
    ctx.phase_id = phase.id
    try:
        return phase.run(ctx)
    finally:
        ctx.close()
        state.close()


def test_map_crawls_through_guard_and_resumes(site_target, settings_secrets, notifier):
    from hunter.phases import MapPhase
    target, site = site_target
    settings = settings_secrets[0]
    settings["crawl"] = {"minutes_per_site": 1}
    result = _run(MapPhase(), target, settings, notifier)
    assert result.status == st.DONE, result.summary
    store = Assets(st.State(target.state_db).db)
    urls = {(r["method"], r["url"].split(f":{site.port}")[-1]) for r in store.endpoints()}
    assert ("GET", "/products?id=1") in urls
    assert ("POST", "/login") in urls                      # form recorded
    assert not any("/login" == p for p in site.seen)       # ...but never submitted
    assert not any("localhost" in r["url"] for r in store.endpoints())
    js = (target.output / "js_files.txt").read_text()
    assert "app.js" in js
    assert "id   <- interesting" in (target.output / "params.txt").read_text()
    assert "Mapping done" in notifier.titles()
    # Resume: nothing left to crawl, the tool is not run again.
    seen_before = len(site.seen)
    assert _run(MapPhase(), target, settings, notifier).status == st.DONE
    assert len(site.seen) == seen_before


def test_discover_finds_hidden_files_and_checks_content(site_target, settings_secrets, notifier):
    from hunter.phases import DiscoverPhase
    target, site = site_target
    settings = settings_secrets[0]
    settings["discover"] = {"minutes_per_site": 1}
    result = _run(DiscoverPhase(), target, settings, notifier)
    assert result.status == st.DONE, result.summary
    store = Assets(st.State(target.state_db).db)
    leads = {r["kind"]: r for r in store.leads()}
    assert leads["exposed-git"]["status"] == "signature-match"
    assert "variables: API_KEY, DB_PASSWORD" == leads["env-file"]["evidence"]
    everything = json.dumps(notifier.sent) + (target.output / "leads.txt").read_text()
    assert SECRET not in everything                         # values never copied
    assert any(r["url"].endswith("/admin") for r in store.endpoints())
    assert "Discovery done" in notifier.titles()


def test_work_services_skips_gates_dead_and_duplicate_scheme(tmp_path):
    import sqlite3
    db = sqlite3.connect(str(tmp_path / "s.db"), isolation_level=None)
    db.row_factory = sqlite3.Row
    store = Assets(db)
    gate = json.dumps({"kind": "uniform_gate"})
    store.upsert_service("a.acme.test", 443, "https", status=200, priority=60)
    store.upsert_service("a.acme.test", 80, "http", status=200, priority=60)      # same site, http
    store.upsert_service("b.acme.test", 443, "https", status=502, priority=90)    # dead upstream
    store.upsert_service("c.acme.test", 443, "https", status=403, baseline=gate, priority=90)
    store.upsert_service("d.acme.test", 8443, "https", status=200, priority=100)
    store.upsert_service("e.acme.test", 443, "https", status=200, priority=0)     # avoided
    scope = sc.Scope(in_scope=[sc.parse_asset("*.acme.test")])
    assert [(r["host"], r["port"]) for r in store.work_services(scope, "crawled")] == [
        ("d.acme.test", 8443), ("a.acme.test", 443)]
