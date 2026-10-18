"""The notice-and-react layer: tripwires, the AI reviewer's allowlisted
actions, lead follow-up, and the discovery auto-filter."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hunter import assets as A
from hunter import review as R
from hunter import scope as sc
from hunter import state as st
from hunter.proxy import mitmdump_bin

pytestmark = pytest.mark.skipif(mitmdump_bin() is None, reason="mitmproxy not installed")


def test_tripwires_and_mask():
    assert R.same_response([{"status": 200, "length": 512}] * 40 + [{"status": 200, "length": 7}] * 4)
    assert not R.same_response([{"status": 200, "length": i} for i in range(40)])
    assert R.wildcard_dns({f"h{i}.x.test": ["1.2.3.4"] for i in range(60)}).kind == "wildcard-dns"
    assert R.block_wall([{"host": "a.test", "status": 403}] * 55 + [{"host": "a.test", "status": 200}] * 5)
    assert not R.block_wall([{"host": "a.test", "status": 403, "blocked": "out of scope"}] * 80)
    masked = R.mask("DB_PASSWORD=hunter2secret token: abcdef123456 AKIAABCDEFGHIJKLMNOP")
    assert "hunter2secret" not in masked and "abcdef123456" not in masked and "DB_PASSWORD" in masked


@pytest.fixture
def ctx(env, make_target, settings_secrets, notifier, monkeypatch, tmp_path):
    from hunter.phases.base import Context
    target = make_target("acme")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.acme.test"), sc.parse_asset("127.0.0.1")],
                     out_of_scope=[sc.parse_asset("legacy.acme.test")], rules={"effective_rps": 50}),
            target.scope_file)
    state = st.State(target.state_db)
    c = Context(target, state, settings_secrets[0], settings_secrets[1], notifier)
    c.phase_id = "05-discover"
    yield c
    c.close()
    state.close()


def _answer(monkeypatch, tmp_path, **files):
    pairs = []
    for name, data in files.items():
        path = tmp_path / f"answer-{name}"
        path.write_text(json.dumps(data))
        pairs.append(f"{name.replace('_', '.')}={path}")
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "files")
    monkeypatch.setenv("FAKE_CLAUDE_FILES", ";".join(pairs))


def test_reviewer_applies_allowed_actions_and_refuses_the_rest(ctx, monkeypatch, tmp_path, notifier, env):
    store = ctx.assets()
    store.add_host("app.acme.test", A.IN, "t")
    store.upsert_service("app.acme.test", 443, "https", url="https://app.acme.test", priority=50)
    store.add_endpoint("GET", "https://app.acme.test/x1", "discover", status=200, length=999)
    store.add_endpoint("GET", "https://app.acme.test/x2", "discover", status=200, length=999)
    store.add_endpoint("GET", "https://app.acme.test/real", "discover", status=200, length=42)
    _answer(monkeypatch, tmp_path, review_json={
        "verdict": "mixed", "assessment": "app answers many paths with one page. token=abcdef123456",
        "actions": [
            {"type": "filter_response", "host": "app.acme.test", "status": 200, "length": 999, "reason": "catch-all"},
            {"type": "add_endpoint", "method": "GET", "url": "https://app.acme.test/api/v1/users", "reason": "from js"},
            {"type": "focus", "host": "app.acme.test", "reason": "api"},
            {"type": "add_endpoint", "url": "https://evil.example/steal", "reason": "out of scope"},
            {"type": "focus", "host": "legacy.acme.test", "reason": "excluded host"},
            {"type": "raise_rate", "rps": 1000},
        ]})
    observation = {"hits_sample": [{"url": "https://app.acme.test/x1"}, {"url": "https://legacy.acme.test/"},
                                   {"url": "https://evil.example/steal"}]}
    outcome = R.Reviewer(ctx).review("discovery", observation)
    assert outcome.verdict == "mixed" and len(outcome.applied) == 3 and len(outcome.rejected) == 3
    urls = {r["url"] for r in store.endpoints()}
    assert "https://app.acme.test/x1" not in urls and "https://app.acme.test/real" in urls
    assert "https://app.acme.test/api/v1/users" in urls and "https://evil.example/steal" not in urls
    assert store.services()[0]["priority"] == 95
    assert R.Reviewer(ctx).filters("app.acme.test") == {(200, 999)}     # remembered for later
    title, message, _ = notifier.sent[-1]
    assert title == "Reviewed: discovery" and "abcdef123456" not in message
    row = ctx.state.db.execute("SELECT * FROM reviews").fetchone()
    assert row["verdict"] == "mixed"
    # The AI session ran with the guard's network settings.
    call = json.loads(env["record"].read_text().splitlines()[-1])
    assert call["env"]["HTTPS_PROXY"] == ctx.proxy().url


def test_review_failure_never_breaks_the_phase(ctx, monkeypatch):
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "noresult")
    outcome = R.Reviewer(ctx).review("crawl", {"sample": []})
    assert outcome.verdict == "skipped" and not outcome.applied


def test_follow_up_updates_lead_masks_secrets_and_keeps_scope(ctx, monkeypatch, tmp_path, notifier):
    store = ctx.assets()
    store.add_lead("api-docs", "https://app.acme.test/swagger.json", "05-discover", "OpenAPI", "signature-match")
    _answer(monkeypatch, tmp_path, lead_json={
        "status": "confirmed",
        "evidence": "GET /swagger.json returned 42 operations; example api_key=sk_live_abcdefghijklmnop",
        "impact": "Full API map including admin operations.",
        "endpoints": [{"method": "GET", "url": "https://app.acme.test/api/admin/users"},
                      {"method": "POST", "url": "https://app.acme.test/api/orders"},
                      {"method": "GET", "url": "https://legacy.acme.test/api"},
                      {"method": "GET", "url": "https://other.example/api"}],
        "next_steps": ["test /api/admin/users without a session"]})
    results = R.Reviewer(ctx).follow_up()
    lead = store.leads()[0]
    assert lead["status"] == "ai-confirmed" and "sk_live_abcdefghijklmnop" not in lead["evidence"]
    urls = {(r["method"], r["url"]) for r in store.endpoints()}
    assert urls == {("GET", "https://app.acme.test/api/admin/users"), ("POST", "https://app.acme.test/api/orders")}
    assert results and "Leads followed up" in notifier.titles()


class CatchAll:
    """Every path answers 200 with the same page (soft 404)."""

    def __init__(self):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b"<html>welcome</html>" if self.path != "/backup.zip" else b"PK\x03\x04zipdata"
                self.send_response(200)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def test_discovery_filters_a_catch_all_site_by_itself(ctx, tmp_path, monkeypatch):
    """The case from the old system: a fuzz returns hundreds of hits with the
    same status and length. They are recognised and filtered without help;
    the one real file (a different length) survives."""
    from hunter.phases import DiscoverPhase
    site = CatchAll()
    words = tmp_path / "words.txt"
    words.write_text("\n".join([f"path{i}" for i in range(60)] + ["backup.zip"]) + "\n")
    tools = tmp_path / "tools"
    tools.mkdir()
    ffuf = tools / "ffuf"
    ffuf.write_text(
        "#!/usr/bin/env python3\nimport sys, json, urllib.request\n"
        "a = sys.argv; base = a[a.index('-u') + 1]; words = open(a[a.index('-w') + 1]).read().split()\n"
        "op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': a[a.index('-x') + 1]}))\n"
        "for w in words:\n"
        "    url = base.replace('FUZZ', w); r = op.open(url, timeout=10); body = r.read()\n"
        "    print(json.dumps({'url': url, 'status': r.status, 'length': len(body)}), flush=True)\n")
    ffuf.chmod(0o755)
    monkeypatch.setenv("HUNTER_TOOLS_DIR", str(tools))
    ctx.settings["discover"] = {"wordlist": str(words), "minutes_per_site": 1}
    ctx.settings["review"] = {"enabled": False, "follow_up": False}
    store = ctx.assets()
    store.add_host("127.0.0.1", A.IN, "t")
    store.upsert_service("127.0.0.1", site.port, "http", url=f"http://127.0.0.1:{site.port}", status=200)
    try:
        result = DiscoverPhase().run(ctx)
    finally:
        site.close()
    hits = [r["url"] for r in store.endpoints() if r["source"] == "discover"]
    assert hits == [f"http://127.0.0.1:{site.port}/backup.zip"], result.summary
    assert R.Reviewer(ctx).filters("127.0.0.1") == {(200, 20)}
    assert [l["kind"] for l in store.leads()] == ["backup-file"]
