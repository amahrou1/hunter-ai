"""httpx import with --attempted marks EVERY attempted host probed, including
hosts that returned no record (dead / firewalled / non-web). Without this a
resolved host that does not serve HTTP stays 'unprobed' forever and the probe
phase can never finish - the Cornelsen stall, where 860 internal dev/stage
hosts resolved but answered no HTTP, so probe looped at ~1378/2238 every pass."""

from __future__ import annotations

import json

from hunter import assets as A
from hunter import scope as sc
from hunter import state as st
from hunter import importers


def _store(tmp_path):
    db = st.State(tmp_path / "state.db").db
    return A.Assets(db)


def _scope():
    return sc.Scope(in_scope=[sc.parse_asset("*.acme.test")])


def _httpx_file(tmp_path, responders):
    """A httpx jsonl where only `responders` produced a line (httpx omits
    non-responders), as real httpx output does."""
    path = tmp_path / "httpx.jsonl"
    with path.open("w") as fh:
        for host in responders:
            fh.write(json.dumps({
                "url": f"https://{host}", "input": host, "host": host,
                "port": 443, "status_code": 200, "title": "ok",
            }) + "\n")
    return path


def test_attempted_marks_dead_hosts_probed(env, tmp_path):
    store = _store(tmp_path)
    # 5 hosts resolved and handed to httpx; only 2 answer.
    attempted = [f"h{i}.acme.test" for i in range(5)]
    for h in attempted:
        store.add_host(h, A.IN, "dnsx")
        store.db.execute("UPDATE hosts SET resolved=1 WHERE host=?", (h,))
    store.db.commit()
    responders = ["h0.acme.test", "h1.acme.test"]
    path = _httpx_file(tmp_path, responders)

    res = importers.httpx(store, _scope(), path, attempted=set(attempted))

    # every attempted host is now probed - the 3 silent ones too
    assert store.unprobed_hosts() == []
    assert res["hosts_with_services"] == 2
    assert res["attempted_no_service"] == 3
    # only responders have a service row
    assert store.service_count() == 2


def test_without_attempted_only_responders_marked(env, tmp_path):
    """Legacy behaviour unchanged when --attempted is not passed: only hosts
    that answered are marked probed."""
    store = _store(tmp_path)
    for i in range(5):
        h = f"h{i}.acme.test"
        store.add_host(h, A.IN, "dnsx")
        store.db.execute("UPDATE hosts SET resolved=1 WHERE host=?", (h,))
    store.db.commit()
    path = _httpx_file(tmp_path, ["h0.acme.test", "h1.acme.test"])

    importers.httpx(store, _scope(), path)  # no attempted

    # the 3 silent hosts stay unprobed (old behaviour)
    assert len(store.unprobed_hosts()) == 3


def test_attempted_ignores_out_of_scope(env, tmp_path):
    """An out-of-scope host in the attempted list is not added or marked."""
    store = _store(tmp_path)
    store.add_host("in.acme.test", A.IN, "dnsx")
    store.db.execute("UPDATE hosts SET resolved=1 WHERE host=?", ("in.acme.test",))
    store.db.commit()
    path = _httpx_file(tmp_path, [])  # nobody answered
    attempted = {"in.acme.test", "evil.example.com"}

    res = importers.httpx(store, _scope(), path, attempted=attempted)

    assert res["attempted_no_service"] == 1          # only the in-scope one
    assert store.unprobed_hosts() == []              # in-scope host cleared
    assert "evil.example.com" not in {r["host"] for r in store.hosts()}
