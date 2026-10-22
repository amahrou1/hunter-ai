"""Probe's completion check is grounded in truth: when essentially every
resolved in-scope host has been probed, the phase is DONE even if the agent's
narrative handoff is thin or it ran out of turns. Without this a fully-probed
run loops PARTIAL for hours re-probing nothing (the Mercedes symptom: 4741/4743
hosts probed yet stuck PARTIAL across multi-hour retries)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hunter import assets as A
from hunter import state as st
from hunter.phases.ai_probe import AIProbePhase


def _store(tmp_path):
    db = st.State(tmp_path / "state.db").db
    return A.Assets(db)


def _ctx(tmp_path):
    output = tmp_path / "out"
    # cluster disabled: check() skips _cluster and needs only target.output + settings
    return SimpleNamespace(target=SimpleNamespace(output=output),
                           settings={"cluster": {"enabled": False}})


def _add_resolved_probed(store, host, *, probed, with_service):
    store.add_host(host, A.IN, "test")
    store.db.execute("UPDATE hosts SET resolved=1, probed=? WHERE host=?", (int(probed), host))
    if with_service:
        store.upsert_service(host, 443, "https", status=200, title="ok")
    store.db.commit()


def test_fully_probed_run_is_done_even_without_handoff(env, tmp_path):
    store = _store(tmp_path)
    # 200 resolved hosts, all probed, all with a service; NO handoff.md written.
    for i in range(200):
        _add_resolved_probed(store, f"h{i}.api.acme.test", probed=True, with_service=True)
    phase = AIProbePhase()
    res = phase.check(_ctx(tmp_path), store)
    assert res.status == st.DONE, res.summary


def test_tiny_unprobed_tail_does_not_hold_phase_open(env, tmp_path):
    store = _store(tmp_path)
    for i in range(400):
        _add_resolved_probed(store, f"h{i}.api.acme.test", probed=True, with_service=True)
    # 2 hosts never came back (DNS flap / timeout) - well under the 0.5% tolerance
    _add_resolved_probed(store, "flap1.api.acme.test", probed=False, with_service=False)
    _add_resolved_probed(store, "flap2.api.acme.test", probed=False, with_service=False)
    phase = AIProbePhase()
    res = phase.check(_ctx(tmp_path), store)
    assert res.status == st.DONE, res.summary
    assert "unprobed" in res.summary  # the tail is reported, not hidden


def test_genuinely_incomplete_probe_stays_partial(env, tmp_path):
    store = _store(tmp_path)
    # 100 probed with services, but 100 still unprobed and no handoff -> not done.
    for i in range(100):
        _add_resolved_probed(store, f"done{i}.api.acme.test", probed=True, with_service=True)
    for i in range(100):
        _add_resolved_probed(store, f"todo{i}.api.acme.test", probed=False, with_service=False)
    phase = AIProbePhase()
    res = phase.check(_ctx(tmp_path), store)
    assert res.status == st.PARTIAL, res.summary


def test_no_services_at_all_is_partial(env, tmp_path):
    store = _store(tmp_path)
    phase = AIProbePhase()
    res = phase.check(_ctx(tmp_path), store)
    assert res.status == st.PARTIAL


def test_handoff_present_is_done_the_normal_way(env, tmp_path):
    store = _store(tmp_path)
    for i in range(50):
        _add_resolved_probed(store, f"h{i}.api.acme.test", probed=True, with_service=True)
    # even with some unprobed, a written handoff means the agent finished
    for i in range(50):
        _add_resolved_probed(store, f"u{i}.api.acme.test", probed=False, with_service=False)
    workdir = tmp_path / "out" / "phases" / "03-probe" / "work"
    workdir.mkdir(parents=True)
    (workdir / "handoff.md").write_text("done")
    phase = AIProbePhase()
    res = phase.check(_ctx(tmp_path), store)
    assert res.status == st.DONE, res.summary
