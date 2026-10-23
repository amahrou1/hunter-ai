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


def _ctx(tmp_path, store=None):
    output = tmp_path / "out"
    # cluster disabled: check() skips _cluster and needs only target.output,
    # settings, and assets() (used by outputs_present on the covered path).
    return SimpleNamespace(target=SimpleNamespace(output=output),
                           settings={"cluster": {"enabled": False}},
                           assets=lambda: store)


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


def test_covered_probe_satisfies_dependents_without_handoff(env, tmp_path):
    """The Binance regression: probe reaches ground-truth completion on a huge
    surface without writing handoff.md. Its outputs_present() must be True so
    the downstream dependency gate does not leave 04-map BLOCKED 'waiting for
    03-probe' while 03-probe is DONE."""
    store = _store(tmp_path)
    for i in range(500):
        _add_resolved_probed(store, f"h{i}.api.acme.test", probed=True, with_service=True)
    phase = AIProbePhase()
    ctx = _ctx(tmp_path, store)
    # no handoff.md exists
    assert not (tmp_path / "out" / "phases" / "03-probe" / "work" / "handoff.md").exists()
    # but the surface is covered -> dependents see the requirement as met
    assert phase.outputs_present(ctx) is True


def test_incomplete_probe_does_not_satisfy_dependents(env, tmp_path):
    """A genuinely unfinished probe (no handoff, lots unprobed) must NOT look
    present to dependents - they should wait, not run on a half-probed surface."""
    store = _store(tmp_path)
    for i in range(100):
        _add_resolved_probed(store, f"done{i}.api.acme.test", probed=True, with_service=True)
    for i in range(100):
        _add_resolved_probed(store, f"todo{i}.api.acme.test", probed=False, with_service=False)
    phase = AIProbePhase()
    assert phase.outputs_present(_ctx(tmp_path, store)) is False


def test_covered_floor_is_ninety_percent(env, tmp_path):
    """A long dead-host tail must not block forever: >=90% probed is 'covered',
    but a surface only 62% probed (the Cornelsen case) is NOT - keep probing."""
    store = _store(tmp_path)
    phase = AIMapAuthReuse = AIProbePhase()
    # 1000 resolved hosts; 900 probed (90%) -> covered
    for i in range(900):
        _add_resolved_probed(store, f"p{i}.api.acme.test", probed=True, with_service=True)
    for i in range(100):
        _add_resolved_probed(store, f"u{i}.api.acme.test", probed=False, with_service=False)
    assert phase._covered(store) is True
    # now make it 62% probed -> NOT covered
    store2 = _store(tmp_path / "b")
    for i in range(620):
        _add_resolved_probed(store2, f"p{i}.api.acme.test", probed=True, with_service=True)
    for i in range(380):
        _add_resolved_probed(store2, f"u{i}.api.acme.test", probed=False, with_service=False)
    assert phase._covered(store2) is False


def test_progress_metric_counts_probed_hosts(env, tmp_path):
    """probe.progress_metric must be hosts-probed, so a pass that probes more
    (dead) hosts counts as progress even if it adds no service rows."""
    from types import SimpleNamespace
    store = _store(tmp_path)
    for i in range(50):
        _add_resolved_probed(store, f"p{i}.api.acme.test", probed=True, with_service=False)
    for i in range(30):
        _add_resolved_probed(store, f"u{i}.api.acme.test", probed=False, with_service=False)
    ctx = SimpleNamespace(assets=lambda: store)
    assert AIProbePhase().progress_metric(ctx) == 50   # 50 probed, regardless of services


def test_on_stall_clears_dead_tail(env, tmp_path):
    """The Cornelsen fix: when the agent stalls (no handoff, out of turns) with a
    tail of resolved hosts that never answered HTTP, on_stall marks them
    probed-no-service in code so the phase can complete instead of looping."""
    from types import SimpleNamespace
    store = _store(tmp_path)
    # 1378 probed-with-service (the responders), 860 resolved-but-never-answered.
    for i in range(1378):
        _add_resolved_probed(store, f"live{i}.api.acme.test", probed=True, with_service=True)
    for i in range(860):
        _add_resolved_probed(store, f"dead{i}.api.acme.test", probed=False, with_service=False)
    assert len(store.unprobed_hosts()) == 860
    phase = AIProbePhase()
    ctx = SimpleNamespace(assets=lambda: store,
                          target=SimpleNamespace(output=tmp_path / "out"))
    # agent stalled, no handoff written -> on_stall clears the tail
    assert phase.on_stall(ctx) is True
    assert store.unprobed_hosts() == []           # tail cleared
    assert store.service_count() == 1378          # no fake services invented
    # a second stall has nothing left to do
    assert phase.on_stall(ctx) is False


def test_no_reconcile_while_probe_still_batching(env, tmp_path):
    """Safety: without a handoff and without a stall (force), the dead-tail
    reconcile does NOT fire - a live, still-batching probe is never cut short."""
    from types import SimpleNamespace
    store = _store(tmp_path)
    for i in range(100):
        _add_resolved_probed(store, f"live{i}.api.acme.test", probed=True, with_service=True)
    for i in range(50):
        _add_resolved_probed(store, f"todo{i}.api.acme.test", probed=False, with_service=False)
    phase = AIProbePhase()
    ctx = SimpleNamespace(assets=lambda: store,
                          target=SimpleNamespace(output=tmp_path / "out"))
    # no handoff.md, force defaults False -> nothing cleared
    assert phase._reconcile_dead_tail(ctx, store) == 0
    assert len(store.unprobed_hosts()) == 50
