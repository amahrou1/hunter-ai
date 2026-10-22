"""Stage 4: the 01c-expand phase. No-op on a plain scope; on a brand pattern it
runs the code TLD sweep, scores each with the evidence, and auto-adds the
strong-proof ones into scope - all without a model call for the sweep itself."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hunter import expand
from hunter import scope as sc
from hunter import state as st
from hunter import assets as A
from hunter.phases.ai_expand import ScopeExpandPhase


def _ctx(tmp_path, scope, settings=None):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    scope_file = out / "scope.json"
    sc.save(scope, scope_file)
    state = st.State(out / "state.db")
    store = A.Assets(state.db)
    logs = []
    return SimpleNamespace(
        target=SimpleNamespace(scope_file=scope_file, output=out),
        state=state, _store=store,
        settings=settings if settings is not None else {},
        scope=lambda: sc.load(scope_file),
        assets=lambda: store,
        log=lambda m: logs.append(m),
        progress=lambda *a, **k: None,
    )


def test_noop_on_plain_scope(tmp_path):
    scope = sc.Scope(in_scope=[sc.parse_asset("*.example.com")], out_of_scope=[])
    ctx = _ctx(tmp_path, scope)
    phase = ScopeExpandPhase()
    assert phase._active(ctx) is False
    res = phase.run(ctx)
    assert res.status == st.DONE
    assert "nothing to expand" in res.summary


def test_active_on_brand_pattern(tmp_path):
    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    ctx = _ctx(tmp_path, scope)
    assert ScopeExpandPhase()._active(ctx) is True


def test_code_sweep_auto_adds_strong_proof(tmp_path, monkeypatch):
    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    ctx = _ctx(tmp_path, scope)
    phase = ScopeExpandPhase()

    # Stub the owner context (no real seed DNS) and per-domain evidence.
    monkeypatch.setattr(expand, "seed_owner_context", lambda *a, **k: {
        "brand": "autoscout24", "legal_names": ["AutoScout24 GmbH"],
        "seed_domains": {"autoscout24.de"}, "seed_ns_roots": {"autoscout24.com"},
        "seed_soa_rnames": {"hostmaster.autoscout24.com"}, "seed_spf_includes": set(),
        "seed_asns": set(), "is_ownership": False})

    def fake_resolve(domain, **k):
        if domain == "autoscout24.nl":   # strong: same NS + cert org -> auto
            return {"resolves": True, "nameservers": ["ns1.autoscout24.com"],
                    "cert_org": "AutoScout24 GmbH"}
        if domain == "autoscout24.it":   # one medium only (SOA matches seed) -> review
            return {"resolves": True, "nameservers": ["ns1.other.net"],
                    "soa_rname": "hostmaster.autoscout24.com"}
        if domain == "autoscout24.shop":  # parked -> reject
            return {"resolves": True, "nameservers": ["ns1.sedoparking.com"]}
        return {"resolves": False}       # the rest don't exist
    monkeypatch.setattr(expand, "resolve_evidence", fake_resolve)

    recorded, auto = phase._code_sweep(ctx, ctx._store)
    added = phase._sync(ctx, ctx._store)

    assert auto == 1 and added == 1
    tiers = {r["domain"]: r["tier"] for r in ctx._store.candidates()}
    assert tiers["autoscout24.nl"] == "added"
    assert tiers["autoscout24.it"] == "review"
    assert tiers["autoscout24.shop"] == "reject"
    # the strong one is now live in scope; the others are not
    live = sc.load(ctx.target.scope_file)
    assert live.decide("www.autoscout24.nl").allowed
    assert not live.decide("www.autoscout24.it").allowed
    assert not live.decide("www.autoscout24.shop").allowed


def test_sweep_is_resumable(tmp_path, monkeypatch):
    scope = sc.Scope(in_scope=[], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    ctx = _ctx(tmp_path, scope)
    phase = ScopeExpandPhase()
    monkeypatch.setattr(expand, "seed_owner_context", lambda *a, **k: {
        "brand": "autoscout24", "legal_names": [], "seed_domains": set(),
        "seed_ns_roots": set(), "seed_soa_rnames": set(), "seed_spf_includes": set(),
        "seed_asns": set(), "is_ownership": False})
    calls = []

    def fake_resolve(domain, **k):
        calls.append(domain)
        return {"resolves": False}
    monkeypatch.setattr(expand, "resolve_evidence", fake_resolve)

    phase._code_sweep(ctx, ctx._store)
    # a candidate already recorded is skipped on the next pass
    ctx._store.record_candidate("autoscout24.nl", source="tld-sweep", tier="review")
    before = len(calls)
    calls.clear()
    phase._code_sweep(ctx, ctx._store)
    assert "autoscout24.nl" not in calls   # skipped as already-seen
    assert before > 0


def test_candidate_domains_generation():
    doms = expand.candidate_domains("autoscout24")
    assert "autoscout24.de" in doms and "autoscout24.com.tr" in doms and "autoscout24.co.uk" in doms
    assert expand.candidate_domains("") == []
    assert expand.candidate_domains("a.b") == []   # not a bare brand


def test_rerun_resyncs_without_calling_agent(tmp_path, monkeypatch):
    """A later phase proposes a new approved candidate; re-opening 01c-expand
    must sync it into scope WITHOUT spending another model call (the agent
    already ran: handoff.md exists and the sweep is done)."""
    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    ctx = _ctx(tmp_path, scope)
    phase = ScopeExpandPhase()
    # simulate a completed first run: a tld-sweep candidate + a handoff
    ctx._store.record_candidate("autoscout24.de", source="tld-sweep", tier="added")
    work = tmp_path / "out" / "phases" / "01c-expand" / "work"
    work.mkdir(parents=True)
    (work / "handoff.md").write_text("done")

    # a later phase proposes & approves a new domain
    ctx._store.record_candidate("autoscout24.fr", source="recon", tier="approved",
                                reason="same cert as a known host")

    called = {"agent": False}
    monkeypatch.setattr(ScopeExpandPhase, "_code_sweep",
                        lambda self, c, s: called.__setitem__("agent", True) or (0, 0))
    # also guard the AgentPhase.run path
    import hunter.agent_phase as ap
    monkeypatch.setattr(ap.AgentPhase, "run",
                        lambda self, c: called.__setitem__("agent", True) or PhaseResult(st.DONE, "x"))

    res = phase.run(ctx)
    assert res.status == st.DONE
    assert called["agent"] is False            # no sweep, no agent - just a sync
    live = sc.load(ctx.target.scope_file)
    assert live.decide("www.autoscout24.fr").allowed


def test_needs_rerun_true_when_admitted_not_in_scope(tmp_path):
    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    ctx = _ctx(tmp_path, scope)
    phase = ScopeExpandPhase()
    assert phase.needs_rerun(ctx, ctx._store) is False
    ctx._store.record_candidate("autoscout24.nl", source="recon", tier="approved")
    assert phase.needs_rerun(ctx, ctx._store) is True
    # once synced it is in scope, so no more rerun
    phase._sync(ctx, ctx._store)
    assert phase.needs_rerun(ctx, ctx._store) is False


def test_auto_add_none_records_strong_as_review(tmp_path, monkeypatch):
    """With scope_expand.auto_add='none', a strong-proof domain is recorded as
    'review' (suggest-only) and nothing auto-enters scope - the suggest-only
    mode for strict/ownership programs."""
    scope = sc.Scope(in_scope=[], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    ctx = _ctx(tmp_path, scope, settings={"scope_expand": {"auto_add": "none"}})
    phase = ScopeExpandPhase()
    monkeypatch.setattr(expand, "seed_owner_context", lambda *a, **k: {
        "brand": "autoscout24", "legal_names": ["AutoScout24 GmbH"],
        "seed_domains": {"autoscout24.de"}, "seed_ns_roots": {"autoscout24.com"},
        "seed_soa_rnames": set(), "seed_spf_includes": set(), "seed_asns": set(),
        "is_ownership": True})

    def fake_resolve(domain, **k):
        if domain == "autoscout24.nl":
            return {"resolves": True, "nameservers": ["ns1.autoscout24.com"],
                    "cert_org": "AutoScout24 GmbH"}   # strong
        return {"resolves": False}
    monkeypatch.setattr(expand, "resolve_evidence", fake_resolve)

    recorded, auto = phase._code_sweep(ctx, ctx._store)
    assert auto == 0                                   # nothing auto-added
    assert ctx._store.candidate("autoscout24.nl")["tier"] == "review"
    assert phase._sync(ctx, ctx._store) == 0           # scope unchanged
