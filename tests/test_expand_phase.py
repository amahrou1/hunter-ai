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


def _ctx(tmp_path, scope):
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
