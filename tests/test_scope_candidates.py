"""Stage 3: candidate storage + hk candidate flow + sync into scope.expanded.
The store records every candidate with evidence and verdict; the agent can
approve/reject only REVIEW-tier ones; code's auto verdict and the sync into
scope.json are what actually widen scope."""

from __future__ import annotations

import argparse

from hunter import assets as A
from hunter import expand
from hunter import scope as sc
from hunter import state as st
from hunter.kit import Kit, cmd_candidate


def _store(tmp_path):
    return A.Assets(st.State(tmp_path / "state.db").db)


def _kit(target, monkeypatch):
    monkeypatch.setenv("HUNTER_TARGET_DIR", str(target.path))
    monkeypatch.setenv("HUNTER_PHASE", "01c-expand")
    return Kit()


# ------------------------------------------------------------- store methods

def test_record_and_read_candidate(tmp_path):
    s = _store(tmp_path)
    s.record_candidate("autoscout24.nl", source="tld-sweep", tier="auto",
                       evidence={"resolves": True}, reason="same nameservers")
    row = s.candidate("autoscout24.nl")
    assert row["tier"] == "auto" and row["source"] == "tld-sweep"
    assert row["subdomains"] == 1
    # update in place
    s.record_candidate("autoscout24.nl", source="crt.sh", tier="added", reason="promoted")
    assert s.candidate("autoscout24.nl")["tier"] == "added"
    assert len(s.candidates()) == 1


def test_candidates_filter_by_tier(tmp_path):
    s = _store(tmp_path)
    s.record_candidate("a.de", source="x", tier="auto")
    s.record_candidate("b.de", source="x", tier="review")
    s.record_candidate("c.de", source="x", tier="reject")
    assert {r["domain"] for r in s.candidates("auto")} == {"a.de"}
    assert {r["domain"] for r in s.candidates("review")} == {"b.de"}


# ----------------------------------------------------- sync into scope.expanded

def test_sync_promotes_only_admitted(tmp_path):
    s = _store(tmp_path)
    s.record_candidate("autoscout24.nl", source="x", tier="added", subdomains=True)
    s.record_candidate("autoscout24.it", source="x", tier="approved", subdomains=False)
    s.record_candidate("autoscout24.xyz", source="x", tier="reject")   # must NOT enter scope
    s.record_candidate("autoscout24.pl", source="x", tier="review")    # pending: not yet

    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[])
    saved = {}
    n = expand.sync_scope_expanded(s, scope, "scope.json", lambda sc_, p: saved.setdefault("called", True))
    assert n == 2
    raws = {a.raw for a in scope.expanded}
    assert raws == {"*.autoscout24.nl", "autoscout24.it"}
    assert scope.decide("www.autoscout24.nl").allowed
    assert scope.decide("autoscout24.it").allowed
    assert not scope.decide("www.autoscout24.xyz").allowed   # rejected never added
    assert not scope.decide("www.autoscout24.pl").allowed    # review not yet added


def test_sync_skips_out_of_scope_domain(tmp_path):
    s = _store(tmp_path)
    s.record_candidate("autoscout24.nl", source="x", tier="added", subdomains=True)
    scope = sc.Scope(in_scope=[], out_of_scope=[sc.parse_asset("*.autoscout24.nl")])
    n = expand.sync_scope_expanded(s, scope, "scope.json", lambda *a: None)
    assert n == 0   # the operator/policy excluded it: discovery must not re-add


def test_sync_is_idempotent_and_only_saves_on_change(tmp_path):
    s = _store(tmp_path)
    s.record_candidate("autoscout24.nl", source="x", tier="added")
    scope = sc.Scope(in_scope=[], out_of_scope=[])
    calls = []
    expand.sync_scope_expanded(s, scope, "f", lambda *a: calls.append(1))
    expand.sync_scope_expanded(s, scope, "f", lambda *a: calls.append(1))
    assert calls == [1]   # saved once; second call is a no-op


# ----------------------------------------------------- hk candidate command

def test_agent_add_is_scored_by_code(env, make_target, monkeypatch):
    target = make_target("as24")
    target.output.mkdir(parents=True, exist_ok=True)
    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    sc.save(scope, target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        # No evidence -> code scores it 'reject', whatever the agent claims.
        rc = cmd_candidate(kit, argparse.Namespace(
            action="add", domain="autoscout24.evil", source="agent", pattern=None,
            evidence='{"resolves": true, "nameservers": ["ns.unknown.net"]}',
            reason=None, apex_only=False, tier=None, json=False))
        assert rc == 0
        # no evidence either way: 'unverified' (agent should investigate), never admitted
        assert kit.store.candidate("autoscout24.evil")["tier"] == "unverified"
        assert kit.store.candidate("autoscout24.evil")["tier"] not in expand.ADMITTED_TIERS
    finally:
        kit.state.close()


def test_agent_cannot_approve_a_rejected_candidate(env, make_target, monkeypatch):
    target = make_target("as24b")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[]), target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        kit.store.record_candidate("autoscout24.evil", source="agent", tier="reject",
                                   reason="no evidence")
        kit.state.db.commit()
        rc = cmd_candidate(kit, argparse.Namespace(
            action="approve", domain="autoscout24.evil", reason="trust me",
            source=None, pattern=None, evidence=None, apex_only=False, tier=None, json=False))
        assert rc == 1   # refused: code only lets the agent approve 'review' tier
        assert kit.store.candidate("autoscout24.evil")["tier"] == "reject"
    finally:
        kit.state.close()


def test_agent_can_approve_a_review_candidate(env, make_target, monkeypatch):
    target = make_target("as24c")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[]), target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        kit.store.record_candidate("autoscout24.pl", source="agent", tier="review",
                                   reason="one medium signal")
        kit.state.db.commit()
        rc = cmd_candidate(kit, argparse.Namespace(
            action="approve", domain="autoscout24.pl", reason="confirmed via hreflang",
            source=None, pattern=None, evidence=None, apex_only=False, tier=None, json=False))
        assert rc == 0
        assert kit.store.candidate("autoscout24.pl")["tier"] == "approved"
    finally:
        kit.state.close()


def _add(kit, domain, evidence):
    return cmd_candidate(kit, argparse.Namespace(
        action="add", domain=domain, source="agent", pattern=None, evidence=evidence,
        reason=None, apex_only=False, tier=None, json=False))


def test_agent_strong_proof_is_admitted_and_synced(env, make_target, monkeypatch):
    """The AI finds a domain with strong proof: it must be stored 'added' (not
    'auto'), so the sync puts it in scope."""
    target = make_target("as24d")
    target.output.mkdir(parents=True, exist_ok=True)
    scope = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]})
    sc.save(scope, target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        ev = ('{"resolves": true, "cert_org": "AutoScout24 GmbH", '
              '"cert_sans": ["autoscout24.ch", "www.autoscout24.de"]}')
        assert _add(kit, "autoscout24.ch", ev) == 0
        assert kit.store.candidate("autoscout24.ch")["tier"] == "added"
        live = kit.scope()
        expand.sync_scope_expanded(kit.store, live, target.scope_file, sc.save)
        assert sc.load(target.scope_file).decide("www.autoscout24.ch").allowed
    finally:
        kit.state.close()


def test_admitted_candidate_not_downgraded_by_thin_resubmission(env, make_target, monkeypatch):
    target = make_target("as24e")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[]), target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        kit.store.record_candidate("autoscout24.ch", source="tld-sweep", tier="added", reason="strong")
        kit.state.db.commit()
        _add(kit, "autoscout24.ch", '{"resolves": true}')          # no evidence this time
        assert kit.store.candidate("autoscout24.ch")["tier"] == "added"
        _add(kit, "autoscout24.ch", '{"resolves": true, "nameservers": ["ns1.sedoparking.com"]}')
        assert kit.store.candidate("autoscout24.ch")["tier"] == "reject"   # real counter-evidence wins
    finally:
        kit.state.close()


def test_ownership_scope_agent_strong_is_review_by_default(env, make_target, monkeypatch):
    target = make_target("own1")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("exrail.ch")], out_of_scope=[],
                     rules={"ownership_scope": {"owner": "ExRail AG", "legal_names": ["ExRail AG"],
                                                "seed_domains": ["exrail.ch"]}}), target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        ev = '{"resolves": true, "cert_org": "ExRail AG", "rdap_org": "ExRail AG"}'
        _add(kit, "exrail-cargo.ch", ev)
        assert kit.store.candidate("exrail-cargo.ch")["tier"] == "review"   # suggest-only for ownership
    finally:
        kit.state.close()


def test_recheck_drops_sibling_brands_from_scope(env, make_target, monkeypatch):
    """The AutoScout24 cleanup: candidates added before the brand gate (sibling
    brands) are dropped by `hk candidate recheck`, scope.json re-synced."""
    target = make_target("as24recheck")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]}),
            target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        from hunter import expand
        expand.save_owner_context(kit.state.db, {
            "brand": "autoscout24", "brand_aliases": [], "legal_names": ["AutoScout24 GmbH"],
            "seed_domains": {"autoscout24.de"}, "seed_ns_roots": set(), "seed_soa_rnames": set(),
            "seed_spf_includes": set(), "seed_asns": set(), "is_ownership": False})
        # a legit same-brand domain and two wrongly-approved sibling brands
        kit.store.record_candidate("autoscout24.hu", source="tld-sweep", tier="added",
                                   evidence={"resolves": True, "cert_org": "AutoScout24 GmbH",
                                             "rdap_org": "AutoScout24 GmbH"})
        kit.store.record_candidate("autotrader.ca", source="agent", tier="approved",
                                   evidence={"resolves": True, "cert_org": "AutoScout24 GmbH"})
        kit.store.record_candidate("autotrack.nl", source="agent", tier="approved",
                                   evidence={"resolves": True})
        kit.state.db.commit()
        expand.sync_scope_expanded(kit.store, kit.scope(), target.scope_file, sc.save)
        assert sc.load(target.scope_file).decide("x.autotrader.ca").allowed   # bad: in scope before recheck

        cmd_candidate(kit, argparse.Namespace(action="recheck", domain=None, source=None, pattern=None,
                                              evidence=None, reason=None, apex_only=False, tier=None, json=False))
        live = sc.load(target.scope_file)
        assert live.decide("x.autoscout24.hu").allowed          # same brand kept
        assert not live.decide("x.autotrader.ca").allowed       # sibling brand dropped
        assert not live.decide("x.autotrack.nl").allowed
        assert kit.store.candidate("autotrader.ca")["tier"] == "reject"
    finally:
        kit.state.close()


def test_approve_refuses_sibling_brand_on_brand_tld_scope(env, make_target, monkeypatch):
    target = make_target("as24approve")
    target.output.mkdir(parents=True, exist_ok=True)
    sc.save(sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[],
                     rules={"scope_patterns": [{"brand": "autoscout24", "subdomains": True}]}),
            target.scope_file)
    kit = _kit(target, monkeypatch)
    try:
        from hunter import expand
        expand.save_owner_context(kit.state.db, {
            "brand": "autoscout24", "brand_aliases": [], "legal_names": [], "seed_domains": set(),
            "seed_ns_roots": set(), "seed_soa_rnames": set(), "seed_spf_includes": set(),
            "seed_asns": set(), "is_ownership": False})
        kit.store.record_candidate("autotrader.ca", source="agent", tier="review", reason="same group")
        kit.state.db.commit()
        rc = cmd_candidate(kit, argparse.Namespace(action="approve", domain="autotrader.ca",
                           reason="same parent company", source=None, pattern=None, evidence=None,
                           apex_only=False, tier=None, json=False))
        assert rc == 1                                           # refused
        assert kit.store.candidate("autotrader.ca")["tier"] == "review"   # unchanged
    finally:
        kit.state.close()
