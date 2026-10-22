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
        assert kit.store.candidate("autoscout24.evil")["tier"] == "reject"
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
