"""Kept fixes from this session that are NOT part of scope discovery: intake
carries over an operator-set rate across a policy re-read, and any-TLD
exclusions (support.binance.*) are enforced."""

from __future__ import annotations

from types import SimpleNamespace

from hunter import config, policy, scope as sc
from hunter.phases.p00_intake import IntakePhase


def _settings():
    s = config.load_settings()
    s["researcher"]["handle"] = "amahrou1"
    return s


def test_intake_rerun_keeps_operator_rate(tmp_path):
    scope_file = tmp_path / "scope.json"
    prev = sc.Scope(in_scope=[sc.parse_asset("*.binance.com")],
                    rules={"effective_rps": 200.0, "rate_source": "operator set 200/s on 2026-10-22"})
    sc.save(prev, scope_file)
    fresh = sc.Scope(in_scope=[sc.parse_asset("*.binance.com")],
                     rules={"effective_rps": 5.0, "rate_source": "no rate stated, default used"})
    ctx = SimpleNamespace(target=SimpleNamespace(scope_file=scope_file))
    IntakePhase()._carry_over(ctx, fresh, "")
    assert fresh.rules["effective_rps"] == 200.0


def test_override_rate_beats_carried_operator_rate(tmp_path):
    scope_file = tmp_path / "scope.json"
    sc.save(sc.Scope(rules={"effective_rps": 200.0, "rate_source": "operator set 200/s"}), scope_file)
    fresh = sc.Scope(rules={"effective_rps": 30.0, "rate_source": "your override"})
    IntakePhase()._carry_over(SimpleNamespace(target=SimpleNamespace(scope_file=scope_file)), fresh, "rate 30")
    assert fresh.rules["effective_rps"] == 30.0


def test_binance_support_exclusion_is_enforced():
    text = "In scope: *.binance.com, *.binance.us. Out of scope: support.binance.*"
    draft = {"program_name": "Binance", "platform": "bugcrowd",
             "in_scope": [{"asset": "*.binance.com", "type": "wildcard", "quote": "*.binance.com"},
                          {"asset": "*.binance.us", "type": "wildcard", "quote": "*.binance.us"}],
             "out_of_scope": [{"asset": "support.binance.*", "type": "wildcard", "quote": "support.binance.*"}]}
    s = policy.build_scope(draft, text, "", _settings()).scope
    assert not s.decide("support.binance.com").allowed
    assert not s.decide("support.binance.us").allowed
    assert s.decide("www.binance.com").allowed
    assert not any("support.binance" in a["item"] for a in s.ambiguities)


def test_any_tld_exclusion_survives_save_load(tmp_path):
    s = sc.Scope(in_scope=[sc.parse_asset("*.binance.com")],
                 out_of_scope=[sc.parse_any_tld_exclusion("support.binance.*")])
    sc.save(s, tmp_path / "s.json")
    assert not sc.load(tmp_path / "s.json").decide("support.binance.com").allowed


def test_any_tld_exclusion_never_broadens_in_scope():
    import pytest
    with pytest.raises(sc.AssetError):
        sc.parse_asset("support.binance.*")
