"""Stage 1: intake recognises 'brand on any TLD' patterns (*.autoscout24.*)
and ownership scopes with legal names + seed domains, without turning either
into a testable asset. The discovery phase (01c-expand) expands them later with
proof; here we only check they are parsed and recorded correctly."""

from __future__ import annotations

import json
from pathlib import Path

from hunter import config, policy, scope as sc


def _settings():
    s = config.load_settings()
    s["researcher"]["handle"] = "amahrou1"
    return s


# ------------------------------------------------------------- parse_pattern

def test_parse_pattern_forms():
    assert sc.parse_pattern("*.autoscout24.*") == {
        "brand": "autoscout24", "subdomains": True, "raw": "*.autoscout24.*"}
    assert sc.parse_pattern("autoscout24.*")["subdomains"] is False
    assert sc.parse_pattern(".bmw.*")["brand"] == "bmw"
    # not patterns:
    for s in ("*.autoscout24.de", "autoscout24.de", "api.example.com", "311785642",
              "company.co.*", "ab.*", "123.*", "*.*", "http://autoscout24.de/"):
        assert sc.parse_pattern(s) is None, s


# ------------------------------------------------- patterns through build_scope

AUTOSCOUT_POLICY = (
    "AutoScout24 bug bounty.\n"
    "In scope: *.autoscout24.* (all our country sites), *.leasingmarkt.de\n"
    "Out of scope: support.autoscout24.*\n"
)


def test_pattern_from_scope_patterns_field():
    draft = {
        "program_name": "AutoScout24", "platform": "intigriti",
        "in_scope": [{"asset": "*.leasingmarkt.de", "type": "wildcard",
                      "quote": "*.leasingmarkt.de"}],
        "out_of_scope": [],
        "scope_patterns": [{"asset": "*.autoscout24.*", "brand": "autoscout24",
                            "subdomains": True, "quote": "*.autoscout24.*"}],
    }
    s = policy.build_scope(draft, AUTOSCOUT_POLICY, "", _settings()).scope
    pats = s.scope_patterns()
    assert len(pats) == 1
    assert pats[0]["brand"] == "autoscout24" and pats[0]["subdomains"] is True
    # the pattern itself tests nothing - no country domain is in scope yet
    assert not s.decide("www.autoscout24.de").allowed
    assert not s.decide("www.autoscout24.nl").allowed
    # the real wildcard still works
    assert s.decide("x.leasingmarkt.de").allowed


def test_pattern_rescued_from_in_scope():
    # The AI wrongly put the pattern in in_scope instead of scope_patterns.
    draft = {
        "program_name": "AutoScout24", "platform": "intigriti",
        "in_scope": [{"asset": "*.autoscout24.*", "type": "wildcard", "quote": "*.autoscout24.*"}],
        "out_of_scope": [],
    }
    s = policy.build_scope(draft, AUTOSCOUT_POLICY, "", _settings()).scope
    assert [p["brand"] for p in s.scope_patterns()] == ["autoscout24"]
    # it must NOT have become an in-scope asset or an ambiguity
    assert not any(a.host == "autoscout24" for a in s.in_scope)
    assert not any("autoscout24.*" in a["item"] for a in s.ambiguities)


def test_pattern_rescued_from_ambiguities():
    draft = {
        "program_name": "AutoScout24", "platform": "intigriti",
        "in_scope": [], "out_of_scope": [],
        "ambiguities": [{"item": "*.autoscout24.*", "why": "more than one wildcard"}],
    }
    s = policy.build_scope(draft, AUTOSCOUT_POLICY, "", _settings()).scope
    assert [p["brand"] for p in s.scope_patterns()] == ["autoscout24"]
    assert s.ambiguities == []


# -------------------------------------------------------- ownership enrichment

OWN_POLICY = (
    "Program: Example Rail.\n"
    "Scope: all assets owned by Example Rail AG (ExRail) are in scope, including subsidiaries.\n"
    "Seed: exrail.ch is our main site.\n"
)


def test_ownership_enriched_with_legal_names_and_seeds():
    draft = {
        "program_name": "Example Rail", "platform": "intigriti",
        "in_scope": [{"asset": "exrail.ch", "type": "domain", "quote": "exrail.ch is our main site"}],
        "out_of_scope": [],
        "ownership_scope": {
            "owner": "Example Rail AG",
            "legal_names": ["Example Rail AG", "ExRail"],
            "seed_domains": ["exrail.ch", "https://exrail.ch/"],
            "include_subsidiaries": True,
            "quote": "all assets owned by Example Rail AG",
        },
    }
    s = policy.build_scope(draft, OWN_POLICY, "", _settings()).scope
    own = s.rules["ownership_scope"]
    assert own["owner"] == "Example Rail AG"
    assert own["legal_names"] == ["Example Rail AG", "ExRail"]
    assert own["seed_domains"] == ["exrail.ch"]   # deduped + host-normalised
    assert own["include_subsidiaries"] is True


# -------------------------------------------------------------- expanded list

def test_expanded_assets_are_in_scope_and_persist(tmp_path):
    s = sc.Scope(in_scope=[sc.parse_asset("*.autoscout24.de")], out_of_scope=[])
    s.expanded = [sc.parse_asset("*.autoscout24.nl"), sc.parse_asset("autoscout24.it")]
    # discovered ones decide as in scope
    assert s.decide("www.autoscout24.nl").allowed
    assert s.decide("autoscout24.it").allowed
    assert s.decide("www.autoscout24.xyz").allowed is False   # not discovered
    assert "autoscout24.nl" in s.wildcard_roots()
    # round-trips through save/load
    p = tmp_path / "scope.json"
    sc.save(s, p)
    loaded = sc.load(p)
    assert loaded.decide("api.autoscout24.nl").allowed
    assert {a.raw for a in loaded.expanded} == {"*.autoscout24.nl", "autoscout24.it"}


def test_expanded_still_loses_to_out_of_scope():
    s = sc.Scope(in_scope=[], out_of_scope=[sc.parse_asset("secret.autoscout24.nl")])
    s.expanded = [sc.parse_asset("*.autoscout24.nl")]
    assert s.decide("www.autoscout24.nl").allowed
    assert not s.decide("secret.autoscout24.nl").allowed   # out-of-scope wins
