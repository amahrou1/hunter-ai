"""Scope reading for HackerOne-style tables (the TikTok case):
- glued wildcards like *us.tiktokv.com must parse and match as a suffix;
- the policy prompt must classify by the asset string and not drop eligible
  wildcards into 'ambiguities' because of a 'Type' column or tier notes.
"""

from __future__ import annotations

from hunter import scope as sc
from hunter.policy import PROMPT


def test_glued_wildcard_parses_as_suffix():
    a = sc.parse_asset("*us.tiktokv.com")
    assert a.kind == "wildcard" and a.suffix_match and a.host == "us.tiktokv.com"
    b = sc.parse_asset("*tiktokv.us")
    assert b.kind == "wildcard" and b.suffix_match and b.host == "tiktokv.us"


def test_plain_wildcard_is_not_suffix():
    a = sc.parse_asset("*.tiktokv.com")
    assert a.kind == "wildcard" and not a.suffix_match
    assert sc.asset_matches(a, "x.tiktokv.com") and not sc.asset_matches(a, "tiktokv.com")


def test_glued_exclusion_beats_inscope_wildcard():
    s = sc.Scope(
        in_scope=[sc.parse_asset("*.tiktok.com"), sc.parse_asset("*.tiktokv.com")],
        out_of_scope=[sc.parse_asset("*us.tiktokv.com"), sc.parse_asset("usds.tiktok.com")],
    )
    assert s.decide("ads.tiktok.com").allowed
    assert s.decide("fp-sg.tiktokv.com").allowed
    assert not s.decide("a.us.tiktokv.com").allowed     # glued exclusion enforced
    assert not s.decide("usds.tiktok.com").allowed      # listed exclusion wins over the wildcard


def test_prompt_classifies_by_asset_string_not_type_column():
    # Guards the fix that made the reader keep *.tiktok.com (typed "Other") in scope.
    assert 'labels its type "Other"' in PROMPT
    assert "Tier 1" in PROMPT and "bounty tier" in PROMPT
    assert "Do NOT mark an asset unclear" in PROMPT
