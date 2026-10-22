"""Infix label wildcards like *dev*.autoscout24.com: a long-term scope form, not
a one-off. Matches any host under the root whose leftmost label matches the
fragment; never broadens beyond what the program wrote, and never swallows a
plain *.root."""

from __future__ import annotations

import pytest

from hunter import config, policy, scope as sc


def _settings():
    s = config.load_settings(); s["researcher"]["handle"] = "amahrou1"; return s


@pytest.mark.parametrize("raw,root,mode,frag", [
    ("*dev*.autoscout24.com", "autoscout24.com", "contains", "dev"),
    ("https://*dev*.autoscout24.de/*", "autoscout24.de", "contains", "dev"),
    ("*sandbox*.autoscout24.be/*", "autoscout24.be", "contains", "sandbox"),
    ("*test*.autoscout24.nl/*", "autoscout24.nl", "contains", "test"),
    ("dev*.example.com", "example.com", "prefix", "dev"),
    ("*staging.example.org", "example.org", "suffix", "staging"),
])
def test_parse_label_wildcard(raw, root, mode, frag):
    a = sc.parse_label_wildcard(raw)
    assert a is not None
    assert (a.kind, a.host, a.label_mode, a.label_frag) == ("label_wildcard", root, mode, frag)


@pytest.mark.parametrize("raw", [
    "*.example.com",       # plain wildcard, not a label wildcard
    "example.com", "api.example.com", "10.0.0.1",
    "de*v.example.com",    # star mid-label, ambiguous -> not read
    "*dev*.example.*",     # root itself wildcarded -> not a label wildcard
    "*.*",
])
def test_non_label_wildcards_return_none(raw):
    assert sc.parse_label_wildcard(raw) is None


def test_matching_semantics():
    s = sc.Scope(in_scope=[sc.parse_label_wildcard("*dev*.autoscout24.com")])
    for h in ["api-dev.autoscout24.com", "dev.autoscout24.com", "devtools.autoscout24.com",
              "mydev.autoscout24.com", "x.api-dev.autoscout24.com"]:
        assert s.decide(h).allowed, h
    for h in ["api.autoscout24.com", "autoscout24.com", "dev.autoscout24.de", "www.autoscout24.com"]:
        assert not s.decide(h).allowed, h


def test_prefix_and_suffix_modes():
    s = sc.Scope(in_scope=[sc.parse_label_wildcard("dev*.example.com"),
                           sc.parse_label_wildcard("*staging.example.org")])
    assert s.decide("dev-api.example.com").allowed
    assert not s.decide("mydev.example.com").allowed          # prefix: must START with dev
    assert s.decide("blue-staging.example.org").allowed
    assert not s.decide("staging-blue.example.org").allowed   # suffix: must END with staging


def test_round_trip_save_load(tmp_path):
    s = sc.Scope(in_scope=[sc.parse_label_wildcard("*dev*.autoscout24.com")])
    sc.save(s, tmp_path / "s.json")
    loaded = sc.load(tmp_path / "s.json")
    assert loaded.decide("api-dev.autoscout24.com").allowed
    assert loaded.in_scope[0].kind == "label_wildcard"


def test_root_enumerated_by_recon():
    s = sc.Scope(in_scope=[sc.parse_label_wildcard("*dev*.autoscout24.com")])
    assert "autoscout24.com" in s.wildcard_roots()   # recon must enumerate the root


def test_build_scope_rescues_infix_from_in_scope():
    text = ("In scope: *dev*.autoscout24.com, *test*.autoscout24.de, *.leasingmarkt.de")
    draft = {"program_name": "AutoScout24", "platform": "intigriti",
             "in_scope": [{"asset": a, "type": "url", "quote": a} for a in
                          ["*dev*.autoscout24.com", "*test*.autoscout24.de", "*.leasingmarkt.de"]],
             "out_of_scope": []}
    s = policy.build_scope(draft, text, "", _settings()).scope
    kinds = {a.raw: a.kind for a in s.in_scope}
    assert kinds["*dev*.autoscout24.com"] == "label_wildcard"
    assert kinds["*test*.autoscout24.de"] == "label_wildcard"
    assert s.decide("api-dev.autoscout24.com").allowed
    assert not any("autoscout24" in a["item"] for a in s.ambiguities)   # not parked as unclear


def test_build_scope_rejects_infix_not_in_policy():
    # the AI invents an infix wildcard the policy never names -> stays unclear
    draft = {"program_name": "X", "platform": "intigriti",
             "in_scope": [{"asset": "*dev*.evil.com", "type": "url", "quote": "x"}],
             "out_of_scope": []}
    s = policy.build_scope(draft, "In scope: *.good.com only", "", _settings()).scope
    assert not any(a.kind == "label_wildcard" for a in s.in_scope)
    assert any("evil.com" in a["item"] for a in s.ambiguities)


def test_infix_exclusion():
    s = sc.Scope(in_scope=[sc.parse_asset("*.example.com")],
                 out_of_scope=[sc.parse_label_wildcard("*internal*.example.com")])
    assert s.decide("api.example.com").allowed
    assert not s.decide("api-internal.example.com").allowed


def test_sibling_infix_wildcards_on_one_root_not_deduped():
    """*dev*/*test*/*sandbox* on the same root are distinct assets - the dedup
    key must keep all of them, not collapse to the first (the AutoScout24 bug)."""
    roots = ["com", "de", "nl", "be"]
    assets = [f"*{w}*.autoscout24.{t}/*" for w in ("dev", "test", "sandbox") for t in roots]
    text = "In scope: " + ", ".join(assets)
    draft = {"program_name": "AutoScout24", "platform": "intigriti",
             "in_scope": [{"asset": a, "type": "url", "quote": a} for a in assets], "out_of_scope": []}
    s = policy.build_scope(draft, text, "", _settings()).scope
    lw = [a for a in s.in_scope if a.kind == "label_wildcard"]
    assert len(lw) == 12
    assert s.decide("x-dev.autoscout24.com").allowed
    assert s.decide("x-test.autoscout24.be").allowed
    assert s.decide("x-sandbox.autoscout24.nl").allowed
