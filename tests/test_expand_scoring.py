"""Stage 2: the ownership scoring engine. Pure/offline - evidence in, verdict
out. The dangerous cases (squatter, parked, CDN-shared IP) must NEVER auto-add;
the safe cases (shared NS, shared cert, registrant org) must. This engine is
where 'code owns the in-scope decision' lives."""

from __future__ import annotations

from hunter import expand
from hunter.expand import AUTO, REVIEW, DECLINE


OWNER = {
    "brand": "autoscout24",
    "legal_names": ["AutoScout24 GmbH", "AutoScout24 AG"],
    "seed_domains": {"autoscout24.com", "autoscout24.de"},
    "seed_ns_roots": {"autoscout24.com"},
    "seed_nameservers": {"ns1.autoscout24.com", "ns2.autoscout24.com"},
    "seed_soa_rnames": {"hostmaster.autoscout24.com"},
    "seed_spf_includes": {"_spf.as24.internal"},
    "seed_asns": {"AS1234"},
    "is_ownership": False,
}


# ---------------------------------------------------------------- AUTO cases

def test_same_nameservers_plus_cert_org_auto_adds():
    ev = {
        "resolves": True,
        "nameservers": ["ns1.autoscout24.com", "ns2.autoscout24.com"],
        "cert_org": "AutoScout24 GmbH",
    }
    v = expand.decide("autoscout24.nl", ev, OWNER)
    assert v.tier == AUTO, v.to_dict()


def test_shared_certificate_plus_registrant_auto_adds():
    ev = {
        "resolves": True,
        "nameservers": ["ns1.someprovider.net"],   # not shared with seed
        "cert_sans": ["autoscout24.it", "www.autoscout24.de"],  # spans a seed domain
        "rdap_org": "AutoScout24 AG",
    }
    v = expand.decide("autoscout24.it", ev, OWNER)
    assert v.tier == AUTO, v.to_dict()


def test_one_strong_plus_two_medium_auto_adds():
    ev = {
        "resolves": True,
        "cert_org": "AutoScout24 GmbH",                 # strong
        "soa_rname": "hostmaster.autoscout24.com",       # medium
        "asn": "AS1234", "asn_name": "AUTOSCOUT24-AS",   # medium (not a shared cloud)
        "nameservers": ["ns1.other.net"],
    }
    v = expand.decide("autoscout24.fr", ev, OWNER)
    assert v.tier == AUTO, v.to_dict()


# -------------------------------------------------------------- REJECT cases

def test_parked_nameservers_rejected_even_with_other_proof():
    ev = {
        "resolves": True,
        "nameservers": ["ns1.sedoparking.com", "ns2.sedoparking.com"],
        "cert_org": "AutoScout24 GmbH",   # even a strong signal must not save a parked domain
    }
    v = expand.decide("autoscout24.xyz", ev, OWNER)
    assert v.tier == DECLINE
    assert "park" in v.reason.lower()


def test_squatter_different_registrant_rejected():
    ev = {
        "resolves": True,
        "nameservers": ["ns1.randomhost.com"],
        "rdap_org": "Domain Capital Holdings LLC",   # a different company
    }
    v = expand.decide("autoscout24.tv", ev, OWNER)
    assert v.tier == DECLINE
    assert "does not match" in v.reason


def test_cdn_shared_ip_alone_is_not_ownership():
    # Same Cloudflare IP/ASN as the seed proves nothing - must not auto-add.
    ev = {
        "resolves": True,
        "nameservers": ["lia.ns.cloudflare.com", "rob.ns.cloudflare.com"],
        "ips": ["104.16.0.1"], "asn": "AS13335", "asn_name": "CLOUDFLARENET",
        "shared_hosting_ip": True,
    }
    v = expand.decide("autoscout24-fake.com", ev, OWNER)
    assert v.tier == DECLINE, v.to_dict()


def test_no_evidence_rejected():
    v = expand.decide("autoscout24.ninja", {"resolves": True, "nameservers": ["ns.unknown.net"]}, OWNER)
    assert v.tier == DECLINE


# -------------------------------------------------------------- REVIEW cases

def test_single_medium_goes_to_review():
    ev = {
        "resolves": True,
        "nameservers": ["ns1.other.net"],
        "soa_rname": "hostmaster.autoscout24.com",   # one medium signal only
    }
    v = expand.decide("autoscout24.pl", ev, OWNER)
    assert v.tier == REVIEW, v.to_dict()


def test_single_strong_goes_to_review():
    ev = {"resolves": True, "nameservers": ["ns1.other.net"], "linked_from_scope": True}
    v = expand.decide("autoscout24.at", ev, OWNER)
    assert v.tier == REVIEW, v.to_dict()


def test_strong_but_not_resolving_is_review_not_auto():
    ev = {"resolves": False, "cert_org": "AutoScout24 GmbH", "rdap_org": "AutoScout24 GmbH"}
    v = expand.decide("autoscout24.lu", ev, OWNER)
    assert v.tier == REVIEW
    assert "resolve" in v.reason.lower()


# ------------------------------------------------------------- helper checks

def test_shared_ns_root_not_counted_as_ownership():
    # cloudflare NS must not be read as "same nameservers as seed"
    assert expand._ns_is_shared("rob.ns.cloudflare.com")
    assert not expand._ns_is_shared("ns1.autoscout24.com")


def test_org_match_ignores_company_suffixes():
    assert expand._org_matches("AutoScout24 GmbH", {"autoscout24 ag"}, "autoscout24")
    assert not expand._org_matches("Totally Different Inc", {"autoscout24 ag"}, "autoscout24")


def test_registrable_root_two_level_suffixes():
    assert expand._registrable_root("ns1.example.co.uk") == "example.co.uk"
    assert expand._registrable_root("a.b.example.com") == "example.com"
    assert expand._registrable_root("example.de") == "example.de"
