"""Infrastructure-clone collapsing, evidence-based. Covers the real cases:
SBB event microsites, Binance apex wildcard clones, and the failure modes we
must NOT hit (WAF/redirect pages, distinct APIs, mixed-port hosts, protected
hosts). Proofs: wildcard-echo (A, auto), platform-instance (B, agent-reviewed),
exact-dup (C, auto)."""

from __future__ import annotations

import json

from hunter import cluster


def _svc(sid, host, status=200, server="nginx", tech="", ctype="text/html",
         title="Event", length=5000, body_hash=None, favicon="f1",
         addresses=("10.0.0.1",), cname="", port=443):
    return {"id": sid, "host": host, "status": status, "server": server, "tech": tech,
            "content_type": ctype, "title": title, "content_length": length,
            "body_hash": body_hash or f"h{sid}", "favicon_hash": favicon,
            "addresses": json.dumps(list(addresses)), "cname": cname, "port": port}


# ---------------------------------------------------------------- Proof B (SBB)
def test_sbb_event_microsites_are_a_review_group_not_auto_parked():
    # 50 event microsites: same infra, server, favicon, 200, shared title word
    # "sbb", but different event names -> platform-instance (agent-reviewed).
    svcs = [_svc(i, f"event-{i}.event.sbb.ch", title=f"Event {i} - SBB", length=5000 + i)
            for i in range(50)]
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"})
    assert rep["auto"] == []                       # NOT auto-parked (judgment)
    assert len(rep["review"]) == 1
    g = rep["review"][0]
    assert g["parent"] == "event.sbb.ch"
    assert g["size"] == 50
    assert len(g["kept"]) == 3
    assert "sbb" in g["stable_title_words"]


# ---------------------------------------------------------------- Proof A (Binance)
def test_binance_apex_clones_auto_park_only_as_wildcard_echoes():
    # machine-labelled apex clones; they are echoes (random names match them)
    svcs = [_svc(i, f"0-{i}.binance.com", title="", body_hash="SAME") for i in range(30)]
    echoes = {s["host"] for s in svcs}
    rep = cluster.plan(svcs, echo_hosts=echoes, apex_roots={"binance.com"})
    assert len(rep["auto"]) == 1
    assert rep["auto"][0]["proof"] == "wildcard-echo"
    assert len(rep["auto_parked_services"]) == 30


def test_apex_non_machine_labels_are_never_grouped_by_template():
    # real distinct apps directly under the apex: shop, careers, status, help...
    svcs = [_svc(i, h + ".binance.com", title="Portal")
            for i, h in enumerate(["shop", "careers", "status", "help", "news",
                                    "blog", "about", "jobs", "press", "legal",
                                    "invest", "learn"])]
    rep = cluster.plan(svcs, apex_roots={"binance.com"})
    # same signature would group them, but the apex rule needs machine labels
    assert rep["review"] == []
    assert rep["auto"] == []


def test_apex_machine_labels_without_echo_can_be_review_group():
    # machine-labelled apex clones, same infra/fingerprint, but NOT proven echoes
    svcs = [_svc(i, f"0-{i}.binance.com", title="") for i in range(20)]
    rep = cluster.plan(svcs, apex_roots={"binance.com"})
    # no echo proof -> not auto; machine-label group -> offered for review
    assert rep["auto"] == []
    assert len(rep["review"]) == 1
    assert all(cluster.is_machine_label(h) for h in rep["review"][0]["sample_parked"])


# ---------------------------------------------------------------- must-NOT cases
def test_different_apps_behind_same_waf_page_are_not_grouped():
    # same 403 body, but DIFFERENT infrastructure -> not one backend
    svcs = [_svc(i, f"app{i}.acme.com", status=403, body_hash="WAFPAGE",
                 addresses=(f"10.0.{i}.1",)) for i in range(20)]
    rep = cluster.plan(svcs, apex_roots={"acme.com"})
    assert rep["auto"] == [] and rep["review"] == []   # 403 + distinct infra


def test_redirects_are_not_grouped():
    # 302 login redirects, same target - status != 200 so never a B/C group
    svcs = [_svc(i, f"x{i}.acme.com", status=302, body_hash="REDIR") for i in range(20)]
    rep = cluster.plan(svcs, apex_roots={"acme.com"})
    assert rep["auto"] == [] and rep["review"] == []


def test_same_infra_same_fingerprint_different_body_is_review_not_auto():
    # 20 hosts: same parent, same IP, same status/length/server, empty titles,
    # but different bodies. This is strong evidence of ONE templated backend
    # (like SBB events differing byte-wise), so it is offered for REVIEW - never
    # auto-parked. The agent decides; nothing is removed without judgment.
    svcs = [_svc(i, f"n{i}.svc.acme.com", title="", ctype="application/json",
                 body_hash=f"different{i}") for i in range(20)]
    rep = cluster.plan(svcs, apex_roots={"acme.com"})
    assert rep["auto"] == []                 # never auto-parked
    assert len(rep["review"]) == 1           # offered for agent judgment
    assert rep["review"][0]["infra"] == "ip"


def test_different_infra_never_groups_even_with_same_fingerprint():
    # the real safety: distinct apps on DIFFERENT IPs never group, whatever the
    # status or fingerprint. This is what protects separate apps behind a shared
    # WAF page - they would need the SAME backend IPs to merge.
    svcs = [_svc(i, f"n{i}.svc.acme.com", title="", status=403,
                 body_hash="WAF", addresses=(f"10.{i}.0.1",)) for i in range(20)]
    rep = cluster.plan(svcs, apex_roots={"acme.com"})
    assert rep["auto"] == [] and rep["review"] == []


def test_sbb_gated_403_random_microsites_auto_park():
    # the REAL SBB event case: hundreds of RANDOM-SLUG microsites returning 403 on
    # shared IPs under a dedicated platform parent -> a true microsite platform,
    # AUTO-parked even though gated (random labels, not named services).
    svcs = [_svc(i, f"{_slug(i)}.event.sbb.ch", status=403, title="", server="",
                 length=None, body_hash="SAME403", favicon="") for i in range(500)]
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"})
    assert len(rep["auto"]) == 1
    g = rep["auto"][0]
    assert g["parent"] == "event.sbb.ch"
    assert g["parked_count"] == 497          # keep 3 of 500


def test_named_api_fleet_behind_shared_gate_goes_to_review_not_auto():
    # the api/app internal fleet: DISTINCT NAMED services sharing an identical 401
    # gate on shared IPs. Must NOT auto-park (that is real API surface where BAC
    # bugs live) - it goes to agent review instead.
    names = ["contact-center-waittime", "itop-sbb-acm-int", "p2p-sync",
             "itsm-sc-order", "zvs-vb-worker-snapshot", "network-adapter-details",
             "processmodelling-int", "sts-billing", "tmf-sync-test",
             "smp-impersonal-users", "costcenter-information", "identity-info"]
    svcs = [_svc(i, f"{n}.api.sbb.ch", status=401, title="",
                 ctype="application/json", body_hash="SAME401") for i, n in enumerate(names)]
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"})
    assert rep["auto"] == []                 # never auto-dropped
    assert len(rep["review"]) == 1
    assert rep["review"][0]["parent"] == "api.sbb.ch"


def _slug(i):
    # random-looking event codes like the real 08ce-7495 / 042324inputsl / zvdgclxe
    import hashlib
    return hashlib.md5(str(i).encode()).hexdigest()[:8]


def test_identical_endpoints_exact_dup_auto_parks():
    # identical JSON bodies, same infra -> exact-dup (Proof C) auto-parks.
    svcs = [_svc(i, f"n{i}.svc.acme.com", title="", ctype="application/json",
                 body_hash="IDENTICAL") for i in range(20)]
    rep = cluster.plan(svcs, apex_roots={"acme.com"})
    assert len(rep["auto"]) == 1
    assert rep["auto"][0]["proof"] == "exact-dup"


def test_behavioural_outlier_survives_inside_a_clone_family():
    svcs = [_svc(i, f"e{i}.event.sbb.ch", title=f"Event {i} - SBB", length=5000)
            for i in range(40)]
    # an admin panel hiding among the event clones: different length/title/server
    svcs.append(_svc(999, "secret-admin.event.sbb.ch", title="Admin Console",
                     length=250, server="express", favicon="f9"))
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"})
    g = rep["review"][0]
    all_parked = []
    for grp in rep["review"]:
        all_parked += grp["sample_parked"]
    assert "secret-admin.event.sbb.ch" not in all_parked
    assert 999 not in g["parked_candidate_ids"]


# ---------------------------------------------------------------- protection
def test_protected_hosts_are_never_parked():
    svcs = [_svc(i, f"e{i}.event.sbb.ch", title=f"Event {i} - SBB") for i in range(40)]
    # mark one as protected (policy-listed / focused / has a lead)
    rep = cluster.plan(svcs, protected={"e5.event.sbb.ch"}, apex_roots={"sbb.ch"})
    # protected host must not be a parking candidate in ANY group
    for g in rep["review"] + rep["auto"]:
        assert 5 not in g.get("parked_candidate_ids", [])
        assert "e5.event.sbb.ch" not in g.get("sample_parked", [])


def test_important_label_hosts_are_never_parked():
    svcs = [_svc(i, f"e{i}.event.sbb.ch", title=f"Event {i} - SBB") for i in range(40)]
    svcs.append(_svc(999, "api.event.sbb.ch", title="Event X - SBB"))  # api => important
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"})
    g = rep["review"][0]
    assert 999 not in g["parked_candidate_ids"]


def test_important_label_only_checks_leftmost():
    # dev.api is in the parent, but the leftmost label 0-2-4 is machine -> not protected
    assert not cluster.is_important_label("0-2-4.dev.api.binance.com")
    assert cluster.is_important_label("api.binance.com")
    assert cluster.is_important_label("admin.acme.com")


def test_mixed_port_host_parks_only_the_clone_service():
    # host serves an event clone on 443 and something else on 8443
    clones = [_svc(i, f"e{i}.event.sbb.ch", title=f"Event {i} - SBB") for i in range(40)]
    # the odd service: same host as a clone but different app (diff title/length)
    odd = _svc(500, "e3.event.sbb.ch", port=8443, title="Grafana", server="grafana",
               length=99000, favicon="fx")
    rep = cluster.plan(clones + [odd], apex_roots={"sbb.ch"})
    g = rep["review"][0]
    assert 500 not in g["parked_candidate_ids"]      # the 8443 app is not parked


# ---------------------------------------------------------------- infra proof
def test_no_infra_means_no_grouping():
    # no addresses, no cname -> infra unknown -> never grouped
    svcs = [{"id": i, "host": f"e{i}.event.sbb.ch", "status": 200, "server": "nginx",
             "tech": "", "content_type": "text/html", "title": f"Event {i} - SBB",
             "content_length": 5000, "body_hash": f"h{i}", "favicon_hash": "f1",
             "addresses": None, "cname": ""} for i in range(40)]
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"})
    assert rep["auto"] == [] and rep["review"] == []


def test_small_group_left_alone():
    svcs = [_svc(i, f"e{i}.event.sbb.ch", title=f"Event {i} - SBB") for i in range(5)]
    rep = cluster.plan(svcs, apex_roots={"sbb.ch"}, min_cluster=10)
    assert rep["auto"] == [] and rep["review"] == []


# ---------------------------------------------------------------- helpers
def test_parent_of_and_machine_label():
    assert cluster.parent_of("0-11.us.api.binance.com") == "us.api.binance.com"
    assert cluster.is_machine_label("0-5-3.binance.com")
    assert cluster.is_machine_label("08ce-7495.event.sbb.ch")
    assert not cluster.is_machine_label("careers.binance.com")


def test_stable_title_words():
    titles = ["Event A - SBB", "Event B - SBB", "Workshop - SBB", "Meeting - SBB"]
    assert "sbb" in cluster.stable_title_words(titles)
    # a group with no common backbone -> empty
    assert cluster.stable_title_words(["Alpha", "Bravo", "Charlie", "Delta"]) == set()
