"""Infrastructure-clone collapsing: big same-backend groups park to a few
representatives; small/diverse groups and behavioural outliers are left alone."""

from __future__ import annotations

from hunter import cluster


def _svc(host, status=200, server="nginx", tech="", ctype="text/html",
         title="Event", length=5000):
    return {"host": host, "status": status, "server": server, "tech": tech,
            "content_type": ctype, "title": title, "content_length": length}


def test_big_clone_group_is_collapsed_to_representatives():
    # 50 event microsites, same backend signature, differing only by event name
    services = [_svc(f"event-{i}.event.sbb.ch", title=f"Event {i} - SBB", length=5000 + i)
                for i in range(50)]
    report = cluster.plan(services, min_cluster=10, keep=3)
    assert len(report["clusters"]) == 1
    c = report["clusters"][0]
    assert c["parent"] == "event.sbb.ch"
    assert c["size"] == 50
    assert len(c["kept"]) == 3
    assert report["parked"] == 47          # 50 - 3 kept


def test_small_group_is_left_alone():
    services = [_svc(f"a{i}.event.sbb.ch") for i in range(5)]  # below min_cluster
    report = cluster.plan(services, min_cluster=10, keep=3)
    assert report["clusters"] == []
    assert report["parked"] == 0


def test_diverse_hosts_under_same_parent_are_not_collapsed():
    # same parent, but genuinely different apps (different server/title/status)
    services = [
        _svc("api.acme.com", server="nginx", title="API"),
        _svc("shop.acme.com", server="apache", title="Shop", status=200, length=90000),
        _svc("admin.acme.com", server="iis", title="Admin", status=403, length=200),
        _svc("blog.acme.com", server="nginx", title="Blog", length=12000),
    ]
    report = cluster.plan(services, min_cluster=3, keep=1)
    # each has a distinct signature -> no group reaches min_cluster
    assert report["parked"] == 0


def test_behavioural_outlier_survives_inside_a_clone_family():
    # 40 identical clones + 1 that behaves differently (different status/length)
    services = [_svc(f"e{i}.event.sbb.ch", length=5000) for i in range(40)]
    outlier = _svc("secret-admin.event.sbb.ch", status=200, title="Admin Panel",
                   length=250, server="express")
    services.append(outlier)
    report = cluster.plan(services, min_cluster=10, keep=3)
    # the outlier has a different signature -> not in the parked set
    assert "secret-admin.event.sbb.ch" not in report["parked_hosts"]


def test_signature_ignores_hostname_label():
    a = _svc("alpha.event.sbb.ch", title="Event A", length=5000)
    b = _svc("beta.event.sbb.ch", title="Event B", length=5000)
    # same template/parent/server/status/length-bucket -> same signature
    assert cluster.signature(a) == cluster.signature(b)


def test_title_template_strips_dates_and_numbers():
    assert cluster._title_template("Event 2024-03-15 #4821") == \
           cluster._title_template("Event 2023-11-02 #9100")


def test_apply_parks_in_db():
    class FakeStore:
        def __init__(self):
            self.parked: list[str] = []

        def set_priority_hosts(self, hosts, priority):
            assert priority == 0
            self.parked.extend(hosts)
            return len(hosts)

    services = [_svc(f"e{i}.event.sbb.ch", length=5000) for i in range(30)]
    store = FakeStore()
    report = cluster.apply(store, services, min_cluster=10, keep=3)
    assert len(store.parked) == report["parked"] == 27
    assert all(h.endswith(".event.sbb.ch") for h in store.parked)
