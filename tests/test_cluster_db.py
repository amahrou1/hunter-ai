"""Reversibility and idempotence of clone parking against a real sqlite DB."""

from __future__ import annotations

import sqlite3

import pytest

from hunter import assets as A


@pytest.fixture
def store(tmp_path):
    db = sqlite3.connect(str(tmp_path / "s.db"), isolation_level=None)
    db.row_factory = sqlite3.Row
    s = A.Assets(db)
    # seed a host + services
    s.add_host("e1.event.sbb.ch", A.IN, "test")
    for i in range(5):
        s.upsert_service(f"e{i}.event.sbb.ch", 443, "https",
                         url=f"https://e{i}.event.sbb.ch", status=200, priority=50)
    return s


def _ids(store):
    return {r["host"]: r["id"] for r in store.services()}


def test_park_records_and_lowers_priority(store):
    ids = _ids(store)
    items = [{"service_id": ids[f"e{i}.event.sbb.ch"], "host": f"e{i}.event.sbb.ch",
              "parent": "event.sbb.ch", "proof": "platform-instance", "reason": "x"}
             for i in range(3)]
    n = store.park_services(items)
    assert n == 3
    parked = {r["host"]: r["priority"] for r in store.services(min_priority=0)}
    assert parked["e0.event.sbb.ch"] == 0
    # unparked ones keep priority
    assert parked["e4.event.sbb.ch"] == 50
    # default listing hides parked
    assert len(store.services(min_priority=1)) == 2


def test_restore_family_brings_them_back_and_blocks_reparking(store):
    ids = _ids(store)
    items = [{"service_id": ids[f"e{i}.event.sbb.ch"], "host": f"e{i}.event.sbb.ch",
              "parent": "event.sbb.ch", "proof": "platform-instance", "reason": "x"}
             for i in range(3)]
    store.park_services(items)
    restored = store.unpark_family("event.sbb.ch")
    assert restored == 3
    back = {r["host"]: r["priority"] for r in store.services()}
    assert back["e0.event.sbb.ch"] == 50          # restored to previous priority
    assert "event.sbb.ch" in store.restored_parents()
    # re-parking the same family is now refused (operator said keep it)
    assert store.park_services(items) == 0
    assert all(r["priority"] == 50 for r in store.services())


def test_reconcile_reapplies_after_a_reprobe(store):
    ids = _ids(store)
    items = [{"service_id": ids["e0.event.sbb.ch"], "host": "e0.event.sbb.ch",
              "parent": "event.sbb.ch", "proof": "exact-dup", "reason": "x"}]
    store.park_services(items)
    # simulate a re-probe that reset the priority back to 50
    store.db.execute("UPDATE services SET priority=50 WHERE id=?", (ids["e0.event.sbb.ch"],))
    reapplied = store.reconcile_parked()
    assert reapplied == 1
    assert {r["host"]: r["priority"] for r in store.services()}["e0.event.sbb.ch"] == 0


def test_prev_priority_is_preserved_across_double_park(store):
    ids = _ids(store)
    # a focused host at priority 100 gets parked (shouldn't normally, but test the
    # record keeps the real previous priority for a faithful restore)
    store.db.execute("UPDATE services SET priority=100 WHERE id=?", (ids["e2.event.sbb.ch"],))
    items = [{"service_id": ids["e2.event.sbb.ch"], "host": "e2.event.sbb.ch",
              "parent": "event.sbb.ch", "proof": "exact-dup", "reason": "x"}]
    store.park_services(items)
    store.park_services(items)  # second time: must not overwrite prev_priority with 0
    store.unpark_family("event.sbb.ch")
    assert {r["host"]: r["priority"] for r in store.services()}["e2.event.sbb.ch"] == 100
