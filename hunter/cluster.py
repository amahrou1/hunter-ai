"""Collapse infrastructure clones so the testing phases see distinct apps.

Many programs run a platform that spins up one host per customer/event/tenant,
all on the SAME backend: e.g. thousands of `<slug>.event.sbb.ch`. Testing all of
them is testing one app thousands of times - it starves the deep phases where
bugs are actually found, and makes mapping/crawling take days.

This clusters live services by a BEHAVIOURAL signature (same backend, proven by
response shape - never by the hostname label alone), keeps a few representatives
per big cluster, and sets the rest to priority 0 so every downstream phase skips
them (they all select priority > 0). Nothing is deleted: the hosts stay in the
inventory, the collapse is recorded, and it is fully reversible with
`hk priority <pattern> 50`.

Safety, matching the operator's own rules:
- Collapse only a cluster that is genuinely large AND shares a parent domain AND
  has a near-identical response signature. Small or diverse groups are untouched.
- A host whose behaviour DIFFERS (status, length outlier) is kept at full
  priority even inside a clone parent, so a vulnerable odd-one-out survives.
- Always keep representatives; never reduce a cluster to zero.
"""

from __future__ import annotations

import re
from collections import defaultdict

# A cluster must have at least this many members to be collapsed.
DEFAULT_MIN_CLUSTER = 10
# How many representatives to keep per collapsed cluster.
DEFAULT_KEEP = 3
# Priority a clustered-away host is set to (0 = skipped by every phase).
PARKED_PRIORITY = 0

_HEX = re.compile(r"\b[0-9a-f]{4,}\b")
_NUM = re.compile(r"\d+")
_DATE = re.compile(r"\b\d{1,4}[.\-/]\d{1,2}([.\-/]\d{1,4})?\b")


def _parent(host: str) -> str:
    """The parent that groups a clone family: the host minus its leftmost label.
    `alumni-event-2023.event.sbb.ch` -> `event.sbb.ch`."""
    parts = host.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else host


def _title_template(title: str) -> str:
    """Reduce a title to a template that sibling microsites share. Strips the
    per-instance bits (dates, numbers, hex ids) AND collapses the variable event
    name: microsites built from one platform keep a common prefix/suffix (e.g.
    "<event name> - SBB") and differ only in that name. We keep the stable parts
    (first word + any brand suffix) and template the middle, so "Event A - SBB"
    and "Event B - SBB" match while a genuinely different title ("Admin Panel")
    does not."""
    t = (title or "").lower().strip()
    t = _DATE.sub("<d>", t)
    t = _HEX.sub("<h>", t)
    t = _NUM.sub("<n>", t)
    words = t.split()
    if len(words) <= 1:
        return t
    # Keep the first and last word (stable brand/prefix), template the middle.
    if len(words) == 2:
        # "Event A" / "Event B" -> keep first word, template the rest.
        return words[0] + " <x>"
    return words[0] + " <x> " + words[-1]


def _length_bucket(length: int | None) -> int:
    """Bucket content-length so cosmetically-different-but-same-template pages
    (an event name changes a few bytes) land together. Log-ish buckets."""
    if not length or length < 0:
        return -1
    if length < 1000:
        return length // 200
    if length < 20000:
        return 1000 + length // 2000
    return 2000 + length // 20000


def signature(row) -> tuple:
    """Behavioural signature of a service: same signature => very likely the
    same backend. Deliberately ignores the hostname label itself."""
    return (
        _parent(row["host"]),
        row["status"],
        (row["server"] or "").lower(),
        (row["tech"] or "").lower(),
        (row["content_type"] or "").split(";")[0].lower(),
        _title_template(row["title"] or ""),
        _length_bucket(row["content_length"]),
    )


def plan(services: list, min_cluster: int = DEFAULT_MIN_CLUSTER,
         keep: int = DEFAULT_KEEP) -> dict:
    """Decide which services to park. Returns a report:
    {"clusters": [{signature, parent, size, kept:[host], parked:[host]}],
     "parked_hosts": [host...], "kept": n, "parked": n}.
    Pure function - does not touch the DB."""
    groups: dict[tuple, list] = defaultdict(list)
    for row in services:
        groups[signature(row)].append(row)

    clusters = []
    parked_hosts: list[str] = []
    for sig, rows in groups.items():
        if len(rows) < min_cluster:
            continue  # small/diverse group: leave it fully tested
        # Keep representatives: prefer ones with distinct behaviour, then fill.
        rows_sorted = sorted(rows, key=lambda r: (r["content_length"] or 0))
        reps = []
        # the smallest, the largest, and the median - spread across the cluster.
        for idx in dict.fromkeys([0, len(rows_sorted) - 1, len(rows_sorted) // 2]):
            if len(reps) < keep:
                reps.append(rows_sorted[idx])
        kept_hosts = {r["host"] for r in reps}
        parked = [r["host"] for r in rows if r["host"] not in kept_hosts]
        if not parked:
            continue
        parked_hosts.extend(parked)
        clusters.append({
            "parent": sig[0], "status": sig[1], "size": len(rows),
            "kept": sorted(kept_hosts), "parked_count": len(parked),
            "sample_parked": parked[:5],
        })
    clusters.sort(key=lambda c: -c["size"])
    return {"clusters": clusters, "parked_hosts": parked_hosts,
            "parked": len(parked_hosts)}


def apply(store, services: list, min_cluster: int = DEFAULT_MIN_CLUSTER,
          keep: int = DEFAULT_KEEP) -> dict:
    """Run plan() and set parked hosts to PARKED_PRIORITY in the DB. Returns the
    report (with the hosts actually parked)."""
    report = plan(services, min_cluster=min_cluster, keep=keep)
    if report["parked_hosts"]:
        store.set_priority_hosts(report["parked_hosts"], PARKED_PRIORITY)
    return report
