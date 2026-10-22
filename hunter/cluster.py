"""Collapse infrastructure clones so the testing phases see distinct apps.

Many programs run a platform that spins up one host per customer/event/tenant,
all on ONE backend: thousands of `<slug>.event.sbb.ch`, or machine-generated
`0-11.binance.com`. Testing them all is testing one app thousands of times - it
starves the deep phases where bugs are found and makes mapping take days.

This collapses clones ONLY ON PROOF they are the same app, never on the hostname
pattern alone. Three proofs, strongest first:

  A. wildcard-echo  - random names that cannot exist resolve and return the same
     response as the members: the parent is a catch-all, members matching it are
     echoes. Direct proof, works at any depth (covers Binance's apex clones).
  B. platform-instance - real instances serving different content but clearly one
     app: same parent, same infrastructure (IPs/CNAME), same server+tech+ctype
     +favicon, status 200, a title pattern shared across the group, large group.
     Covers SBB event microsites. Judgment-ish, so it is AGENT-REVIEWED, not
     auto-parked.
  C. exact-dup - identical body hash, same parent, same infra, 200, large group.
     For empty-title APIs where a template match would be too weak.

Split of work: this module (code) builds the evidence-backed candidate groups and
auto-parks only the strong proofs (A, C). The platform-instance groups (B) are
staged for the probe AGENT to approve or keep, because deciding "is this noise"
is judgment. Everything parked is recorded in cluster_parked (reversible), logged
and never includes a protected host.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict

DEFAULT_MIN_CLUSTER = 10      # a group must be at least this big to collapse
DEFAULT_KEEP = 3             # representatives kept per group (plus protected ones)
PARKED_PRIORITY = 0
TITLE_STABLE_FRACTION = 0.8  # a word is "stable" if >= this fraction of titles have it

# Leftmost-label tokens that mark a host too important to ever auto-collapse.
IMPORTANT_LABEL = ("admin", "api", "auth", "sso", "internal", "intranet", "dev",
                   "staging", "stage", "uat", "preprod", "vpn", "git", "jenkins",
                   "gateway", "graphql", "console", "portal", "dashboard", "secret")

_HEX = re.compile(r"\b[0-9a-f]{4,}\b")
_NUM = re.compile(r"\d+")
_DATE = re.compile(r"\b\d{1,4}[.\-/]\d{1,2}([.\-/]\d{1,4})?\b")
# A machine-generated leftmost label: hex blobs, numbers, dash-number salad.
_MACHINE_LABEL = re.compile(r"^(?:[0-9a-f]{4,}|[0-9]+(?:-[0-9]+)*|[0-9a-f]{2,}-[0-9a-f]{2,})$")


def _is_redirect(status) -> bool:
    """3xx redirects genuinely vary (different Location per host) and must never
    be grouped. Every other status may group WITH infra proof."""
    try:
        return 300 <= int(status) < 400
    except (TypeError, ValueError):
        return True  # unknown status -> treat as non-groupable, be safe


def _is_2xx(status) -> bool:
    """Only a 2xx response is safe to AUTO-park as an exact duplicate. An
    identical NON-2xx body (401/403/503) is a shared GATE or error page, not
    proof the apps behind it are the same - distinct internal APIs legitimately
    return the same 401 auth-challenge. Those go to agent review instead, so a
    real API fleet is never silently dropped."""
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def parent_of(host: str) -> str:
    """The parent that groups a clone family: host minus its leftmost label.
    `0-11.us.api.binance.com` -> `us.api.binance.com`."""
    parts = host.split(".")
    return ".".join(parts[1:]) if len(parts) > 2 else host


def leftmost(host: str) -> str:
    return host.split(".", 1)[0]


def is_machine_label(host: str) -> bool:
    return bool(_MACHINE_LABEL.match(leftmost(host)))


def is_important_label(host: str) -> bool:
    """Only the LEFTMOST label is checked, so 0-2-4.dev.api.binance.com is not
    protected just because it sits under dev.api."""
    label = leftmost(host)
    return any(tok in label for tok in IMPORTANT_LABEL)


# Words that mark a meaningful SERVICE name (vs a random event/tenant slug).
# A host whose label contains one of these is a named service, not platform noise.
_SERVICE_WORDS = ("api", "app", "service", "svc", "adapter", "gateway", "backend",
                  "server", "portal", "admin", "auth", "sync", "worker", "proxy",
                  "management", "order", "billing", "inventory", "info", "ui",
                  "cockpit", "viewer", "shell", "snapshot", "incident", "support",
                  "contact", "center", "costcenter", "identity", "finanz", "partner")


def is_service_name(host: str) -> bool:
    """True when the leftmost label reads as a meaningful SERVICE name - so it
    must NOT be auto-parked on a shared gate response (that is real API surface).
    Conservative: anything that could be a named service returns True, so the
    only things that fall through to 'random slug' are clearly code-like tokens."""
    label = leftmost(host).lower()
    if any(w in label for w in _SERVICE_WORDS):
        return True
    words = [w for w in label.split("-") if w]
    # A label made of several dictionary-ish words (vowel-bearing, >=4 chars) is a
    # named service: contact-center-waittime, ris-modelviewer, gtech-betriebscockpit.
    wordy = [w for w in words if len(w) >= 4 and any(v in w for v in "aeiou")
             and not all(c in "0123456789abcdef" for c in w)]
    return len(wordy) >= 2


def is_random_slug_group(parked: list) -> bool:
    """A group is a random-slug microsite PLATFORM (safe to auto-park even when
    gated) only when NONE of its parked members looks like a named service. If
    even one member reads as a service name, treat the whole group as a service
    fleet -> review, never auto-drop. This is the conservative direction: when in
    doubt, do not auto-park."""
    return not any(is_service_name(dict(r)["host"]) for r in parked)


def _norm_title(title: str) -> str:
    t = (title or "").lower()
    t = _DATE.sub(" ", t)
    t = _HEX.sub(" ", t)
    t = _NUM.sub(" ", t)
    return t


def stable_title_words(titles: list[str]) -> set[str]:
    """Words present in >= TITLE_STABLE_FRACTION of the group's titles: the
    common brand/prefix (e.g. {'sbb'} for '<event> - SBB'). Empty if the titles
    have no shared backbone (then proof B does not apply)."""
    if not titles:
        return set()
    counts: dict[str, int] = defaultdict(int)
    for t in titles:
        for w in set(_norm_title(t).split()):
            if len(w) >= 3:
                counts[w] += 1
    threshold = max(2, int(len(titles) * TITLE_STABLE_FRACTION))
    return {w for w, n in counts.items() if n >= threshold}


def _infra_key(row) -> tuple:
    """Shared-infrastructure key from the host's resolution. Services with the
    same IP set or the same CNAME target are on the same backend."""
    cname = (row.get("cname") or "").strip().lower().rstrip(".")
    if cname:
        return ("cname", cname)
    addrs = row.get("addresses")
    if addrs:
        try:
            ips = tuple(sorted(json.loads(addrs))) if isinstance(addrs, str) else tuple(sorted(addrs))
        except (ValueError, TypeError):
            ips = ()
        if ips:
            return ("ip", ips)
    return ("none", row["host"])  # unknown infra -> unique, never groups


# --------------------------------------------------------------------------
# Candidate grouping
# --------------------------------------------------------------------------

def _b_signature(row) -> tuple:
    """Platform-instance signature: same parent + infra + server/tech/ctype +
    favicon + status 200. Title is handled separately (stable-words)."""
    return (
        parent_of(row["host"]),
        _infra_key(row),
        row["status"],
        (row.get("server") or "").lower(),
        (row.get("tech") or "").lower(),
        (row.get("content_type") or "").split(";")[0].lower(),
        row.get("favicon_hash") or "",
    )


def _c_signature(row) -> tuple:
    """Exact-duplicate signature: same parent + infra + status + exact body."""
    return (parent_of(row["host"]), _infra_key(row), row["status"], row.get("body_hash") or "")


def _is_protected(row, protected: set[str]) -> bool:
    host = row["host"]
    if host in protected:
        return True
    if is_important_label(host):
        return True
    return False


def _pick_reps(rows: list, keep: int, protected: set[str]) -> set[str]:
    """Hosts to KEEP in a group: every protected member (never parked) plus up to
    `keep` non-protected representatives spread across response sizes (smallest,
    largest, median) so an outlier by size is retained."""
    kept = {r["host"] for r in rows if _is_protected(r, protected)}
    non_protected = sorted((r for r in rows if not _is_protected(r, protected)),
                           key=lambda r: (r.get("content_length") or 0))
    if not non_protected:
        return kept
    picks: list[int] = []
    for idx in (0, len(non_protected) - 1, len(non_protected) // 2):
        if idx not in picks:
            picks.append(idx)
    for idx in picks:
        if len([h for h in kept if h in {r["host"] for r in non_protected}]) >= keep:
            break
        kept.add(non_protected[idx]["host"])
    return kept


def _service_rows(services: list) -> list:
    """services may be sqlite3.Row; make them plain dicts with .get()."""
    return [dict(r) for r in services]


def plan(services: list, *, protected: set[str] | None = None,
         wildcard_parents: set[str] | None = None,
         echo_hosts: set[str] | None = None,
         min_cluster: int = DEFAULT_MIN_CLUSTER, keep: int = DEFAULT_KEEP,
         apex_roots: set[str] | None = None) -> dict:
    """Build candidate clone groups with proof. Pure (no DB writes).

    protected: hosts never parked (policy assets, focus, leads, takeover).
    wildcard_parents / echo_hosts: results of the agent/code wildcard-echo probe
      (Proof A). echo_hosts are confirmed catch-all echoes -> auto-park.
    apex_roots: the program's scope roots; directly under these, Proof B also
      requires a machine-generated label.

    Returns {"auto": [...groups to park now...],
             "review": [...platform-instance groups for the agent...],
             "auto_parked_services": [service_id...]}.
    """
    protected = {h.lower() for h in (protected or set())}
    echo_hosts = {h.lower() for h in (echo_hosts or set())}
    apex_roots = {r.lower() for r in (apex_roots or set())}
    rows = _service_rows(services)

    auto_groups: list[dict] = []
    review_groups: list[dict] = []
    auto_ids: list[int] = []
    claimed: set[int] = set()  # service ids already placed in a group

    # ---- Proof A: wildcard echo (auto-park, strongest) -------------------
    if echo_hosts:
        by_parent: dict[str, list] = defaultdict(list)
        for r in rows:
            if r["host"] in echo_hosts and not _is_protected(r, protected):
                by_parent[parent_of(r["host"])].append(r)
        for parent, grp in by_parent.items():
            ids = [r["id"] for r in grp]
            claimed.update(ids)
            auto_ids.extend(ids)
            auto_groups.append({"proof": "wildcard-echo", "parent": parent,
                                "size": len(grp), "parked_count": len(grp),
                                "sample_parked": [r["host"] for r in grp[:5]]})

    # ---- Proof C: exact duplicates (auto-park) ---------------------------
    # AUTO-park only 2xx exact duplicates. A non-2xx identical body (shared 401
    # auth-gate, 403, 503 "down" page) is NOT proof the apps are the same - those
    # fall through to Proof B below and go to AGENT REVIEW, so an internal API
    # fleet behind a shared gate is never auto-dropped (that surface is where
    # BAC/auth-bypass bugs live).
    c_groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        if r["id"] in claimed or _is_protected(r, protected):
            continue
        if not _is_2xx(r["status"]) or not r.get("body_hash"):
            continue  # only 2xx auto-parks; non-2xx handled by Proof B (review)
        if _infra_key(r)[0] == "none":
            continue  # no infra proof -> do not group
        c_groups[_c_signature(r)].append(r)
    for sig, grp in c_groups.items():
        if len(grp) < min_cluster:
            continue
        reps = _pick_reps(grp, keep, protected)
        parked = [r for r in grp if r["host"] not in reps]
        if not parked:
            continue
        ids = [r["id"] for r in parked]
        claimed.update(r["id"] for r in grp)
        auto_ids.extend(ids)
        auto_groups.append({"proof": "exact-dup", "parent": sig[0], "size": len(grp),
                            "kept": sorted(reps), "parked_count": len(parked),
                            "parked_candidate_ids": ids,
                            "sample_parked": [r["host"] for r in parked[:5]]})

    # ---- Proof B: platform instances (AGENT-REVIEWED) -------------------
    # Any non-redirect status may group here, BUT only with real infra proof
    # (shared IPs/CNAME). That is what keeps distinct apps behind a shared WAF/
    # login page from merging: they would need the SAME backend IPs to group. A
    # gated microsite platform (thousands of same-parent 403s on the same IPs,
    # same length) is exactly one backend, so excluding non-200 broke the real
    # SBB case and is not needed - the infra key is the guard.
    b_groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        if r["id"] in claimed or _is_protected(r, protected):
            continue
        if _is_redirect(r["status"]):
            continue
        if _infra_key(r)[0] == "none":
            continue
        b_groups[_b_signature(r)].append(r)
    for sig, grp in b_groups.items():
        if len(grp) < min_cluster:
            continue
        parent = sig[0]
        # Apex rule: directly under a scope root, require machine-generated labels
        # so real apps (shop, careers) are never grouped by template.
        if parent in apex_roots and not all(is_machine_label(r["host"]) for r in grp):
            # keep only the machine-labelled members as a group; the rest stay.
            machine = [r for r in grp if is_machine_label(r["host"])]
            if len(machine) < min_cluster:
                continue
            grp = machine
        titles = [r.get("title") or "" for r in grp]
        machine_group = all(is_machine_label(r["host"]) for r in grp)
        stable = stable_title_words(titles)
        # Accept the group when ANY of these holds (each is strong evidence of one
        # backend, given the signature already fixed parent+infra+status+length+
        # server+ctype+favicon):
        #  - a shared title backbone (e.g. "<event> - SBB"), or
        #  - an all-machine-label group (0-11.binance.com style), or
        #  - a proven SHARED-IP/CNAME infra set (sig[1][0] in {ip, cname}). A large
        #    group of same-parent hosts on identical IPs with an identical response
        #    (incl. gated 403/401 microsites with empty titles) is one backend.
        strong_infra = sig[1][0] in ("ip", "cname")
        if not stable and not machine_group and not strong_infra:
            continue
        reps = _pick_reps(grp, keep, protected)
        parked = [r for r in grp if r["host"] not in reps]
        if not parked:
            continue
        status_2xx = _is_2xx(sig[2])
        # A true microsite PLATFORM is a large same-parent group whose members are
        # RANDOM slugs (event/tenant codes). Those auto-park even when gated (403),
        # because they are one platform minting hosts - the SBB event.sbb.ch case.
        # A group of DISTINCT NAMED services sharing a gate (the api/app internal
        # fleet: itop-sbb-acm, contact-center-waittime, ...) is NOT platform noise:
        # it goes to review so real API surface behind a shared 401/503 is never
        # auto-dropped. 2xx platform-instances also stay review (judgment).
        random_platform = is_random_slug_group(parked)
        if random_platform and not status_2xx:
            claimed.update(r["id"] for r in grp)
            ids = [r["id"] for r in parked]
            auto_ids.extend(ids)
            auto_groups.append({"proof": "platform-instance", "parent": parent,
                                "size": len(grp), "kept": sorted(reps),
                                "parked_count": len(parked), "parked_candidate_ids": ids,
                                "sample_parked": [r["host"] for r in parked[:5]]})
            continue
        claimed.update(r["id"] for r in grp)
        review_groups.append({
            "proof": "platform-instance", "parent": parent, "size": len(grp),
            "infra": sig[1][0], "server": sig[3], "status": sig[2],
            "stable_title_words": sorted(stable),
            "kept": sorted(reps),
            "parked_candidate_ids": [r["id"] for r in parked],
            "parked_count": len(parked),
            "sample_parked": [r["host"] for r in parked[:8]],
            "sample_titles": list(dict.fromkeys(titles))[:5],
        })

    auto_groups.sort(key=lambda c: -c["size"])
    review_groups.sort(key=lambda c: -c["size"])
    return {"auto": auto_groups, "review": review_groups, "auto_parked_services": auto_ids}


def random_probe_names(parent: str, n: int = 3) -> list[str]:
    """Names that cannot legitimately exist under `parent`, for the catch-all
    (wildcard-echo) probe."""
    import secrets
    return [f"{secrets.token_hex(5)}-hunter-nx.{parent}" for _ in range(n)]


def _park_items(services: list, group: dict) -> list[dict]:
    """Build park_services() items for the hosts a group parks."""
    kept = set(group.get("kept", []))
    by_host = {}
    for r in services:
        d = dict(r)
        by_host.setdefault(d["host"], d)
    items = []
    for r in services:
        d = dict(r)
        if "parked_candidate_ids" in group:
            if d["id"] not in group["parked_candidate_ids"]:
                continue
        else:  # auto groups: park members of this parent not kept
            if parent_of(d["host"]) != group["parent"] or d["host"] in kept:
                continue
            # only members flagged into this group (sample covers echo/exact sets)
        items.append({"service_id": d["id"], "host": d["host"], "parent": group["parent"],
                      "proof": group["proof"],
                      "reason": f"{group['proof']} clone of {group['parent']} "
                                f"({group['size']} same-backend hosts)"})
    return items


def apply_auto(store, services: list, report: dict) -> int:
    """Park the auto groups (wildcard-echo, exact-dup, random-slug platform) with
    full records. Each auto group carries the exact service ids the plan chose."""
    rows = {dict(r)["id"]: dict(r) for r in services}
    parked = 0
    # wildcard-echo: auto_parked_services carries the exact ids.
    echo_ids = set(report.get("auto_parked_services", []))
    items = []
    for g in report["auto"]:
        # exact-dup and random-slug platform-instance auto groups both carry
        # parked_candidate_ids; wildcard-echo ids are in auto_parked_services.
        for sid in g.get("parked_candidate_ids", []):
            d = rows.get(sid)
            if d:
                items.append({"service_id": sid, "host": d["host"], "parent": g["parent"],
                              "proof": g["proof"],
                              "reason": f"{g['proof']} clone of {g['parent']} ({g['size']} hosts)"})
    for sid in echo_ids:
        if sid in rows:
            d = rows[sid]
            items.append({"service_id": sid, "host": d["host"], "parent": parent_of(d["host"]),
                          "proof": "wildcard-echo",
                          "reason": f"wildcard-echo under {parent_of(d['host'])}"})
    # de-dup by service_id
    seen, uniq = set(), []
    for it in items:
        if it["service_id"] not in seen:
            seen.add(it["service_id"])
            uniq.append(it)
    return store.park_services(uniq)


def apply_review_group(store, group: dict) -> int:
    """Park one platform-instance group the agent approved."""
    items = [{"service_id": sid, "host": "", "parent": group["parent"],
              "proof": "platform-instance",
              "reason": f"platform-instance of {group['parent']} ({group['size']} hosts), "
                        f"agent-approved"}
             for sid in group["parked_candidate_ids"]]
    # fill host for the record
    for it in items:
        row = store.db.execute("SELECT host FROM services WHERE id=?", (it["service_id"],)).fetchone()
        it["host"] = row["host"] if row else ""
    return store.park_services(items)
