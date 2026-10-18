"""Inventory of discovered hosts and services, in the run's SQLite database.

Hosts come from recon (phase 02). Services (a live HTTP endpoint on a host)
come from probing (phase 03). Both carry provenance (which source found it)
and a scope decision, so later phases only ever work on in-scope, live,
first-party assets, and the final report can show the whole surface.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

# Host classification
IN = "in_scope"
OUT = "out_of_scope"
THIRD_PARTY = "third_party"      # resolves to a provider that pays nothing
UNRESOLVED = "unresolved"

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    host TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    source TEXT,
    resolved INTEGER NOT NULL DEFAULT 0,
    addresses TEXT,
    cname TEXT,
    third_party_reason TEXT,
    takeover_candidate INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    url TEXT NOT NULL,
    status INTEGER,
    title TEXT,
    server TEXT,
    tech TEXT,
    content_type TEXT,
    content_length INTEGER,
    body_hash TEXT,
    baseline TEXT,
    priority INTEGER NOT NULL DEFAULT 50,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (host, port, scheme)
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host);
"""

# Hosts whose A/AAAA or CNAME point at these are almost never the program's
# own origin. They are kept but deprioritised and flagged third party.
THIRD_PARTY_CNAME = (
    "zendesk.com", "statuspage.io", "github.io", "herokuapp.com", "herokudns.com",
    "myshopify.com", "wordpress.com", "wpengine.com", "squarespace.com", "wixdns.net",
    "salesforce.com", "force.com", "desk.com", "freshdesk.com", "intercom.io",
    "hubspot.com", "hs-sites.com", "marketo.com", "pardot.com", "sendgrid.net",
    "cloudfront.net", "akamai.net", "akamaiedge.net", "fastly.net", "azureedge.net",
    "cdn.cloudflare.net", "edgekey.net", "readthedocs.io", "netlify.app", "vercel.app",
    "pages.dev", "firebaseapp.com", "web.app", "s3.amazonaws.com", "googleusercontent.com",
    "ghost.io", "helpscoutdocs.com", "gitbook.io", "surge.sh", "bitbucket.io",
)
# CNAMEs that often indicate a dangling record (subdomain takeover).
TAKEOVER_FINGERPRINTS = (
    "github.io", "herokudns.com", "herokuapp.com", "wordpress.com", "pantheonsite.io",
    "myshopify.com", "statuspage.io", "ghost.io", "surge.sh", "bitbucket.io",
    "fastly.net", "readthedocs.io", "netlify.app", "readme.io", "unbouncepages.com",
    "helpscoutdocs.com", "wpengine.com", "azurewebsites.net", "cloudapp.net",
    "trafficmanager.net", "zendesk.com", "desk.com",
)


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def classify_cname(cname: str) -> tuple[str | None, bool]:
    """Return (third_party_provider_or_None, takeover_candidate)."""
    c = (cname or "").strip().lower().rstrip(".")
    if not c:
        return None, False
    provider = next((p for p in THIRD_PARTY_CNAME if c == p or c.endswith("." + p)), None)
    takeover = any(c == p or c.endswith("." + p) for p in TAKEOVER_FINGERPRINTS)
    return provider, takeover


@dataclass
class Host:
    host: str
    scope: str
    resolved: bool = False
    addresses: list = None
    cname: str = ""
    third_party_reason: str = ""
    takeover_candidate: bool = False


class Assets:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(hosts)")}
        if "probed" not in columns:
            self.db.execute("ALTER TABLE hosts ADD COLUMN probed INTEGER NOT NULL DEFAULT 0")
            # Databases from before probe tracking: a host with a live service
            # was certainly probed already.
            self.db.execute("UPDATE hosts SET probed=1 WHERE host IN (SELECT host FROM services)")

    # hosts ----------------------------------------------------------------
    def add_host(self, host: str, scope: str, source: str) -> bool:
        """Insert or touch a host. Returns True if it was new."""
        host = host.strip().lower().rstrip(".")
        if not host:
            return False
        existing = self.db.execute("SELECT host FROM hosts WHERE host=?", (host,)).fetchone()
        if existing:
            self.db.execute("UPDATE hosts SET last_seen=?, source=COALESCE(source, ?) WHERE host=?",
                            (now(), source, host))
            return False
        self.db.execute(
            "INSERT INTO hosts(host, scope, source, first_seen, last_seen) VALUES(?,?,?,?,?)",
            (host, scope, source, now(), now()))
        return True

    def set_resolution(self, host: str, addresses: list[str], cname: str = "") -> None:
        provider, takeover = classify_cname(cname)
        row = self.db.execute("SELECT scope FROM hosts WHERE host=?", (host,)).fetchone()
        scope = row["scope"] if row else IN
        if provider and scope == IN:
            scope = THIRD_PARTY
        self.db.execute(
            "UPDATE hosts SET resolved=1, addresses=?, cname=?, third_party_reason=?, "
            "takeover_candidate=?, scope=?, last_seen=? WHERE host=?",
            (json.dumps(addresses), cname, f"CNAME to {provider}" if provider else "",
             int(takeover), scope, now(), host))

    def mark_third_party(self, host: str, reason: str) -> None:
        self.db.execute("UPDATE hosts SET scope=?, third_party_reason=?, last_seen=? WHERE host=?",
                        (THIRD_PARTY, reason, now(), host))

    def hosts(self, scope: str | None = None, resolved: bool | None = None) -> list[sqlite3.Row]:
        query, params = "SELECT * FROM hosts", []
        clauses = []
        if scope is not None:
            clauses.append("scope=?")
            params.append(scope)
        if resolved is not None:
            clauses.append("resolved=?")
            params.append(int(resolved))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        return list(self.db.execute(query + " ORDER BY host", params))

    def host_counts(self) -> dict[str, int]:
        rows = self.db.execute("SELECT scope, COUNT(*) AS n FROM hosts GROUP BY scope")
        return {row["scope"]: row["n"] for row in rows}

    def unprobed_hosts(self) -> list[str]:
        return [r["host"] for r in self.db.execute(
            "SELECT host FROM hosts WHERE scope=? AND resolved=1 AND probed=0 ORDER BY host", (IN,))]

    def mark_probed(self, hosts, probed: bool = True) -> None:
        self.db.executemany("UPDATE hosts SET probed=? WHERE host=?",
                            [(int(probed), h.strip().lower()) for h in hosts])

    def set_priority(self, pattern: str, priority: int) -> int:
        """Set the priority of every service whose host matches `pattern`
        (a host, or *.root for the root and all its subdomains)."""
        pattern = pattern.strip().lower()
        if pattern.startswith("*."):
            root = pattern[2:]
            cur = self.db.execute("UPDATE services SET priority=? WHERE host=? OR host LIKE ?",
                                  (priority, root, "%." + root))
        else:
            cur = self.db.execute("UPDATE services SET priority=? WHERE host=?", (priority, pattern))
        return cur.rowcount

    def takeover_candidates(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM hosts WHERE takeover_candidate=1 ORDER BY host"))

    # services -------------------------------------------------------------
    def upsert_service(self, host: str, port: int, scheme: str, **fields) -> None:
        url = fields.get("url") or f"{scheme}://{host}" + ("" if port in (80, 443) else f":{port}")
        columns = {"host": host, "port": port, "scheme": scheme, "url": url,
                   "first_seen": now(), "last_seen": now(), **fields}
        existing = self.db.execute(
            "SELECT id FROM services WHERE host=? AND port=? AND scheme=?", (host, port, scheme)).fetchone()
        if existing:
            sets = ", ".join(f"{k}=?" for k in fields) + ", last_seen=?"
            self.db.execute(f"UPDATE services SET {sets} WHERE id=?",
                            (*fields.values(), now(), existing["id"]))
        else:
            cols = ", ".join(columns)
            marks = ", ".join("?" for _ in columns)
            self.db.execute(f"INSERT INTO services({cols}) VALUES({marks})", tuple(columns.values()))

    def services(self, min_priority: int = 0) -> list[sqlite3.Row]:
        return list(self.db.execute(
            "SELECT * FROM services WHERE priority>=? ORDER BY priority DESC, host", (min_priority,)))

    def service_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) AS n FROM services").fetchone()["n"]

    def set_baseline(self, service_id: int, baseline: dict) -> None:
        self.db.execute("UPDATE services SET baseline=?, last_seen=? WHERE id=?",
                        (json.dumps(baseline), now(), service_id))
