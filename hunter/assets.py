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
from urllib.parse import parse_qsl, urlsplit

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
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    template TEXT NOT NULL,          -- scheme://host:port/path?sorted&param&names
    params TEXT NOT NULL DEFAULT '[]',
    body TEXT,
    source TEXT NOT NULL,            -- crawl, js, discover, robots, ...
    status INTEGER,
    content_type TEXT,
    length INTEGER,
    is_js INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    UNIQUE (method, template)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase TEXT NOT NULL,
    title TEXT NOT NULL,
    kind TEXT,                       -- idor, xss, ssrf, info-leak, takeover, ...
    severity TEXT,                   -- info | low | medium | high | critical
    status TEXT NOT NULL DEFAULT 'candidate',  -- candidate|validated|confirmed|disproved|reported
    host TEXT,
    url TEXT,
    summary TEXT,
    steps TEXT,
    impact TEXT,
    cvss TEXT,
    evidence TEXT,
    created TEXT NOT NULL,
    updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,              -- exposed-git, env-file, api-docs, takeover, ...
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'unverified',   -- unverified | signature-match | dismissed
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    UNIQUE (kind, url)
);
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


# How many services serving the exact same page are crawled / fuzzed.
MAX_SAME_PAGE = 2


def endpoint_template(url: str) -> tuple[str, str, list[str]]:
    """(template, host, parameter names) for deduplication: same scheme,
    host, port and path, and the same set of query parameter names."""
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return "", "", []
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "", "", []
    host = parts.hostname.lower()
    port = port or (443 if parts.scheme == "https" else 80)
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    path = parts.path or "/"
    template = f"{parts.scheme}://{host}:{port}{path}" + ("?" + "&".join(names) if names else "")
    return template, host, names


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
        service_cols = {row[1] for row in self.db.execute("PRAGMA table_info(services)")}
        for column in ("crawled", "discovered"):
            if column not in service_cols:
                self.db.execute(f"ALTER TABLE services ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(hosts)")}
        if "probed" not in columns:
            self.db.execute("ALTER TABLE hosts ADD COLUMN probed INTEGER NOT NULL DEFAULT 0")
            # Databases from before probe tracking: a host with a live service
            # was certainly probed already.
            self.db.execute("UPDATE hosts SET probed=1 WHERE host IN (SELECT host FROM services)")
            # If probe already finished on the old layout, every resolved host
            # it saw was probed: do not probe them all again.
            try:
                row = self.db.execute(
                    "SELECT status FROM phases WHERE phase_id='03-probe'").fetchone()
            except sqlite3.OperationalError:
                row = None
            if row is not None and row[0] in ("DONE", "PARTIAL"):
                self.db.execute("UPDATE hosts SET probed=1 WHERE resolved=1")

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

    def set_priority_hosts(self, hosts: list[str], priority: int) -> int:
        """Set the priority of many hosts at once (exact match). For bulk
        operations like infrastructure-clone parking."""
        total = 0
        batch = 500
        for i in range(0, len(hosts), batch):
            chunk = [h.strip().lower() for h in hosts[i:i + batch] if h.strip()]
            if not chunk:
                continue
            marks = ",".join("?" * len(chunk))
            cur = self.db.execute(
                f"UPDATE services SET priority=? WHERE host IN ({marks})", (priority, *chunk))
            total += cur.rowcount
        return total

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

    def mark_service(self, service_id: int, column: str, value: bool = True) -> None:
        assert column in ("crawled", "discovered")
        self.db.execute(f"UPDATE services SET {column}=? WHERE id=?", (int(value), service_id))

    def work_services(self, scope, column: str) -> list[sqlite3.Row]:
        """Services worth crawling or fuzzing, highest priority first, not
        done yet: in scope now, not a dead upstream (5xx), not a gate that
        answers every path the same, and one scheme per host:port pair
        (HTTPS preferred) so the same site is not done twice."""
        assert column in ("crawled", "discovered")
        rows = list(self.db.execute(
            f"SELECT * FROM services WHERE {column}=0 AND priority>0 ORDER BY priority DESC, host, port"))
        chosen, seen = [], set()
        same_page: dict[tuple, int] = {}
        all_rows = list(self.db.execute("SELECT host, port, scheme FROM services"))
        https_hosts = {r["host"] for r in all_rows if r["scheme"] == "https"}
        for row in rows:
            if not scope.host_in_scope(row["host"]):
                continue
            status = row["status"] or 0
            if status >= 500:
                continue
            kind = json.loads(row["baseline"]).get("kind") if row["baseline"] else None
            if kind == "uniform_gate":
                continue
            if row["scheme"] == "http" and row["port"] == 80 and row["host"] in https_hosts:
                continue
            key = (row["host"], row["port"])
            if key in seen:
                continue
            # The same page on many hosts or ports (a load balancer's default
            # page, a parked domain): crawling two copies is enough.
            if row["body_hash"]:
                page = (row["status"], row["body_hash"])
                same_page[page] = same_page.get(page, 0) + 1
                if same_page[page] > MAX_SAME_PAGE:
                    continue
            seen.add(key)
            chosen.append(row)
        return chosen

    # endpoints ------------------------------------------------------------
    def add_endpoint(self, method: str, url: str, source: str, *, body: str | None = None,
                     status: int | None = None, content_type: str = "", length: int | None = None) -> bool:
        """Store a request we have seen. Deduplicated by method + URL shape
        (same path, same parameter names). Returns True if it was new."""
        template, host, params = endpoint_template(url)
        if not template:
            return False
        is_js = int(urlsplit(url).path.lower().endswith((".js", ".mjs")))
        cur = self.db.execute(
            "INSERT OR IGNORE INTO endpoints(host, method, url, template, params, body, source, status, "
            "content_type, length, is_js, first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (host, method.upper(), url, template, json.dumps(params), body, source, status,
             (content_type or "")[:120], length, is_js, now()))
        return cur.rowcount > 0

    def endpoints(self, host: str | None = None) -> list[sqlite3.Row]:
        if host:
            return list(self.db.execute("SELECT * FROM endpoints WHERE host=? ORDER BY url", (host,)))
        return list(self.db.execute("SELECT * FROM endpoints ORDER BY host, url"))

    def endpoint_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) AS n FROM endpoints").fetchone()["n"]

    # leads ----------------------------------------------------------------
    def add_lead(self, kind: str, url: str, source: str, evidence: str = "",
                 status: str = "unverified") -> bool:
        host = (urlsplit(url).hostname or url).lower()
        cur = self.db.execute(
            "INSERT OR IGNORE INTO leads(kind, url, host, evidence, status, source, first_seen) "
            "VALUES(?,?,?,?,?,?,?)", (kind, url, host, evidence[:2000], status, source, now()))
        return cur.rowcount > 0

    def leads(self, status: str | None = None) -> list[sqlite3.Row]:
        if status:
            return list(self.db.execute("SELECT * FROM leads WHERE status=? ORDER BY kind, url", (status,)))
        return list(self.db.execute("SELECT * FROM leads ORDER BY kind, url"))

    def host_note(self, host: str) -> dict:
        row = self.db.execute("SELECT notes FROM hosts WHERE host=?", (host,)).fetchone()
        try:
            return json.loads(row["notes"]) if row and row["notes"] else {}
        except ValueError:
            return {}

    def set_host_note(self, host: str, **values) -> None:
        note = self.host_note(host)
        note.update(values)
        self.db.execute("UPDATE hosts SET notes=? WHERE host=?", (json.dumps(note, sort_keys=True), host))

    def clear_takeover(self, host: str, reason: str) -> None:
        self.db.execute("UPDATE hosts SET takeover_candidate=0 WHERE host=?", (host,))
        self.set_host_note(host, takeover_check=reason)

    def write_leads(self, path: Path) -> None:
        lines = [f"[{r['status']}] {r['kind']:<15} {r['url']}  - {r['evidence'] or ''}" for r in self.leads()]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def set_baseline(self, service_id: int, baseline: dict) -> None:
        self.db.execute("UPDATE services SET baseline=?, last_seen=? WHERE id=?",
                        (json.dumps(baseline), now(), service_id))

    # findings -------------------------------------------------------------
    def add_finding(self, phase: str, title: str, **fields) -> int:
        cols = {"phase": phase, "title": title, "created": now(), "updated": now(),
                "status": fields.pop("status", "candidate")}
        allowed = ("kind", "severity", "host", "url", "summary", "steps", "impact", "cvss", "evidence")
        for key in allowed:
            if key in fields:
                cols[key] = fields[key]
        names = ", ".join(cols)
        marks = ", ".join("?" for _ in cols)
        cur = self.db.execute(f"INSERT INTO findings({names}) VALUES({marks})", tuple(cols.values()))
        return cur.lastrowid

    def set_finding(self, finding_id: int, **fields) -> None:
        allowed = ("title", "kind", "severity", "status", "host", "url", "summary", "steps",
                   "impact", "cvss", "evidence")
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        clause = ", ".join(f"{k}=?" for k in sets) + ", updated=?"
        self.db.execute(f"UPDATE findings SET {clause} WHERE id=?", (*sets.values(), now(), finding_id))

    def findings(self, status: str | None = None) -> list[sqlite3.Row]:
        if status:
            return list(self.db.execute("SELECT * FROM findings WHERE status=? ORDER BY id", (status,)))
        return list(self.db.execute("SELECT * FROM findings ORDER BY id"))

    def finding(self, finding_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
