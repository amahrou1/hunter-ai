"""Ownership scoring for scope discovery.

The discovery phase (01c-expand) gathers passive evidence about a candidate
apex domain - its nameservers, TLS-certificate names and issuer org, RDAP
registrant, MX/SPF, resolved IPs/ASN, whether it is parked - and this module
turns that evidence into a decision:

    auto    -> add to scope now (strong proof of same ownership)
    review  -> let the AI agent decide, with a written reason (some proof)
    reject  -> never add (parked, for-sale, different owner, or no proof)

This is deliberately pure and offline: it takes evidence in, returns a verdict
out, and makes no network calls, so the whole ownership decision is testable
and lives in code - the model can gather and propose, but it cannot widen scope
past what the evidence supports. Same split as the scope proxy and guard.

Evidence is a dict built by the phase; every field is optional:
    {
      "nameservers": ["ns1.example.net", ...],      # candidate's NS
      "cert_sans": ["autoscout24.nl", "www...", ...],# names on candidate's cert
      "cert_org": "AutoScout24 GmbH",                # cert subject O=
      "rdap_org": "AutoScout24 GmbH",                # RDAP/WHOIS registrant org
      "rdap_created": "2001-03-...",                 # registration date (ISO)
      "mx_hosts": ["aspmx.l.google.com", ...],
      "spf_includes": ["_spf.google.com", ...],
      "soa_rname": "hostmaster.autoscout24.com",
      "ips": ["1.2.3.4"], "asn": "AS1234", "asn_name": "AUTOSCOUT24",
      "resolves": true,
      "parked": false,                               # heuristic set by phase
      "linked_from_scope": true,                     # found via hreflang on an in-scope host
      "shared_hosting_ns": false,                    # NS belongs to a mass host/CDN
      "shared_hosting_ip": false,                    # IP belongs to a CDN/cloud
    }

Owner context is built from the seed (known-owned) domains and the policy:
    {
      "brand": "autoscout24",
      "legal_names": ["autoscout24 gmbh", "autoscout24 ag"],  # lowercased
      "seed_nameservers": {"ns1.autoscout24.com", ...},       # NS of seeds
      "seed_ns_roots": {"autoscout24.com", ...},              # registrable root of seed NS
      "seed_domains": {"autoscout24.de", ...},
      "seed_soa_rnames": {"hostmaster.autoscout24.com", ...},
      "seed_asns": {"AS1234"},
      "is_ownership": false,   # True for 'owned by X' scopes (needs owner-name proof)
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Nameserver / registrar roots that host millions of unrelated domains: a match
# here is NOT evidence of shared ownership. Kept lowercase, matched as a suffix.
SHARED_NS_ROOTS = frozenset({
    "cloudflare.com", "awsdns-01.net", "awsdns.com", "azure-dns.com", "azure-dns.net",
    "azure-dns.org", "azure-dns.info", "googledomains.com", "google.com", "domaincontrol.com",
    "registrar-servers.com", "dnsimple.com", "name.com", "nsone.net", "ultradns.com",
    "ultradns.net", "ultradns.org", "akam.net", "akamai.net", "dynect.net", "nsone.info",
    "wordpress.com", "wixdns.net", "shopify.com", "squarespace.com", "gandi.net",
    "ovh.net", "ovh.com", "hover.com", "ns.cloudflare.com", "digitalocean.com",
    "linode.com", "vultr.com", "hetzner.com", "hetzner.de", "1and1.com", "ionos.com",
})

# Parked / for-sale / domain-sale nameservers and markers: a strong REJECT.
PARKED_NS_MARKERS = frozenset({
    "sedoparking.com", "sedo.com", "dan.com", "undeveloped.com", "afternic.com",
    "parkingcrew.net", "parkingcrew.com", "bodis.com", "above.com", "voodoo.com",
    "fabulous.com", "hugedomains.com", "namebright.com", "parklogic.com", "parkple.com",
    "cashparking.com", "domainsponsor.com", "smartname.com", "ztomy.com", "uniregistry.com",
    "dsredirection.com", "name-services.com", "parking.godaddy.com",
})

# Mass hosting / CDN ASNs where a shared IP means nothing about ownership.
SHARED_ASN_NAMES = ("cloudflare", "amazon", "aws", "google", "microsoft", "azure", "akamai",
                    "fastly", "cloudfront", "digitalocean", "linode", "ovh", "hetzner",
                    "vultr", "godaddy", "wix", "shopify", "squarespace", "automattic",
                    "incapsula", "imperva", "sucuri", "stackpath", "edgecast", "limelight")

STRONG, MEDIUM, REJECT = "strong", "medium", "reject"
AUTO, REVIEW, DECLINE = "auto", "review", "reject"

# Common TLDs a global brand actually operates on: every ccTLD plus the major
# gTLDs and the frequent two-level suffixes. A brand-on-any-TLD sweep tries
# `brand.<suffix>` for each of these (DNS only). This is NOT the full public
# suffix list (~9000) - the long tail is left to the AI's cert/reverse-WHOIS
# discovery, which finds the unusual ones. Keeping it to the realistic set
# keeps the sweep fast and the false-positive surface small.
COMMON_SUFFIXES = (
    # major gTLDs
    "com", "net", "org", "info", "biz", "io", "co", "app", "dev", "cloud", "ai",
    "shop", "store", "online", "site", "tech", "group", "global", "world",
    # ccTLDs (apex)
    "de", "at", "ch", "fr", "it", "es", "pt", "nl", "be", "lu", "uk", "ie", "dk",
    "se", "no", "fi", "is", "pl", "cz", "sk", "hu", "ro", "bg", "hr", "si", "rs",
    "gr", "tr", "ua", "ru", "by", "lt", "lv", "ee", "us", "ca", "mx", "br", "ar",
    "cl", "co", "pe", "au", "nz", "jp", "cn", "kr", "in", "sg", "hk", "tw", "my",
    "th", "id", "ph", "vn", "ae", "sa", "il", "za", "eg", "ma", "ng", "ke",
    # frequent two-level suffixes
    "co.uk", "org.uk", "com.tr", "com.br", "com.au", "com.mx", "com.ar", "co.jp",
    "co.kr", "co.in", "com.cn", "com.sg", "com.hk", "com.tw", "com.my", "co.za",
    "co.nz", "com.ua", "com.pl", "co.il", "com.sa", "com.eg",
)


def candidate_domains(brand: str, suffixes=COMMON_SUFFIXES) -> list[str]:
    """Every `brand.<suffix>` to try for a brand-on-any-TLD pattern."""
    brand = (brand or "").strip().lower()
    if not brand or "." in brand or "*" in brand:
        return []
    return [f"{brand}.{s}" for s in suffixes]


# --------------------------------------------------------------------------
# Passive evidence gathering (network; isolated so the scorer stays pure)
# --------------------------------------------------------------------------

def resolve_evidence(domain: str, *, timeout: float = 4.0) -> dict:
    """Resolve a domain and collect the cheap, passive evidence the scorer uses:
    whether it resolves, its A records, and its authoritative nameservers. DNS
    only - no HTTP, nothing that touches the domain's web server. Returns an
    evidence dict (possibly just {'resolves': False})."""
    import socket
    ev: dict = {}
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
        ev["resolves"] = bool(ips)
        ev["ips"] = ips
    except (socket.gaierror, OSError, UnicodeError):
        ev["resolves"] = False
        return ev
    ev["nameservers"] = _nameservers(domain, timeout)
    return ev


def _nameservers(domain: str, timeout: float) -> list[str]:
    """Authoritative NS for a domain's registrable root, via dnspython if
    present, else an empty list (the sweep still works, just with less
    evidence)."""
    try:
        import dns.resolver  # type: ignore
    except ImportError:
        return []
    root = _registrable_root(domain)
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = resolver.timeout = timeout
        answers = resolver.resolve(root, "NS")
        return sorted({str(r.target).rstrip(".").lower() for r in answers})
    except Exception:  # noqa: BLE001 - any DNS failure just means no NS evidence
        return []


def crtsh_names(domain: str, *, timeout: float = 25.0, cap: int = 300) -> list[str]:
    """Every name that shares a TLS certificate with `domain`, from the public
    certificate-transparency log (crt.sh). Passive: it queries the log, never
    the domain. A certificate that also names a known-owned domain is strong
    proof of the same owner. Returns [] on any error (crt.sh is often slow)."""
    import json as _json
    import time
    import urllib.parse
    import urllib.request
    url = "https://crt.sh/?q=" + urllib.parse.quote(domain) + "&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hunter-ai scope discovery"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 - fixed public host
            rows = _json.loads(resp.read().decode("utf-8", "replace") or "[]")
    except Exception:  # noqa: BLE001
        return []
    finally:
        time.sleep(1.0)   # be polite to crt.sh between sweep queries
    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if name and " " not in name:
                names.add(name)
        if len(names) >= cap:
            break
    return sorted(names)[:cap]


def seed_owner_context(brand: str, legal_names, seed_domains, ownership: bool = False) -> dict:
    """Build the owner context from the seed (known-owned) domains: learn their
    nameserver roots so a candidate sharing them scores as same-owner."""
    seeds = {d.strip().lower().rstrip(".") for d in seed_domains if d}
    ns_roots = set()
    for d in sorted(seeds)[:8]:          # a few seeds are enough to learn the NS operator
        for ns in _nameservers(d, 4.0):
            if not _ns_is_shared(ns):
                ns_roots.add(_registrable_root(ns))
    return {
        "brand": (brand or "").strip().lower(),
        "brand_aliases": [],
        "legal_names": [n for n in (legal_names or []) if n],
        "seed_domains": seeds,
        "seed_ns_roots": ns_roots,
        "seed_soa_rnames": set(),
        "seed_spf_includes": set(),
        "seed_asns": set(),
        "is_ownership": bool(ownership),
    }


@dataclass
class Signal:
    name: str
    strength: str   # STRONG | MEDIUM | REJECT
    detail: str

    def to_dict(self) -> dict:
        return {"name": self.name, "strength": self.strength, "detail": self.detail}


@dataclass
class Verdict:
    tier: str                       # AUTO | REVIEW | DECLINE
    signals: list[Signal] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"tier": self.tier, "reason": self.reason,
                "signals": [s.to_dict() for s in self.signals]}


def _registrable_root(host: str) -> str:
    """Cheap eTLD+1 good enough for grouping NS by owner. Handles the common
    two-level public suffixes (co.uk, com.tr, com.br, com.au, ...)."""
    host = (host or "").strip().lower().rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
    if labels[-2] in two_level and len(labels[-1]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _org_matches(org: str, legal_names: set[str], brand: str) -> bool:
    """True if a cert/RDAP org string clearly names the owner. Matches on the
    brand token or on a legal name (normalised, ignoring GmbH/AG/Inc/Ltd)."""
    if not org:
        return False
    o = _norm(org)
    if not o:
        return False
    for name in legal_names:
        n = _norm(name)
        # strip common company suffixes from both before compare
        for suffix in ("gmbh", "ag", "inc", "ltd", "llc", "limited", "sa", "se", "bv", "co", "corp", "group", "holding"):
            n = n[:-len(suffix)] if n.endswith(suffix) and len(n) > len(suffix) + 2 else n
        if n and (n in o or o in n):
            return True
    b = _norm(brand)
    return bool(b) and len(b) >= 4 and b in o


def _ns_is_shared(ns: str) -> bool:
    root = _registrable_root(ns)
    return any(root == r or root.endswith("." + r) or ns.endswith("." + r) for r in SHARED_NS_ROOTS)


def _ns_is_parked(nameservers) -> bool:
    for ns in nameservers or ():
        ns = (ns or "").lower()
        if any(m in ns for m in PARKED_NS_MARKERS):
            return True
    return False


def gather_signals(candidate: str, ev: dict, owner: dict) -> list[Signal]:
    """Turn raw evidence into named, strength-tagged signals."""
    sig: list[Signal] = []
    legal = {n.lower() for n in owner.get("legal_names") or []}
    brand = owner.get("brand") or ""
    ns = [n.lower() for n in ev.get("nameservers") or []]

    # --- REJECT signals (ownership-breaking) --------------------------------
    if _ns_is_parked(ns):
        sig.append(Signal("parked_ns", REJECT, "nameservers belong to a domain-parking/for-sale service"))
    if ev.get("parked"):
        sig.append(Signal("parked_page", REJECT, "the domain serves a parking/for-sale page"))
    rdap_org = ev.get("rdap_org") or ""
    if rdap_org and legal and not _org_matches(rdap_org, legal, brand):
        # A registrant org that clearly names a DIFFERENT company is a reject,
        # but only when we have legal names to compare against.
        sig.append(Signal("registrant_mismatch", REJECT, f"registrant org '{rdap_org[:60]}' does not match the owner"))

    # --- STRONG signals -----------------------------------------------------
    # Shared NS with a seed domain (and not a mass host) => same DNS operator.
    seed_ns_roots = {r.lower() for r in owner.get("seed_ns_roots") or []}
    cand_ns_roots = {_registrable_root(n) for n in ns if not _ns_is_shared(n)}
    shared_ns = cand_ns_roots & seed_ns_roots
    if shared_ns:
        sig.append(Signal("same_nameservers", STRONG,
                           f"same authoritative DNS as a known-owned domain ({sorted(shared_ns)[0]})"))

    # Cert names span the candidate AND a seed/brand domain.
    sans = {s.lower().lstrip("*.") for s in ev.get("cert_sans") or []}
    seed_domains = {d.lower() for d in owner.get("seed_domains") or []}
    san_roots = {_registrable_root(s) for s in sans}
    if san_roots & seed_domains or any(_registrable_root(s) in seed_domains for s in sans):
        sig.append(Signal("shared_certificate", STRONG,
                           "a TLS certificate covers both this domain and a known-owned domain"))
    # Cert subject org names the owner.
    if _org_matches(ev.get("cert_org") or "", legal, brand):
        sig.append(Signal("cert_org", STRONG, f"TLS certificate issued to '{(ev.get('cert_org') or '')[:60]}'"))
    # RDAP registrant org names the owner.
    if _org_matches(rdap_org, legal, brand):
        sig.append(Signal("registrant_org", STRONG, f"domain registrant is '{rdap_org[:60]}'"))
    # Linked as a country site from a page already in scope.
    if ev.get("linked_from_scope"):
        sig.append(Signal("linked_from_scope", STRONG,
                           "linked as an official country/locale site from an in-scope page"))

    # --- MEDIUM signals -----------------------------------------------------
    seed_soa = {r.lower() for r in owner.get("seed_soa_rnames") or []}
    if ev.get("soa_rname") and ev["soa_rname"].lower() in seed_soa:
        sig.append(Signal("same_soa_contact", MEDIUM, "same DNS zone contact (SOA) as a known-owned domain"))
    seed_spf = {i.lower() for i in owner.get("seed_spf_includes") or []}
    cand_spf = {i.lower() for i in ev.get("spf_includes") or []}
    # A shared SPF include only counts if it is NOT a generic provider include.
    generic_spf = {"_spf.google.com", "spf.protection.outlook.com", "amazonses.com",
                   "sendgrid.net", "_spf.salesforce.com", "mailgun.org", "servers.mcsv.net"}
    private_shared_spf = (cand_spf & seed_spf) - generic_spf
    if private_shared_spf:
        sig.append(Signal("shared_spf", MEDIUM, f"shares a non-generic SPF include ({sorted(private_shared_spf)[0]})"))
    # Same ASN as a seed, only when not a shared cloud/CDN.
    asn_name = (ev.get("asn_name") or "").lower()
    cand_asn = ev.get("asn")
    if cand_asn and cand_asn in (owner.get("seed_asns") or set()) \
            and not any(w in asn_name for w in SHARED_ASN_NAMES) and not ev.get("shared_hosting_ip"):
        sig.append(Signal("same_asn", MEDIUM, f"hosted in the same owner network ({cand_asn} {asn_name})"))
    # The candidate's own ASN is named after the brand/owner.
    if asn_name and (_org_matches(asn_name, legal, brand)):
        sig.append(Signal("asn_named_owner", MEDIUM, f"hosting network is named after the owner ({asn_name})"))

    return sig


def _brand_token_matches(candidate: str, owner: dict) -> bool:
    """True if the candidate's registrable name IS the brand (or a stated
    alias): autoscout24.hu for brand 'autoscout24', as24.tech for alias 'as24'.
    A different marketplace brand (autotrader.ca) does NOT match, even if the
    same company owns it."""
    root = _registrable_root(candidate)
    label = root.split(".")[0]                 # the registrable name without the TLD
    brand = _norm(owner.get("brand") or "")
    aliases = {_norm(a) for a in owner.get("brand_aliases") or []}
    cand = _norm(label)
    if not cand:
        return False
    names = {b for b in ({brand} | aliases) if b}
    # The candidate must BE the brand or an extension of it (autoscout24 ->
    # autoscout24, autoscout24-media, autoscout24cars). A shorter stem that is
    # merely a prefix of the brand (auto, autoscout) does NOT match - that would
    # wrongly pull in unrelated brands. An exact alias always matches.
    return any(cand == n or cand.startswith(n) for n in names)


def decide(candidate: str, ev: dict, owner: dict, *, require_resolves: bool = True) -> Verdict:
    """Score a candidate apex domain. Returns a Verdict (auto / review / reject)."""
    signals = gather_signals(candidate, ev, owner)
    rejects = [s for s in signals if s.strength == REJECT]
    strong = [s for s in signals if s.strength == STRONG]
    medium = [s for s in signals if s.strength == MEDIUM]

    # SCOPE-TYPE GATE. A brand-TLD pattern (*.autoscout24.*) authorises only the
    # SAME brand on other TLDs - never a different marketplace brand, however
    # strong the common-ownership evidence. Only an explicit "all assets owned
    # by X" scope (is_ownership) admits sibling brands. This is the guard
    # against expanding *.autoscout24.* into autotrader.ca / autotrack.nl.
    if owner.get("brand") and not owner.get("is_ownership") and not _brand_token_matches(candidate, owner):
        return Verdict(DECLINE, signals,
                       f"different brand from '{owner.get('brand')}'; a brand-TLD scope covers only the same "
                       f"brand on other TLDs, not other brands the same company may own")

    if rejects:
        return Verdict(DECLINE, signals, rejects[0].detail)

    # A domain that does not resolve has nothing to test; keep it out of auto
    # (it can still be reviewed/added once it resolves on a later pass).
    if require_resolves and ev.get("resolves") is False:
        if strong or medium:
            return Verdict(REVIEW, signals, "ownership evidence present but the domain does not resolve yet")
        return Verdict(DECLINE, signals, "does not resolve and no ownership evidence")

    # Auto-add: 2 strong, or 1 strong + 2 medium.
    if len(strong) >= 2 or (len(strong) >= 1 and len(medium) >= 2):
        # On an ownership scope, a domain that is NOT the same brand (a sibling
        # brand owned by the parent) never auto-adds however strong the proof -
        # "owned by the group" is a judgement call, so it goes to review.
        if owner.get("is_ownership") and not _brand_token_matches(candidate, owner):
            return Verdict(REVIEW, signals, "owned by the group but a different brand - needs your judgement: "
                           + "; ".join(s.detail for s in strong[:2]))
        return Verdict(AUTO, signals, "; ".join(s.detail for s in strong[:2] or medium[:2]))

    # Some proof, but not enough to auto-add: the agent decides.
    if strong or medium:
        return Verdict(REVIEW, signals, "; ".join(s.detail for s in (strong + medium)[:3]))

    return Verdict(DECLINE, signals, "no evidence this domain belongs to the owner")


# --------------------------------------------------------------------------
# Promotion: candidates the store marks added/approved -> scope.expanded
# --------------------------------------------------------------------------

# Tiers whose candidates belong in the live scope (tested).
ADMITTED_TIERS = ("added", "approved")


def sync_scope_expanded(store, scope, scope_file, save_fn) -> int:
    """Make scope.expanded exactly match the admitted candidates in the store,
    skipping any the policy already lists or excludes. Writes scope.json only if
    it changed (the running proxy re-reads it live). Returns how many are now in
    the expanded list. Idempotent - safe to call every pass."""
    from . import scope as sc

    wanted = []
    seen = set()
    existing_hosts = {a.host for a in scope.in_scope if a.host}
    for row in store.candidates():
        if row["tier"] not in ADMITTED_TIERS:
            continue
        domain = row["domain"]
        if not domain or domain in seen:
            continue
        # Never shadow something the policy already handles, and never add a
        # domain the policy or operator put out of scope. An out-of-scope entry
        # on the same registrable domain (its apex OR its wildcard, e.g.
        # `*.autoscout24.nl` or `autoscout24.nl`) means discovery must not add
        # it back - the exclusion wins by root, not just by exact host match.
        if domain in existing_hosts:
            continue
        excluded = any(
            o.host == domain or (o.kind == "wildcard" and o.host == domain)
            or sc.asset_matches(o, domain) or sc.asset_matches(o, "_." + domain)
            for o in (*scope.operator_out, *scope.out_of_scope) if o.kind != "url")
        if excluded:
            continue
        raw = f"*.{domain}" if row["subdomains"] else domain
        try:
            asset = sc.parse_asset(raw)
        except sc.AssetError:
            continue
        wanted.append(asset)
        seen.add(domain)

    new_raws = sorted(a.raw for a in wanted)
    old_raws = sorted(a.raw for a in scope.expanded)
    if new_raws != old_raws:
        scope.expanded = wanted
        save_fn(scope, scope_file)
    return len(wanted)


# --------------------------------------------------------------------------
# One rule for verdict -> stored tier, shared by the code sweep and the agent
# --------------------------------------------------------------------------

def auto_mode_for(cfg: dict | None, is_ownership: bool) -> str:
    """'strong' (code auto-adds strong proof) or 'none' (suggest only).
    Ownership scopes default to suggest-only - a wrong 'owned by' guess is the
    costly out-of-scope mistake - unless the operator set auto_add explicitly."""
    mode = str((cfg or {}).get("auto_add") or "auto").lower()
    if mode == "none":
        return "none"
    if mode == "strong":
        return "strong"
    return "none" if is_ownership else "strong"   # "auto" (default) or unknown


def stored_tier(verdict_tier: str, auto_mode: str) -> str:
    """Map a scoring verdict to the tier stored on the candidate. Only 'added'
    (and the agent's 'approved') enter scope."""
    if verdict_tier == AUTO:
        return "review" if auto_mode == "none" else "added"
    return verdict_tier


OWNER_META_KEY = "expand_owner_context"


def save_owner_context(db, owner: dict) -> None:
    """Persist the owner context the phase learned (incl. seed nameserver
    roots) so `hk candidate add` scores agent proposals the same way."""
    import json as _json
    data = {k: sorted(v) if isinstance(v, set) else v for k, v in owner.items()}
    db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (OWNER_META_KEY, _json.dumps(data)))


def load_owner_context(db) -> dict | None:
    import json as _json
    try:
        row = db.execute("SELECT value FROM meta WHERE key=?", (OWNER_META_KEY,)).fetchone()
    except Exception:  # noqa: BLE001
        return None
    if not row:
        return None
    data = _json.loads(row[0])
    for key in ("seed_domains", "seed_ns_roots", "seed_soa_rnames", "seed_spf_includes", "seed_asns"):
        data[key] = set(data.get(key) or [])
    return data
