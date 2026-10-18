"""The scope model: which hosts, URLs and IPs may be touched.

Rules (narrowest reading wins):
- Out of scope always beats in scope.
- `*.example.com` covers subdomains at any depth, but NOT example.com itself.
  The apex is in scope only if the policy lists it.
- `example.com` covers exactly that host.
- A URL entry with a path (https://app.example.com/api) covers that host,
  only under that path prefix; with an explicit port, only that port.
- IPs and CIDR ranges match IP literals only. A hostname being in scope
  does not put every service on its IP in scope.
- Mobile apps, source code and other non-network assets are kept for the
  report phases but never match network traffic.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

NETWORK_KINDS = ("wildcard", "domain", "url", "ip", "cidr")
OTHER_KINDS = ("mobile", "source_code", "executable", "other")
ALL_KINDS = NETWORK_KINDS + OTHER_KINDS

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,62}}$")

# Domains that appear in almost every policy but are never targets.
PLATFORM_DOMAINS = {
    "intigriti.com", "app.intigriti.com", "intigriti.me", "bugcrowd.com", "bugcrowdninja.com",
    "hackerone.com", "wearehackerone.com", "yeswehack.com", "yeswehack.ninja", "owasp.org",
    "first.org", "cvss.js.org", "nvd.nist.gov", "mitre.org", "cwe.mitre.org", "github.com",
    "google.com", "apple.com", "play.google.com", "apps.apple.com", "w3.org", "example.com",
    "securitytxt.org", "disclose.io", "bugcrowd.zendesk.com", "docs.bugcrowd.com",
    "docs.hackerone.com", "kb.intigriti.com",
}


class AssetError(ValueError):
    pass


@dataclass(frozen=True)
class Asset:
    kind: str
    raw: str
    host: str = ""            # for wildcard: the base (without "*.")
    path: str = ""            # url entries only, "" = whole host
    port: int | None = None   # url entries only
    scheme: str = ""          # url entries only
    wildcard_host: bool = False  # url entries like https://*.example.com/

    @property
    def is_network(self) -> bool:
        return self.kind in NETWORK_KINDS

    def label(self) -> str:
        return self.raw

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in ("", None, False)}


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:  # [ipv6]:port
        return host[1:host.index("]")]
    if host.count(":") == 1:  # host:port
        host = host.split(":", 1)[0]
    try:
        host = host.encode("idna").decode("ascii") if host and not _is_ip(host) else host
    except UnicodeError:
        pass
    return host


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _check_host(host: str, raw: str) -> str:
    if not _HOST_RE.match(host):
        raise AssetError(f"'{raw}' is not a valid host name")
    return host


def _clean(raw: str) -> str:
    value = raw.strip().strip("`'\"<>").strip()
    value = re.sub(r"\s+\(.*\)$", "", value)        # trailing "(production)" notes
    value = value.rstrip(",;")
    return value.strip()


def parse_asset(raw: str, kind: str | None = None) -> Asset:
    """Turn one scope entry into an Asset. Raises AssetError when the entry
    cannot be read safely; the caller then treats it as unclear (out)."""
    if kind is not None and kind not in ALL_KINDS:
        raise AssetError(f"unknown asset type '{kind}'")
    if kind in OTHER_KINDS:
        return Asset(kind=kind, raw=raw.strip())
    value = _clean(raw)
    if not value:
        raise AssetError("empty entry")
    lowered = value.lower()

    # URL with scheme
    if "://" in lowered:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https", "ws", "wss"):
            raise AssetError(f"'{raw}' uses an unsupported scheme")
        netloc_host = (parts.hostname or "").lower().rstrip(".")
        if not netloc_host:
            raise AssetError(f"'{raw}' has no host")
        wildcard = False
        if netloc_host.startswith("*."):
            wildcard, netloc_host = True, netloc_host[2:]
        if "*" in netloc_host:
            raise AssetError(f"'{raw}' has a wildcard that is not of the form *.domain")
        if not _is_ip(netloc_host):
            _check_host(netloc_host, raw)
        try:
            port = parts.port
        except ValueError as exc:
            raise AssetError(f"'{raw}' has an invalid port") from exc
        path = parts.path.rstrip("/")
        if "*" in path:
            path = path[: path.index("*")].rstrip("/")
        if not path and not port and not wildcard:
            # https://app.example.com is the same as the host entry.
            return Asset(kind="domain", raw=raw.strip(), host=netloc_host)
        if not path and not port and wildcard:
            return Asset(kind="wildcard", raw=raw.strip(), host=netloc_host)
        return Asset(kind="url", raw=raw.strip(), host=netloc_host, path=path, port=port,
                     scheme=parts.scheme.lower(), wildcard_host=wildcard)

    # CIDR / IP
    if "/" in lowered and re.match(r"^[0-9a-f:.]+/\d{1,3}$", lowered):
        try:
            net = ipaddress.ip_network(lowered, strict=False)
        except ValueError as exc:
            raise AssetError(f"'{raw}' is not a valid IP range") from exc
        return Asset(kind="cidr", raw=raw.strip(), host=str(net))
    if _is_ip(lowered):
        return Asset(kind="ip", raw=raw.strip(), host=str(ipaddress.ip_address(lowered)))

    # host/path without scheme
    if "/" in lowered:
        host_part, _, rest = lowered.partition("/")
        return parse_asset(f"https://{host_part}/{rest}", None) if host_part else _fail(raw)

    # wildcard forms
    if lowered.startswith("*."):
        base = lowered[2:]
        if "*" in base:
            raise AssetError(f"'{raw}' has more than one wildcard")
        return Asset(kind="wildcard", raw=raw.strip(), host=_check_host(normalize_host(base), raw))
    if lowered.startswith("."):
        return Asset(kind="wildcard", raw=raw.strip(), host=_check_host(normalize_host(lowered[1:]), raw))
    if "*" in lowered:
        raise AssetError(f"'{raw}' uses a wildcard form that is not clear (only *.domain is accepted)")

    host = normalize_host(lowered)
    return Asset(kind="domain", raw=raw.strip(), host=_check_host(host, raw))


def _fail(raw: str):
    raise AssetError(f"'{raw}' cannot be read")


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def _host_matches(asset: Asset, host: str) -> bool:
    if asset.kind == "wildcard" or (asset.kind == "url" and asset.wildcard_host):
        return host.endswith("." + asset.host)
    if asset.kind in ("domain", "url"):
        return host == asset.host
    if asset.kind in ("ip", "cidr"):
        if not _is_ip(host):
            return False
        address = ipaddress.ip_address(host)
        if asset.kind == "ip":
            return address == ipaddress.ip_address(asset.host)
        return address in ipaddress.ip_network(asset.host)
    return False


def _path_matches(prefix: str, path: str) -> bool:
    if not prefix:
        return True
    path = path or "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    return path == prefix or path.startswith(prefix + "/")


def asset_matches(asset: Asset, host: str, path: str = "/", port: int | None = None) -> bool:
    if not asset.is_network or not _host_matches(asset, host):
        return False
    if asset.kind == "url":
        if asset.port and port and asset.port != port:
            return False
        if asset.port and port is None:
            return False
        return _path_matches(asset.path, path)
    return True


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched: str = ""


@dataclass
class Scope:
    in_scope: list[Asset] = field(default_factory=list)
    out_of_scope: list[Asset] = field(default_factory=list)
    rules: dict = field(default_factory=dict)
    program: dict = field(default_factory=dict)
    excluded_vulnerabilities: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    ambiguities: list[dict] = field(default_factory=list)
    unclassified_hosts: list[str] = field(default_factory=list)
    other_rules: list[str] = field(default_factory=list)

    def decide(self, host: str, path: str = "/", port: int | None = None) -> Decision:
        host = normalize_host(host)
        if not host:
            return Decision(False, "no host")
        for asset in self.out_of_scope:
            if asset_matches(asset, host, path, port):
                return Decision(False, "out of scope", asset.raw)
        for asset in self.in_scope:
            if asset_matches(asset, host, path, port):
                return Decision(True, "in scope", asset.raw)
        return Decision(False, "not in scope")

    def decide_url(self, url: str) -> Decision:
        if "://" not in url:
            url = "https://" + url
        parts = urlsplit(url)
        try:
            port = parts.port
        except ValueError:
            return Decision(False, "invalid port")
        return self.decide(parts.hostname or "", parts.path or "/", port)

    def host_in_scope(self, host: str) -> bool:
        """True if any path of this host may be tested. Used to filter
        recon results (hosts, not full URLs)."""
        host = normalize_host(host)
        for asset in self.out_of_scope:
            if asset.kind != "url" and asset_matches(asset, host):
                return False
        return any(_host_matches(a, host) for a in self.in_scope if a.is_network)

    def network_assets(self) -> list[Asset]:
        return [a for a in self.in_scope if a.is_network]

    def wildcard_roots(self) -> list[str]:
        return sorted({a.host for a in self.in_scope if a.kind == "wildcard"})

    @property
    def rate_limit_rps(self) -> float:
        return float(self.rules.get("effective_rps") or 1.0)

    @property
    def required_headers(self) -> dict[str, str]:
        return dict(self.rules.get("required_headers") or {})

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "program": self.program,
            "in_scope": [a.to_dict() for a in self.in_scope],
            "out_of_scope": [a.to_dict() for a in self.out_of_scope],
            "rules": self.rules,
            "excluded_vulnerabilities": self.excluded_vulnerabilities,
            "forbidden_actions": self.forbidden_actions,
            "ambiguities": self.ambiguities,
            "unclassified_hosts": self.unclassified_hosts,
            "other_rules": self.other_rules,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        def assets(items):
            out = []
            for item in items or []:
                out.append(Asset(kind=item["kind"], raw=item["raw"], host=item.get("host", ""),
                                 path=item.get("path", ""), port=item.get("port"),
                                 scheme=item.get("scheme", ""), wildcard_host=item.get("wildcard_host", False)))
            return out
        return cls(
            in_scope=assets(data.get("in_scope")),
            out_of_scope=assets(data.get("out_of_scope")),
            rules=data.get("rules") or {},
            program=data.get("program") or {},
            excluded_vulnerabilities=list(data.get("excluded_vulnerabilities") or []),
            forbidden_actions=list(data.get("forbidden_actions") or []),
            ambiguities=list(data.get("ambiguities") or []),
            unclassified_hosts=list(data.get("unclassified_hosts") or []),
            other_rules=list(data.get("other_rules") or []),
        )


def load(path: Path) -> Scope:
    return Scope.from_dict(json.loads(path.read_text(encoding="utf-8")))


def save(scope: Scope, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(scope.to_dict(), indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


# --------------------------------------------------------------------------
# Cross-checks against the raw policy text (anti-hallucination)
# --------------------------------------------------------------------------

_MENTION_RE = re.compile(r"(?<![a-z0-9_-])(\*\.)?((?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,62})(?![a-z0-9_-])", re.I)
_FILE_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|pdf|js|css|html?|php|aspx?|json|xml|txt|zip|md|exe|apk|ipa|dll)$")


def mentioned_hosts(text: str) -> set[str]:
    """Every host-like token in the policy text, lowercased. Wildcards keep
    their '*.' prefix."""
    found = set()
    for star, host in _MENTION_RE.findall(text):
        host = host.lower().rstrip(".")
        if _FILE_EXT.search(host) or host.replace(".", "").isdigit():
            continue
        found.add((star or "") + host)
    return found


def appears_in_policy(asset: Asset, policy_text: str) -> bool:
    """True if the policy text really names this asset. The policy must
    contain the host (or the wildcard base) as a token, the IP, or the
    range; an apex domain does not count as named only because a
    subdomain or a wildcard of it is named."""
    text = policy_text.lower()
    if not asset.is_network:
        return True
    if asset.kind in ("ip", "cidr"):
        literal = _clean(asset.raw).lower()
        return literal in text or asset.host in text
    host = asset.host
    escaped = re.escape(host)
    standalone = re.search(rf"(?<![a-z0-9_.-]){escaped}(?![a-z0-9_-])", text)
    if asset.kind == "wildcard" or asset.wildcard_host:
        starred = re.search(rf"\*\.{escaped}(?![a-z0-9_-])", text)
        dotted = re.search(rf"(?<![a-z0-9_*-])\.{escaped}(?![a-z0-9_-])", text)
        return bool(starred or standalone or dotted)
    return bool(standalone)


def quote_in_policy(quote: str, policy_text: str) -> bool:
    def norm(value: str) -> str:
        return re.sub(r"\s+", " ", value or "").strip().lower()
    q = norm(quote)
    return bool(q) and q in norm(policy_text)


# --------------------------------------------------------------------------
# Operator overrides (scope-overrides.txt)
# --------------------------------------------------------------------------

def parse_overrides(text: str) -> tuple[list[str], list[str], list[str]]:
    """Lines like `in *.foo.com` or `out admin.foo.com`. Returns
    (in_entries, out_entries, problems)."""
    ins, outs, problems = [], [], []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^header\s", line, re.I):
            continue
        match = re.match(r"^(in|out|\+|-)\s+(.+)$", line, re.I)
        if not match:
            problems.append(f"line {number}: '{line}' should start with 'in ' or 'out '")
            continue
        verb, value = match.group(1).lower(), match.group(2).strip()
        (ins if verb in ("in", "+") else outs).append(value)
    return ins, outs, problems


def parse_override_headers(text: str) -> dict[str, str]:
    """Lines like `header X-Bug-Bounty: amahrou1`."""
    headers = {}
    for raw in text.splitlines():
        match = re.match(r"^header\s+([A-Za-z0-9-]+)\s*:\s*(.+)$", raw.strip(), re.I)
        if match:
            headers[match.group(1)] = match.group(2).strip()
    return headers
