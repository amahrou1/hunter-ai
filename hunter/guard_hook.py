"""Command checker for AI agents (a Claude Code PreToolUse hook).

Every Bash command (and WebFetch URL) an agent wants to run is checked here
before it runs. Exit code 2 blocks it and the reason is shown to the agent,
which can correct itself. Rules:

1. Every URL, every IP address, and every host name under one of the
   program's domains must be in scope (or a known passive data source, a
   model API, or loopback). The operator's avoid list counts as out of scope.
2. Nothing may switch the scope proxy off (no --noproxy, no unsetting or
   overriding *_PROXY, no proxychains).
3. No port scanners or brute-force tools: `hk portscan` is the scope-checked
   scanner; brute forcing is never allowed.
4. The run's own controls stay out of reach: scope.json, avoid.json, the run
   database (write it only through `hk`), the real tool binaries (use the
   wrappers that add the proxy), and hunt start/stop/update/reset/setup.

The hook reads the scope from HUNTER_SCOPE_FILE (set by the orchestrator).
If the scope cannot be read, every command that names a host is blocked.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hunter import scope as sc  # noqa: E402

# Reachable without being in scope: public, passive data sources and package
# registries. They are not targets. Extended by settings agent.extra_hosts.
PASSIVE_HOSTS = (
    "crt.sh", "web.archive.org", "archive.org", "index.commoncrawl.org", "otx.alienvault.com",
    "api.hackertarget.com", "urlscan.io", "dns.google", "cloudflare-dns.com", "rdap.org",
    "github.com", "api.github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
    "codeload.github.com", "objects.githubusercontent.com", "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "rubygems.org", "api.rubygems.org", "packagist.org", "repo.packagist.org",
    "nvd.nist.gov", "services.nvd.nist.gov", "cve.mitre.org", "osv.dev", "api.osv.dev",
    "cve.circl.lu", "www.exploit-db.com",
    # Scope-discovery sources (phase 01c-expand): cert logs, RDAP/WHOIS, IP-range
    # ownership, and key-gated passive recon. They describe assets, never targets.
    "rdap.verisign.com", "rdap.iana.org", "data.iana.org", "stat.ripe.net", "rest.db.ripe.net",
    "whois.arin.net", "rdap.arin.net", "api.securitytrails.com", "www.virustotal.com",
    "api.shodan.io", "search.censys.io", "api.censys.io", "chaos.projectdiscovery.io",
    "dns.bufferover.run", "tls.bufferover.run", "api.whoisxmlapi.com",
    "reverse-whois.whoisxmlapi.com", "subdomains.whoisxmlapi.com",
)
MODEL_HOSTS = ("api.z.ai", "open.bigmodel.cn", "api.deepseek.com", "api.anthropic.com",
               "api.mail.tm", "mail.tm", "discord.com")
# Well-known public DNS resolvers: used for name resolution and latency checks,
# never a target. Allowed so `dig @8.8.8.8` and friends work.
PUBLIC_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                    "208.67.222.222", "208.67.220.220", "127.0.0.53")

SCANNERS = ("nmap", "masscan", "zmap", "naabu", "rustscan", "hping3", "unicornscan", "zgrab", "zgrab2")
# DNS resolution load: dnsx fans out to public resolvers that do NOT go through
# the scope proxy, so the proxy cannot throttle them. A high query rate can get
# the VPS IP throttled or temp-banned by those resolvers and drop results. The
# hook requires dnsx to carry a rate-limit flag at or below HUNTER_DNS_MAX_RPS.
_DNSX_RE = re.compile(r"(?<![\w/.-])dnsx(?![\w-])")
_DNSX_RATE_RE = re.compile(r"(?:^|\s)-(?:rl|rate-limit)(?:\s+|=)(\d+)")
BRUTE = ("hydra", "medusa", "ncrack", "patator", "crowbar", "thc-hydra", "kerbrute", "crackmapexec", "netexec")
PROXY_BYPASS = [
    (re.compile(r"--no-?proxy\b"), "--noproxy switches the scope guard off"),
    (re.compile(r"(?:^|\s)(?:-x|--proxy|--proxy-server|-proxy|-http-proxy|--http-proxy)(?:\s+|=)(['\"])\1"),
     "an empty proxy switches the scope guard off"),
    (re.compile(r"\b(?:no_proxy|NO_PROXY)\s*="), "changing NO_PROXY switches the scope guard off"),
    (re.compile(r"\b(?:HTTPS?_PROXY|https?_proxy|ALL_PROXY|all_proxy)\s*="), "the proxy settings are fixed by the run"),
    (re.compile(r"\bunset\b[^;&|\n]*_PROXY", re.I), "the proxy settings are fixed by the run"),
    (re.compile(r"\benv\b[^;&|\n]*\s-u\s"), "env -u can remove the proxy settings"),
    (re.compile(r"\benv\b\s+-i\b"), "env -i removes the proxy settings"),
    (re.compile(r"\bproxychains\w*\b"), "proxychains is not allowed; the run already provides the proxy"),
    (re.compile(r"\b(?:requests|httpx|urllib3)\b.*\btrust_env\s*=\s*False"), "trust_env=False bypasses the proxy"),
    (re.compile(r"proxies\s*=\s*\{\s*\}"), "an empty proxies setting bypasses the guard"),
]
CONTROL = [
    (re.compile(r"\bhunt\s+(?:start|stop|run|resume|update|reset|reset-settings|setup|models|rate-cap|handle|new)\b"),
     "the run's controls are for the operator only"),
    # Agents may stop tools THEY started (a hung ffuf/dnsx), but never the scope
    # proxy or the run's own controls.
    (re.compile(r"\b(?:pkill|killall|kill)\b[^\n;&|]*\b(?:mitmdump|mitmproxy|guard_hook|orchestrator)\b"),
     "the scope proxy and the run's own processes must not be stopped"),
    (re.compile(r"\bmitmdump\b"), "the scope proxy must not be started or stopped"),
    (re.compile(r"\bsudo\b|\bsu\s+-"), "no root access"),
    (re.compile(r"\brm\s+-[a-z]*r[a-z]*f?\s+(?:/|~|\$HOME)(?:\s|$)"), "that would delete far too much"),
]
# Publishing a package to a public registry is the dependency-confusion EXPLOIT
# step, with a real side effect on the public registry and on the target's
# builds. It must be done by the operator by hand after review, never by the
# run - the phase only discovers and validates that a name is unclaimed.
PUBLISH = [
    (re.compile(r"\b(?:npm|pnpm|yarn)\s+publish\b"),
     "publishing an npm package is the exploit step for dependency confusion; the operator does it by hand"),
    (re.compile(r"\bnpm\s+(?:adduser|login|unpublish|deprecate|owner)\b"),
     "npm registry auth/publish actions are for the operator, not the run"),
    (re.compile(r"\btwine\s+upload\b|\b(?:poetry|flit|hatch)\s+publish\b"),
     "publishing to PyPI is the exploit step for dependency confusion; the operator does it by hand"),
    (re.compile(r"\bgem\s+push\b"),
     "publishing a gem is the exploit step for dependency confusion; the operator does it by hand"),
    (re.compile(r"\bcargo\s+publish\b"),
     "publishing a crate is the exploit step for dependency confusion; the operator does it by hand"),
]
_URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>`|;)]+", re.I)
_IP_RE = re.compile(r"(?<![\w.:/-])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?(?![\w.])")
_HOST_RE = re.compile(r"(?<![\w@/.-])((?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,62})(?![\w.-])", re.I)
_RAW_TCP = re.compile(r"\b(?:nc|ncat|netcat|telnet|socat)\b\s+(?:-\S+\s+)*([\w.-]+)")
_SCLIENT = re.compile(r"s_client\b[^\n;|&]*-connect\s+([\w.-]+)")

# `hk` is the run's own toolkit: every subcommand that contacts a host checks
# scope itself first (kit.py) and fetches through the scope proxy regardless, so
# a hostname in an `hk` argument is never an un-checked network contact. Many hk
# subcommands (note, progress, notify, finding, add, priority, filter, mark,
# import, secrets) take free text or local paths that legitimately quote
# in-scope hostnames as DATA. Statically scanning that text for in-scope hosts
# only produces false blocks - it stopped the probe agent from recording its own
# progress and findings and drove it into max_turns. So a command segment whose
# program is `hk` is not host-scanned here (its other guards still apply).
# Only `hk` is exempt: it scope-checks its own contact. Shell plumbing is NOT
# exempt - `awk` can run commands via system(), and `echo host | xargs nc`
# would hide the host in an exempt segment. Its segments are scanned as before
# (they rarely contain a host, so this costs nothing in practice).
_SAFE_LEADERS = frozenset(("hk",))
_SEG_SPLIT = re.compile(r"(?:\|\||&&|\||;|\n|&(?!&))")
_LEADER_RE = re.compile(r"^\s*(?:[A-Za-z_][\w]*=\S*\s+)*([A-Za-z0-9_./-]+)")


def _segment_leader(segment: str) -> str:
    """The program a shell segment runs (after any VAR=val prefixes), lowercased
    and stripped of a directory; '' if the segment has no command word."""
    match = _LEADER_RE.match(segment)
    if not match:
        return ""
    return match.group(1).rsplit("/", 1)[-1].lower()


def _host_check_segments(text: str) -> list[str]:
    """Command segments whose host tokens must be scope-checked here. A segment
    led by `hk` (scope-checks its own contact) is left out, so a hostname quoted as data in it
    cannot cause a false block."""
    out = []
    for segment in _SEG_SPLIT.split(text):
        if not segment.strip():
            continue
        if _segment_leader(segment) in _SAFE_LEADERS:
            continue
        out.append(segment)
    return out


class Verdict(Exception):
    pass


# Characters that mean an extracted token is NOT a literal host: shell variables
# ($h), brace/bracket expansions ({host}, $(...)), regex metacharacters from a
# grep/heredoc, globs, quotes. Such a token cannot be scope-checked statically -
# the scope proxy still enforces the real host at request time - so the hook
# skips it rather than false-blocking the agent (this was ~40% of all blocks).
_NOT_A_HOST = set("${}[]()^|*`\\<>\"' ,")


def _as_host(token: str) -> str | None:
    """A cleaned hostname/IP to scope-check, or None if the token is not a
    literal host (a flag, a number, a shell variable, a regex fragment)."""
    token = token.strip().strip("\"'").rstrip(".,);:")
    if not token or token.startswith("-"):
        return None
    if any(c in token for c in _NOT_A_HOST):
        return None
    if "." not in token and not _is_ip(token):   # not an FQDN and not an IP
        return None
    return token.lower()


def _host_ok(host: str, scope: sc.Scope | None, extra: tuple[str, ...]) -> str | None:
    """None if allowed, else the reason."""
    host = sc.normalize_host(host)
    if not host:
        return None
    if host in ("localhost",) or host.endswith(".localhost"):
        return None
    if host in PUBLIC_RESOLVERS:
        return None
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_unspecified:
            return None
    except ValueError:
        pass
    for allowed in (*PASSIVE_HOSTS, *MODEL_HOSTS, *extra):
        if host == allowed or host.endswith("." + allowed):
            return None
    if scope is None:
        return "the scope could not be read, so no host may be contacted"
    decision = scope.decide(host)
    if decision.allowed:
        return None
    return f"{host} is {decision.reason}" + (f" ({decision.matched})" if decision.matched else "")


def _roots(scope: sc.Scope | None) -> set[str]:
    """Registrable-looking roots of every scope entry: a host token under one
    of these is a target host and must be checked even outside a URL."""
    roots = set()
    if scope is None:
        return roots
    for asset in (*scope.in_scope, *scope.expanded, *scope.out_of_scope, *scope.operator_out):
        host = (asset.host or "").lower().lstrip("*.")
        if not host or asset.kind in ("ip", "cidr"):
            continue
        labels = host.split(".")
        roots.add(".".join(labels[-2:]) if len(labels) >= 2 else host)
    return roots


def _dns_max_rps() -> int:
    try:
        value = int(os.environ.get("HUNTER_DNS_MAX_RPS", "0"))
    except ValueError:
        return 0
    return value if value > 0 else 0


def _check_dns_rate(text: str) -> None:
    """Keep dnsx from running the resolvers at an egregious rate - but NEVER
    block it just for omitting the flag. dnsx is a core recon tool; a hard block
    on a missing -rl kills recon entirely (0 hosts), which is far worse than an
    unthrottled dnsx (resolvers self-throttle). So we only refuse an EXPLICIT
    rate that is well above the ceiling; a missing -rl is allowed (dnsx's own
    default is already modest), and a rate at or near the ceiling passes."""
    ceiling = _dns_max_rps()
    if ceiling <= 0 or not _DNSX_RE.search(text):
        return
    match = _DNSX_RATE_RE.search(text)
    if match is None:
        return  # no explicit rate: allow (do NOT break recon over a missing flag)
    # Only block a rate that is clearly reckless (more than ~4x the ceiling),
    # so a reasonable choice near the ceiling is never refused.
    if int(match.group(1)) > max(ceiling * 4, 200):
        raise Verdict(
            f"dnsx -rl {match.group(1)} is far above the resolver ceiling ({ceiling}/s). "
            f"Use -rl {ceiling} or less.")


def check_command(command: str, scope: sc.Scope | None, protected: list[str], extra: tuple[str, ...] = ()) -> None:
    """Raise Verdict(reason) if the command must not run."""
    text = command or ""
    for word in SCANNERS:
        if re.search(rf"(?<![\w/.-]){re.escape(word)}(?![\w-])", text):
            raise Verdict(f"{word} is not allowed. Use `hk portscan` - it scans only in-scope addresses at the "
                          f"program's rate.")
    for word in BRUTE:
        if re.search(rf"(?<![\w/.-]){re.escape(word)}(?![\w-])", text):
            raise Verdict(f"{word}: brute forcing logins is never allowed in this run.")
    _check_dns_rate(text)
    for pattern, reason in (*PROXY_BYPASS, *CONTROL, *PUBLISH):
        if pattern.search(text):
            raise Verdict(reason)
    for path in protected:
        if not path or path not in text:
            continue
        name = re.escape(path)
        # Writing to / destroying a run file is blocked; READING it is fine
        # (e.g. `sqlite3 state.db "select ..."` to check progress).
        wrote = (re.search(rf">>?\s*{name}", text)
                 or re.search(rf"\b(?:tee|rm|mv|cp|truncate|chmod)\b[^\n;&|]*{name}", text)
                 or re.search(rf"\bsed\s+-i\b[^\n;&|]*{name}", text)
                 or re.search(rf"open\(\s*['\"]?{name}", text))
        sqlite_write = re.search(r"\bsqlite3\b", text) and re.search(
            r"\b(?:insert|update|delete|drop|create|alter|replace|attach|vacuum|reindex)\b", text, re.I)
        if wrote or sqlite_write:
            raise Verdict(f"{Path(path).name} belongs to the run; change it only through `hk` "
                          f"(reading it is fine, e.g. a sqlite SELECT).")
        if path.endswith("/tools") and path in text:
            raise Verdict("call the tools by name (the wrappers add the scope proxy), not from their folder")

    hosts: list[str] = []
    roots = _roots(scope)
    # The bare root of an in-scope wildcard (bol.com for *.bol.com) is how
    # passive tools are told what to enumerate (subfinder -d bol.com); it is
    # not checked as a host here. Contacting it over HTTP still goes through
    # the proxy, which blocks it if it is not in scope.
    wildcard_roots = set(scope.wildcard_roots()) if scope else set()
    # Only scan segments that actually make a request. An `hk ...` segment
    # scope-checks its own contact, so hostnames quoted as data in it (hk note,
    # hk progress, hk finding) are not blocked here.
    for segment in _host_check_segments(text):
        for url in _URL_RE.findall(segment):
            try:
                host = re.split(r"[/:?#]", url.split("://", 1)[1].split("@")[-1], maxsplit=1)[0]
            except IndexError:
                continue
            hosts.append(host)
        for match in _IP_RE.finditer(segment):
            try:
                ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            hosts.append(match.group(1))
        for match in _HOST_RE.finditer(segment):
            token = match.group(1).lower()
            if token in wildcard_roots:
                continue
            if any(token == r or token.endswith("." + r) for r in roots):
                hosts.append(token)
        for pattern in (_RAW_TCP, _SCLIENT):
            for match in pattern.finditer(segment):
                hosts.append(match.group(1))
    for host in hosts:
        host = _as_host(host)
        if host is None:
            continue
        reason = _host_ok(host, scope, extra)
        if reason:
            raise Verdict(f"Blocked: {reason}. Only in-scope targets may be contacted "
                          f"(check with: hk scope check <host>).")


def _load_scope() -> sc.Scope | None:
    path = os.environ.get("HUNTER_SCOPE_FILE")
    if not path:
        return None
    try:
        return sc.load(Path(path))
    except (OSError, ValueError, KeyError):
        return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    tool = event.get("tool_name") or ""
    data = event.get("tool_input") or {}
    scope = _load_scope()
    extra = tuple(h for h in os.environ.get("HUNTER_EXTRA_HOSTS", "").split(",") if h)
    protected = [p for p in os.environ.get("HUNTER_PROTECTED", "").split(os.pathsep) if p]
    try:
        if tool == "Bash":
            check_command(str(data.get("command") or ""), scope, protected, extra)
        elif tool == "WebFetch":
            # Reading the public web (write-ups, docs, disclosed reports) is
            # allowed and does not touch the target. Only the target's own
            # hosts are blocked here: fetch those with curl, which goes through
            # the scope proxy (rate-limited, logged, correct headers).
            url = str(data.get("url") or "")
            host = re.split(r"[/:?#]", url.split("://", 1)[-1], maxsplit=1)[0].split("@")[-1].lower()
            roots = _roots(scope)
            if host and (any(host == r or host.endswith("." + r) for r in roots)
                         or (scope is not None and scope.decide(host).allowed)):
                raise Verdict(f"Blocked: {host} is a target host; fetch it with curl so it goes through the "
                              f"scope proxy, not WebFetch.")
    except Verdict as verdict:
        log = os.environ.get("HUNTER_HOOK_LOG")
        if log:
            try:
                with open(log, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"tool": tool, "input": data, "blocked": str(verdict)})[:4000] + "\n")
            except OSError:
                pass
        print(str(verdict), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
