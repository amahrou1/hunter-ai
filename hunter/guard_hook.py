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
)
MODEL_HOSTS = ("api.z.ai", "open.bigmodel.cn", "api.deepseek.com", "api.anthropic.com",
               "api.mail.tm", "mail.tm", "discord.com")
# Well-known public DNS resolvers: used for name resolution and latency checks,
# never a target. Allowed so `dig @8.8.8.8` and friends work.
PUBLIC_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                    "208.67.222.222", "208.67.220.220", "127.0.0.53")

SCANNERS = ("nmap", "masscan", "zmap", "naabu", "rustscan", "hping3", "unicornscan", "zgrab", "zgrab2")
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
    (re.compile(r"\b(?:pkill|killall)\b|\bkill\s+-?\w*\s*\$\(|mitmdump"), "processes of the run must not be stopped"),
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


class Verdict(Exception):
    pass


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
    for asset in (*scope.in_scope, *scope.out_of_scope, *scope.operator_out):
        host = (asset.host or "").lower().lstrip("*.")
        if not host or asset.kind in ("ip", "cidr"):
            continue
        labels = host.split(".")
        roots.add(".".join(labels[-2:]) if len(labels) >= 2 else host)
    return roots


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
    for pattern, reason in (*PROXY_BYPASS, *CONTROL, *PUBLISH):
        if pattern.search(text):
            raise Verdict(reason)
    for path in protected:
        if path and path in text and re.search(r"(>|\btee\b|\bsed\s+-i|\brm\b|\bmv\b|\bcp\b|\bsqlite3\b|"
                                               r"\btruncate\b|\bchmod\b|open\()", text):
            raise Verdict(f"{Path(path).name} belongs to the run; change it only through `hk` "
                          f"(or ask the operator).")
        if path and path.endswith("/tools") and path in text:
            raise Verdict("call the tools by name (the wrappers add the scope proxy), not from their folder")

    hosts: list[str] = []
    for url in _URL_RE.findall(text):
        try:
            host = re.split(r"[/:?#]", url.split("://", 1)[1].split("@")[-1], maxsplit=1)[0]
        except IndexError:
            continue
        hosts.append(host)
    for match in _IP_RE.finditer(text):
        try:
            ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        hosts.append(match.group(1))
    roots = _roots(scope)
    # The bare root of an in-scope wildcard (bol.com for *.bol.com) is how
    # passive tools are told what to enumerate (subfinder -d bol.com); it is
    # not checked as a host here. Contacting it over HTTP still goes through
    # the proxy, which blocks it if it is not in scope.
    wildcard_roots = set(scope.wildcard_roots()) if scope else set()
    for match in _HOST_RE.finditer(text):
        token = match.group(1).lower()
        if token in wildcard_roots:
            continue
        if any(token == r or token.endswith("." + r) for r in roots):
            hosts.append(token)
    for pattern in (_RAW_TCP, _SCLIENT):
        for match in pattern.finditer(text):
            hosts.append(match.group(1))
    for host in hosts:
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
