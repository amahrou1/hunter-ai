"""Settings (non-secret, JSON) and secrets (KEY=value file, mode 600).

The operator never edits either file by hand: `hunt setup` writes secrets
and `hunt models ...` writes settings. Defaults live in this module, and the
settings file only stores what differs from them, so a code update can add
new defaults without a migration.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import paths

# --------------------------------------------------------------------------
# Defaults
# --------------------------------------------------------------------------

DEFAULT_SETTINGS: dict[str, Any] = {
    "active_profile": "glm",
    # Each profile maps three tiers to concrete model names.
    #   fast   : cheap bulk reading and triage
    #   strong : reasoning and testing
    #   max    : validation, disproof and report writing
    "profiles": {
        "glm": {
            "label": "GLM (z.ai)",
            "base_url": "https://api.z.ai/api/anthropic",
            "key_name": "GLM_API_KEY",
            "auth": "bearer",
            "fast": "glm-5.3-flash",
            "strong": "glm-5.3",
            "max": "glm-5.3",
            "api_timeout_ms": 3000000,
        },
        "deepseek": {
            "label": "DeepSeek",
            "base_url": "https://api.deepseek.com/anthropic",
            "key_name": "DEEPSEEK_API_KEY",
            "auth": "bearer",
            "fast": "deepseek-flash[1m]",
            "strong": "deepseek-v4-pro[1m]",
            "max": "deepseek-v4-pro[1m]",
            "api_timeout_ms": 3000000,
        },
        "claude": {
            "label": "Claude (Anthropic)",
            "base_url": None,
            "key_name": "ANTHROPIC_API_KEY",
            "auth": "x-api-key",
            "fast": "claude-haiku-5-5",
            "strong": "claude-sonnet-5-5",
            "max": "claude-opus-5-5",
            "api_timeout_ms": None,
        },
    },
    # Role -> "<profile>:<tier>". "active" means the active profile.
    "roles": {
        "triage": "active:fast",
        "reviewer": "active:strong",
        "planner": "active:strong",
        "tester": "active:strong",
        "validator": "active:max",
        "disprover": "active:max",
        "writer": "active:max",
        # AI phase drivers: routine phases use the cheap flash tier, phases
        # that need reasoning use the strong tier. Change any with:
        # hunt models role <role> <profile:tier>.
        "scanner": "active:fast",
        "prober": "active:fast",
        "mapper": "active:fast",
        "discoverer": "active:fast",
        "jsanalyst": "active:fast",
        "misconfig": "active:fast",
        "intel": "active:strong",
        "accounts": "active:strong",
        "authz": "active:strong",
        "injection": "active:strong",
    },
    "agent": {
        "max_turns": 80,
        "timeout_minutes": 90,
        "retries": 2,
        # "auto" uses the result of `hunt doctor`; "on"/"off" force it.
        "bare": "auto",
    },
    "run": {
        # After all phases ran once, how long to wait for the operator to
        # resolve blockers (for example add test accounts) before finishing.
        "blocker_wait_minutes": 180,
        "poll_seconds": 60,
        "max_phase_attempts": 3,
    },
    "notify": {"discord": True},
    "scope": {
        # Requests per second used when the policy does not state a limit.
        "default_rps": 5,
        # Never faster than this, whatever the policy allows (small VPS).
        "max_rps": 200,
        # When the policy only allows limited automation.
        "limited_scanning_rps": 2,
    },
    "researcher": {
        # Platform username, used to fill placeholders such as
        # "X-Bug-Bounty: <username>" and to build platform emails.
        "handle": "",
    },
    "recon": {
        "subfinder_rps": 10, "subfinder_max_min": 15,
        "dnsx_rps": 150, "dnsx_threads": 50,
        "brute_max_min": 20, "resolve_max_min": 20,
    },
    "probe": {
        "ports": [80, 443, 8080, 8443, 8000, 8888],
        "threads": 20, "max_min": 30,
    },
    "tools": {
        # Soft memory cap per external tool (MB). The VPS has 8 GB.
        "mem_mb": 1500,
    },
    "proxy": {
        "port": 0,  # 0 = pick a free port per run
        "log_body_bytes": 4096,
        # Route TARGET traffic out through a residential/upstream HTTP proxy so
        # the target sees a residential IP instead of this VPS's datacenter IP
        # (which Akamai/WAF rules often block). Empty = direct. Example:
        # "http://user:pass@gate.provider.com:7000". Set with: hunt egress <url>.
        # Only target egress is affected; the scope guard, rate limit and
        # logging still apply, and OOB/model/passive hosts still go direct.
        "upstream": "",
        # Infrastructure, never targets: reached directly, never scope-checked.
        "passthrough": [
            "api.z.ai", "open.bigmodel.cn", "api.deepseek.com", "api.anthropic.com",
            "api.mail.tm", "mail.tm", "discord.com",
            # Passive data sources an AI phase may query directly (not targets):
            # they bypass the scope proxy; real targets still go through it.
            "crt.sh", "web.archive.org", "archive.org", "index.commoncrawl.org",
            "otx.alienvault.com", "api.hackertarget.com", "rapiddns.io", "dns.bufferover.run",
            "urlscan.io", "dns.google", "cloudflare-dns.com", "github.com", "api.github.com",
            "raw.githubusercontent.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
            "rubygems.org", "api.rubygems.org",
            "services.nvd.nist.gov", "osv.dev", "api.osv.dev",
        ],
    },
    # Where to find wordlists for fuzzing, searched in order. The agent picks
    # the right list per asset from these (your own lists first, then SecLists).
    "wordlists": {
        "dirs": ["~/myLists", "~/SecLists/Discovery/Web-Content", "~/SecLists/Discovery/Web-Content/api"],
    },
    # OSINT / dorking: GitHub code search for leaked secrets tied to the target,
    # then minimal validation of real ones. validate_hosts are vendor APIs a
    # found key is checked against (not the target); add more as needed.
    "osint": {
        "enabled": True,
        "validate_hosts": [
            "api.github.com", "api.openai.com", "api.anthropic.com", "sts.amazonaws.com",
            "slack.com", "api.slack.com", "hooks.slack.com", "api.stripe.com", "api.sendgrid.com",
            "api.mailgun.net", "api.twilio.com", "api.telegram.org", "api.digitalocean.com",
            "gitlab.com", "api.heroku.com", "www.googleapis.com", "oauth2.googleapis.com",
            "api.shodan.io", "api.mapbox.com", "api.dropboxapi.com", "graph.microsoft.com",
            "login.microsoftonline.com", "api.cloudflare.com", "api.pagerduty.com", "api.bitbucket.org",
        ],
    },
    # Your out-of-band testing infrastructure (not targets). The agent points
    # payloads at these and they are allowed through the command checker and the
    # proxy. Change with `hunt oob`.
    "oob": {
        "enabled": True,
        "callback_host": "38.242.235.206",          # your VPS public IP (SSRF/XXE/OOB listener)
        "listener_ports": [80, 8080],
        "blind_xss_url": "https://xss.report/c/abdalah336",
        "temp_mail": True,                           # mail.tm temporary mailboxes
    },
    # A scope-proxied headless Chromium the agents can drive (the `hbrowse`
    # helper) for anything curl cannot show: DOM / client-side XSS, postMessage
    # and window.name PoCs, open-redirect landing, and authenticated or stored
    # XSS flows. Its traffic goes through the same scope proxy. Install the
    # browser with: .venv/bin/python -m playwright install --with-deps chromium
    # (install.sh does this; `hunt doctor` reports if it is missing).
    "browser": {
        "enabled": True,
    },
    # Filled in by `hunt doctor`; never set by hand.
    "detected": {},
}

ROLES = tuple(DEFAULT_SETTINGS["roles"].keys())
TIERS = ("fast", "strong", "max")


@dataclass(frozen=True)
class KeySpec:
    name: str
    label: str
    required: bool
    hint: str
    kind: str = "key"  # "key" | "url"


# Order matters: this is the order `hunt setup` asks in.
KEY_CATALOG: tuple[KeySpec, ...] = (
    KeySpec("DISCORD_WEBHOOK_URL", "Discord webhook URL", True,
            "From Discord: Server Settings > Integrations > Webhooks > Copy Webhook URL", "url"),
    KeySpec("GLM_API_KEY", "GLM (z.ai) API key", False,
            "Needed while GLM is the active model profile"),
    KeySpec("DEEPSEEK_API_KEY", "DeepSeek API key", False,
            "Optional now. Needed only if you switch to DeepSeek"),
    KeySpec("ANTHROPIC_API_KEY", "Claude (Anthropic) API key", False,
            "Optional now. Needed only if you switch to Claude"),
    KeySpec("SHODAN_API_KEY", "Shodan API key", False, "Optional recon key"),
    KeySpec("PDCP_API_KEY", "ProjectDiscovery (Chaos) API key", False, "Optional recon key"),
    KeySpec("GITHUB_TOKEN", "GitHub token (read-only, public data)", False,
            "Optional recon key for code search"),
    KeySpec("SECURITYTRAILS_API_KEY", "SecurityTrails API key", False, "Optional recon key"),
    KeySpec("VIRUSTOTAL_API_KEY", "VirusTotal API key", False, "Optional recon key"),
    KeySpec("URLSCAN_API_KEY", "urlscan.io API key", False, "Optional recon key"),
    KeySpec("CENSYS_API_KEY", "Censys API key (personal access token)", False, "Optional recon key"),
)

KEY_NAMES = {spec.name for spec in KEY_CATALOG}


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _diff(full: dict, base: dict) -> dict:
    """Return only the parts of `full` that differ from `base`."""
    out: dict = {}
    for key, value in full.items():
        if key not in base:
            out[key] = value
        elif isinstance(value, dict) and isinstance(base[key], dict):
            sub = _diff(value, base[key])
            if sub:
                out[key] = sub
        elif value != base[key]:
            out[key] = value
    return out


def load_settings() -> dict:
    path = paths.settings_file()
    overrides: dict = {}
    if path.exists():
        try:
            overrides = json.loads(path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"The settings file {path} is damaged ({exc}). "
                "Run: hunt reset-settings"
            ) from exc
    return _deep_merge(DEFAULT_SETTINGS, overrides)


def save_settings(settings: dict) -> None:
    overrides = _diff(settings, DEFAULT_SETTINGS)
    _atomic_write(paths.settings_file(), json.dumps(overrides, indent=2, sort_keys=True) + "\n", 0o600)


def reset_settings() -> None:
    path = paths.settings_file()
    if path.exists():
        path.unlink()


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


class ConfigError(Exception):
    """A problem the operator must fix (bad key, damaged file...)."""


def load_secrets() -> dict[str, str]:
    path = paths.secrets_file()
    if not path.exists():
        return {}
    secrets: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if _KEY_RE.match(key):
            secrets[key] = value.strip()
    return secrets


def save_secrets(secrets: dict[str, str]) -> None:
    lines = ["# hunter-ai secrets. Written by `hunt setup`. Do not share this file.\n"]
    for key in sorted(secrets):
        value = secrets[key]
        if not value:
            continue
        if not _KEY_RE.match(key):
            raise ConfigError(f"Invalid secret name: {key}")
        if any(ch in value for ch in "\r\n"):
            raise ConfigError(f"The value for {key} contains a line break")
        lines.append(f"{key}={value}\n")
    _atomic_write(paths.secrets_file(), "".join(lines), 0o600)


def clean_secret_value(raw: str) -> str:
    """Normalise a pasted value: strip spaces, surrounding quotes and a
    leading 'KEY=' if the operator pasted a whole line."""
    value = raw.strip().strip("​").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"`":
        value = value[1:-1].strip()
    match = re.match(r"^(?:export\s+)?[A-Z][A-Z0-9_]*=(.*)$", value)
    if match:
        value = match.group(1).strip().strip("'\"")
    return value


def mask(value: str) -> str:
    if not value:
        return "(not set)"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]} ({len(value)} characters)"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _atomic_write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except PermissionError:
        pass
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
