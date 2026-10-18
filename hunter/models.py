"""Model profiles: which provider and model each role uses, and the exact
environment Claude Code needs to talk to that provider."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .config import ROLES, TIERS, ConfigError

# Variables we always set ourselves; any inherited value is removed first so
# an old export in ~/.bashrc can never silently redirect an agent.
_MANAGED_ENV = (
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "CLAUDE_CODE_SUBAGENT_MODEL",
    "API_TIMEOUT_MS",
    "CLAUDE_CODE_EFFORT_LEVEL",
    "CLAUDE_CODE_AUTO_COMPACT_WINDOW",
)


@dataclass(frozen=True)
class ModelChoice:
    role: str
    profile_name: str
    tier: str
    model: str
    profile: dict

    @property
    def label(self) -> str:
        return f"{self.profile.get('label', self.profile_name)} / {self.model}"


def resolve(settings: dict, role: str) -> ModelChoice:
    if role not in settings["roles"]:
        raise ConfigError(f"Unknown role '{role}'. Known roles: {', '.join(ROLES)}")
    spec = settings["roles"][role]
    try:
        profile_name, tier = spec.split(":", 1)
    except ValueError as exc:
        raise ConfigError(f"Role '{role}' has an invalid value '{spec}'") from exc
    if profile_name == "active":
        profile_name = settings["active_profile"]
    profiles = settings["profiles"]
    if profile_name not in profiles:
        raise ConfigError(f"Role '{role}' points to unknown profile '{profile_name}'")
    if tier not in TIERS:
        raise ConfigError(f"Role '{role}' uses unknown tier '{tier}'")
    profile = profiles[profile_name]
    model = profile.get(tier) or profile.get("strong")
    return ModelChoice(role, profile_name, tier, model, profile)


def required_key_names(settings: dict) -> set[str]:
    """Secret names needed by the roles as currently configured."""
    return {resolve(settings, role).profile["key_name"] for role in settings["roles"]}


def agent_env(choice: ModelChoice, secrets: dict[str, str], base: dict | None = None) -> dict[str, str]:
    profile = choice.profile
    key = secrets.get(profile["key_name"], "")
    if not key:
        raise ConfigError(
            f"No {profile['key_name']} is saved, but role '{choice.role}' uses "
            f"{profile.get('label', choice.profile_name)}. Run: hunt setup"
        )
    env = dict(os.environ if base is None else base)
    for name in _MANAGED_ENV:
        env.pop(name, None)

    if profile["auth"] == "x-api-key":
        env["ANTHROPIC_API_KEY"] = key
    else:
        env["ANTHROPIC_AUTH_TOKEN"] = key
    if profile.get("base_url"):
        env["ANTHROPIC_BASE_URL"] = profile["base_url"]
        # Non-Anthropic endpoints: skip telemetry and other side traffic.
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"

    strong = profile.get("strong") or choice.model
    env["ANTHROPIC_MODEL"] = choice.model
    env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = profile.get("max") or strong
    env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = strong
    env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = profile.get("fast") or strong
    env["CLAUDE_CODE_SUBAGENT_MODEL"] = profile.get("fast") or strong
    if profile.get("api_timeout_ms"):
        env["API_TIMEOUT_MS"] = str(profile["api_timeout_ms"])
    # Never update the CLI in the middle of a run.
    env["DISABLE_AUTOUPDATER"] = "1"
    return env


def probe(profile: dict, key: str, timeout: float = 60.0) -> tuple[bool, str]:
    """Send one tiny request straight to the provider to check the key and
    the model name. Returns (ok, human message)."""
    base = profile.get("base_url") or "https://api.anthropic.com"
    url = base.rstrip("/") + "/v1/messages"
    body = json.dumps({
        "model": profile.get("fast") or profile.get("strong"),
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with the word OK."}],
    }).encode()
    headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
    if profile["auth"] == "x-api-key":
        headers["x-api-key"] = key
    else:
        headers["authorization"] = f"Bearer {key}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if 200 <= response.status < 300:
                return True, "the key works"
            return False, f"unexpected HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        detail = _error_detail(exc)
        if exc.code in (401, 403):
            return False, f"the key was rejected (HTTP {exc.code}){detail}"
        if exc.code == 404:
            return False, f"model or address not found (HTTP 404){detail}"
        if exc.code == 429:
            return True, "the key is valid but the provider is rate limiting right now"
        return False, f"HTTP {exc.code}{detail}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"could not reach {base} ({exc})"


def _error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read(2000).decode("utf-8", "replace")
        data = json.loads(raw)
        message = data.get("error", {}).get("message") or data.get("message")
        return f": {message}" if message else ""
    except Exception:
        return ""
