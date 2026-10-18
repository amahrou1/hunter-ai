"""Well-known locations. Every path can be overridden by an environment
variable so the test-suite never touches the real home directory."""

from __future__ import annotations

import os
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else default


def home() -> Path:
    return Path.home()


def config_dir() -> Path:
    return _env_path("HUNTER_CONFIG_DIR", home() / ".config" / "hunter-ai")


def secrets_file() -> Path:
    return config_dir() / "secrets.env"


def settings_file() -> Path:
    return config_dir() / "settings.json"


def notify_log() -> Path:
    return config_dir() / "notify.log"


def targets_dir() -> Path:
    return _env_path("HUNTER_TARGETS_DIR", home() / "targets")


def skills_dir() -> Path:
    return _env_path("HUNTER_SKILLS_DIR", home() / ".claude" / "skills")


def claude_bin() -> str:
    """Path to the Claude Code CLI. The native installer puts it in
    ~/.local/bin, which is not always on PATH inside tmux or cron."""
    override = os.environ.get("HUNTER_CLAUDE_BIN")
    if override:
        return override
    local = home() / ".local" / "bin" / "claude"
    if local.exists():
        return str(local)
    return "claude"
