from __future__ import annotations

import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

POLICY = """Acme Bug Bounty Program
In scope:
- https://app.acme.test
- *.api.acme.test
Out of scope:
- blog.acme.test
Rules: no DoS, max 5 requests per second, use your @intigriti.me address.
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated config, targets and skills folders plus the fake CLI."""
    config_dir = tmp_path / "config"
    targets = tmp_path / "targets"
    skills = tmp_path / "skills"
    for path in (config_dir, targets, skills):
        path.mkdir()
    fake = tmp_path / "claude"
    fake.write_text(f"#!/bin/sh\nexec {sys.executable} {ROOT / 'tests' / 'fake_claude.py'} \"$@\"\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    record = tmp_path / "claude_calls.jsonl"
    monkeypatch.setenv("HUNTER_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("HUNTER_TARGETS_DIR", str(targets))
    monkeypatch.setenv("HUNTER_SKILLS_DIR", str(skills))
    monkeypatch.setenv("HUNTER_CLAUDE_BIN", str(fake))
    monkeypatch.setenv("FAKE_CLAUDE_RECORD", str(record))
    monkeypatch.setenv("FAKE_CLAUDE_MODE", "success")
    # An inherited variable must never leak into an agent session.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example")
    return {"config": config_dir, "targets": targets, "skills": skills, "record": record, "tmp": tmp_path}


def calls(record: Path) -> list[dict]:
    if not record.exists():
        return []
    return [json.loads(line) for line in record.read_text().splitlines() if line.strip()]


class FakeDiscord:
    def __init__(self, fail_first_with: int | None = None):
        self.messages: list[dict] = []
        self.fail_first_with = fail_first_with
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                if outer.fail_first_with:
                    code, outer.fail_first_with = outer.fail_first_with, None
                    payload = json.dumps({"retry_after": 0.05}).encode()
                    self.send_response(code)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                outer.messages.append(body)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/webhooks/1/abc"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def titles(self) -> list[str]:
        return [m["embeds"][0]["title"] for m in self.messages]


@pytest.fixture
def discord():
    server = FakeDiscord()
    yield server
    server.close()


class RecordingNotifier:
    def __init__(self):
        self.sent: list[tuple[str, str, str]] = []

    def send(self, title, message="", level="info", target=None):
        self.sent.append((title, message, level))
        return True

    def titles(self):
        return [t for t, _, _ in self.sent]


@pytest.fixture
def notifier():
    return RecordingNotifier()


@pytest.fixture
def make_target(env):
    def _make(name="acme", policy=POLICY, files=None):
        path = env["targets"] / name
        path.mkdir(parents=True, exist_ok=True)
        (path / "policy.txt").write_text(policy)
        for filename, content in (files or {}).items():
            (path / filename).write_text(content)
        from hunter.target import Target
        return Target(path)
    return _make


@pytest.fixture
def settings_secrets(env):
    from hunter import config
    settings = config.load_settings()
    secrets = {"GLM_API_KEY": "glm-test-key-123456", "DISCORD_WEBHOOK_URL": "http://unused"}
    return settings, secrets


def pytest_configure(config):
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
