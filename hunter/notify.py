"""Discord notifications. A failed notification is logged and never stops
a run. Every message passes through `redact` so a saved secret can never
be posted, even if an agent copies one into a finding title."""

from __future__ import annotations

import datetime as _dt
import json
import sys
import time
import urllib.error
import urllib.request

from . import paths

COLORS = {
    "info": 0x3B82F6,
    "success": 0x16A34A,
    "warn": 0xF59E0B,
    "error": 0xDC2626,
    "finding": 0x9333EA,
}
ICONS = {"info": "[i]", "success": "[ok]", "warn": "[!]", "error": "[x]", "finding": "[*]"}

DESCRIPTION_LIMIT = 3900
TITLE_LIMIT = 240


def redact(text: str, secrets: dict[str, str]) -> str:
    for value in secrets.values():
        if value and len(value) >= 6:
            text = text.replace(value, "[redacted]")
    return text


class Notifier:
    def __init__(self, secrets: dict[str, str], enabled: bool = True, timeout: float = 15.0):
        self.secrets = secrets
        self.webhook = secrets.get("DISCORD_WEBHOOK_URL", "")
        self.enabled = enabled and bool(self.webhook)
        self.timeout = timeout

    def send(self, title: str, message: str = "", level: str = "info", target: str | None = None) -> bool:
        title = redact(title, self.secrets)[:TITLE_LIMIT]
        message = redact(message, self.secrets)
        if len(message) > DESCRIPTION_LIMIT:
            message = message[: DESCRIPTION_LIMIT - 20] + "\n...(cut)"
        self._log(level, title, message, target)
        if not self.enabled:
            return False
        embed = {
            "title": f"{ICONS.get(level, '')} {title}".strip(),
            "description": message or None,
            "color": COLORS.get(level, COLORS["info"]),
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "footer": {"text": f"hunter-ai{' | ' + target if target else ''}"},
        }
        payload = {"username": "Hunter AI", "embeds": [{k: v for k, v in embed.items() if v is not None}]}
        return self._post(payload)

    def _post(self, payload: dict, attempts: int = 4) -> bool:
        data = json.dumps(payload).encode()
        for attempt in range(attempts):
            request = urllib.request.Request(
                self.webhook, data=data, method="POST",
                headers={"content-type": "application/json", "user-agent": "hunter-ai (notifier)"},
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout):
                    return True
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    time.sleep(_retry_after(exc))
                    continue
                if exc.code >= 500 and attempt < attempts - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                self._log("error", f"Discord rejected the message (HTTP {exc.code})", "", None)
                return False
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt < attempts - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                self._log("error", f"Could not reach Discord ({exc})", "", None)
                return False
        return False

    def _log(self, level: str, title: str, message: str, target: str | None) -> None:
        line = json.dumps({
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "level": level, "target": target, "title": title, "message": message[:500],
        })
        try:
            log = paths.notify_log()
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            print(line, file=sys.stderr)


def _retry_after(exc: urllib.error.HTTPError) -> float:
    try:
        data = json.loads(exc.read(1000).decode())
        return min(float(data.get("retry_after", 2)), 60.0) + 0.5
    except Exception:
        header = exc.headers.get("retry-after") if exc.headers else None
        try:
            return min(float(header), 60.0) + 0.5 if header else 2.0
        except ValueError:
            return 2.0


def valid_webhook(url: str) -> bool:
    prefixes = (
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/",
        "https://ptb.discord.com/api/webhooks/",
        "https://canary.discord.com/api/webhooks/",
    )
    return url.startswith(prefixes) and len(url) > 60 and " " not in url
