"""mitmproxy addon: the scope guard.

Loaded by `mitmdump -s hunter/proxy_addon.py`. For every connection and
request it decides, from scope.json, whether the destination may be
touched. Out-of-scope traffic never leaves the server:
- HTTPS: the CONNECT is answered with 403 before any TLS handshake.
- HTTP: the request is answered locally with 403.
Allowed requests get the policy's required headers and pass through a
global rate limiter. Every request (allowed or blocked) is written to
traffic.jsonl. scope.json is re-read when it changes.

Hosts in `hunter_passthrough` (model APIs, mailbox API) are tunnelled
without scope checks or interception; they are infrastructure, not targets.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mitmproxy import ctx, http  # noqa: E402

from hunter import scope as sc  # noqa: E402

BLOCK_HEADER = "X-Hunter-Blocked"
TEXT_TYPES = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "graphql")


# Sent instead of a library's default User-Agent (Python-urllib, Go, curl...)
# when the program asks for a tag to be appended: bot protection often
# blocks library agents, which would hide the real application.
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/129.0.0.0 Safari/537.36")
_LIBRARY_UA = re.compile(r"python|go-http-client|curl/|wget/|aiohttp|okhttp|java/|libwww|"
                         r"node-fetch|axios|projectdiscovery|nuclei|ffuf|katana|httpx|^\s*$", re.I)


def user_agent(current: str, required: str, mode: str = "append") -> str:
    """The User-Agent to send. mode "exact": the program's value as is.
    mode "append" (default, the usual wording "append <user>@... to your
    User-Agent"): keep the client's browser agent and add the tag once."""
    if mode == "exact":
        return required
    if required.lower() in (current or "").lower():
        return current
    base = current if current and not _LIBRARY_UA.search(current) else BROWSER_UA
    return f"{base} {required}"


class TokenBucket:
    def __init__(self, rate: float):
        self.rate = max(0.05, float(rate))
        self.capacity = max(1.0, self.rate)
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()

    async def take(self) -> None:
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)


class ScopeGuard:
    def __init__(self) -> None:
        self.scope: sc.Scope | None = None
        self.scope_mtime: tuple = ()
        self.bucket: TokenBucket | None = None
        self.passthrough: set[str] = set()
        self.log_handle = None
        self.log_path: Path | None = None
        self.log_bytes = 0            # bytes in the current traffic.jsonl
        self.log_max_bytes = 0        # 0 = no rotation
        self.log_keep = 3             # how many rolled traffic.N.jsonl to keep
        self.blocked = 0
        self.allowed = 0

    # mitmproxy hooks -------------------------------------------------------
    def load(self, loader) -> None:
        loader.add_option("hunter_scope", str, "", "Path to scope.json")
        loader.add_option("hunter_log", str, "", "Path of the traffic.jsonl log")
        loader.add_option("hunter_body_bytes", int, 4096, "Bytes of request/response body to log")
        loader.add_option("hunter_passthrough", str, "", "Comma-separated infrastructure hosts")
        loader.add_option("hunter_log_max_mb", int, 50,
                          "Rotate traffic.jsonl when it passes this many MB (0 = never)")
        loader.add_option("hunter_log_keep", int, 3,
                          "How many rotated traffic.N.jsonl files to keep")

    def configure(self, updated) -> None:
        if "hunter_passthrough" in updated:
            self.passthrough = {h.strip().lower() for h in ctx.options.hunter_passthrough.split(",") if h.strip()}
        if "hunter_scope" in updated:
            self._reload(force=True)
        if "hunter_log_max_mb" in updated:
            self.log_max_bytes = max(0, int(ctx.options.hunter_log_max_mb)) * 1_000_000
        if "hunter_log_keep" in updated:
            self.log_keep = max(1, int(ctx.options.hunter_log_keep))
        if "hunter_log" in updated and ctx.options.hunter_log:
            path = Path(ctx.options.hunter_log)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path = path
            self.log_handle = path.open("a", encoding="utf-8", buffering=1)
            try:
                self.log_bytes = path.stat().st_size
            except OSError:
                self.log_bytes = 0

    def _rotate_log(self) -> None:
        """Roll traffic.jsonl -> traffic.1.jsonl (shifting older rolls up) and
        start a fresh one, dropping the oldest beyond log_keep. Keeps the live
        proxy log bounded during a long run; failures are swallowed so logging
        never disrupts traffic."""
        if self.log_handle is None or self.log_path is None:
            return
        try:
            self.log_handle.close()
        except OSError:
            pass
        base = self.log_path
        try:
            # Drop the oldest, shift the rest up: traffic.2 -> traffic.3, etc.
            oldest = base.with_name(f"{base.stem}.{self.log_keep}{base.suffix}")
            if oldest.exists():
                oldest.unlink()
            for i in range(self.log_keep - 1, 0, -1):
                src = base.with_name(f"{base.stem}.{i}{base.suffix}")
                if src.exists():
                    src.replace(base.with_name(f"{base.stem}.{i + 1}{base.suffix}"))
            if base.exists():
                base.replace(base.with_name(f"{base.stem}.1{base.suffix}"))
        except OSError:
            pass
        try:
            self.log_handle = base.open("a", encoding="utf-8", buffering=1)
            self.log_bytes = 0
        except OSError:
            self.log_handle = None

    def http_connect(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host
        if self._is_passthrough(host):
            return
        scope = self._reload()
        if scope is None or not scope.host_in_scope(host):
            reason = "no scope loaded" if scope is None else "not in scope"
            self._block(flow, reason, connect=True)

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if self._is_passthrough(host):
            flow.metadata["hunter_passthrough"] = True
            return
        scope = self._reload()
        if scope is None:
            self._block(flow, "no scope loaded")
            return
        decision = scope.decide(host, flow.request.path, flow.request.port)
        if not decision.allowed:
            self._block(flow, f"{decision.reason}{': ' + decision.matched if decision.matched else ''}")
            return
        for name, value in scope.required_headers.items():
            if name.lower() == "user-agent":
                flow.request.headers["User-Agent"] = user_agent(
                    flow.request.headers.get("User-Agent", ""), value,
                    scope.rules.get("user_agent_mode") or "append")
            elif name not in flow.request.headers:
                flow.request.headers[name] = value
        if self.bucket is not None:
            await self.bucket.take()
        flow.metadata["hunter_start"] = time.time()
        self.allowed += 1

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("hunter_passthrough") or flow.metadata.get("hunter_logged"):
            return
        self._write(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("hunter_passthrough") or flow.metadata.get("hunter_logged"):
            return
        self._write(flow, error=str(flow.error) if flow.error else "error")

    def done(self) -> None:
        if self.log_handle:
            self.log_handle.close()

    # helpers ---------------------------------------------------------------
    def _is_passthrough(self, host: str) -> bool:
        host = sc.normalize_host(host)
        return any(host == p or host.endswith("." + p) for p in self.passthrough)

    def _reload(self, force: bool = False) -> sc.Scope | None:
        path = ctx.options.hunter_scope
        if not path:
            return self.scope
        try:
            mtime = sc.stamp(Path(path))
        except OSError:
            return self.scope
        if force or mtime != self.scope_mtime:
            try:
                loaded = sc.load(Path(path))
            except Exception as exc:  # keep the last good scope
                ctx.log.error(f"hunter: could not read scope {path}: {exc}")
                return self.scope
            old_rate = self.scope.rate_limit_rps if self.scope else None
            self.scope, self.scope_mtime = loaded, mtime
            if old_rate != loaded.rate_limit_rps or self.bucket is None:
                self.bucket = TokenBucket(loaded.rate_limit_rps)
            ctx.log.info(f"hunter: scope loaded ({len(loaded.in_scope)} in, {len(loaded.out_of_scope)} out, "
                         f"{loaded.rate_limit_rps}/s)")
        return self.scope

    def _block(self, flow: http.HTTPFlow, reason: str, connect: bool = False) -> None:
        body = (f"Blocked by hunter-ai scope guard: {flow.request.pretty_host} ({reason}).\n"
                "This host or path is not in scope for this program.\n").encode()
        flow.response = http.Response.make(403, body, {BLOCK_HEADER: reason, "Content-Type": "text/plain"})
        flow.metadata["hunter_logged"] = True
        self.blocked += 1
        self._write(flow, blocked=reason, connect=connect)

    def _body(self, message) -> str | None:
        limit = int(ctx.options.hunter_body_bytes)
        if message is None or limit <= 0:
            return None
        ctype = (message.headers.get("content-type") or "").lower()
        if ctype and not any(t in ctype for t in TEXT_TYPES):
            return None
        try:
            raw = message.get_content(strict=False) or b""
        except Exception:
            raw = message.raw_content or b""
        return raw[:limit].decode("utf-8", "replace") if raw else None

    def _write(self, flow: http.HTTPFlow, blocked: str | None = None, error: str | None = None,
               connect: bool = False) -> None:
        if self.log_handle is None:
            return
        req, resp = flow.request, flow.response
        started = flow.metadata.get("hunter_start")
        entry = {
            "ts": round(time.time(), 3),
            "id": flow.id,
            "method": "CONNECT" if connect else req.method,
            "url": f"{req.host}:{req.port}" if connect else req.pretty_url,
            "host": req.pretty_host,
            "status": resp.status_code if resp else None,
            "blocked": blocked,
            "error": error,
            "duration_ms": round((time.time() - started) * 1000) if started else None,
            "req_headers": dict(req.headers) if not connect else None,
            "req_body": None if connect else self._body(req),
            "resp_headers": dict(resp.headers) if resp and not blocked else None,
            "resp_len": len(resp.raw_content or b"") if resp and resp.raw_content is not None else None,
            "resp_body": None if blocked else self._body(resp),
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        self.log_handle.write(line)
        self.log_bytes += len(line.encode("utf-8", "replace"))
        if self.log_max_bytes and self.log_bytes >= self.log_max_bytes:
            self._rotate_log()


addons = [ScopeGuard()]
