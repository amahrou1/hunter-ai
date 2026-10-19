"""Starts and stops the scope proxy (mitmdump with hunter/proxy_addon.py)
and gives tools and agents the environment that routes them through it."""

from __future__ import annotations

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import paths

ADDON = Path(__file__).resolve().parent / "proxy_addon.py"
SYSTEM_CA_FILES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")
SELF_TEST_HOST = "hunter-selftest.invalid"


class ProxyError(Exception):
    pass


def mitmdump_bin() -> str | None:
    candidate = Path(sys.executable).parent / "mitmdump"
    if candidate.exists():
        return str(candidate)
    return shutil.which("mitmdump")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _oob_hosts(settings: dict) -> list[str]:
    """Hostnames of the operator's out-of-band infrastructure (callback server,
    blind-XSS collector). Not targets: reachable directly, past the guard."""
    from urllib.parse import urlsplit
    oob = settings.get("oob", {}) or {}
    if not oob.get("enabled", True):
        return []
    hosts = []
    if oob.get("callback_host"):
        hosts.append(str(oob["callback_host"]).lower())
    if oob.get("blind_xss_url"):
        host = urlsplit(str(oob["blind_xss_url"])).hostname
        if host:
            hosts.append(host.lower())
    return hosts


def _ignore_pattern(hosts: list[str]) -> str:
    alternatives = "|".join(re.escape(h) for h in hosts)
    return rf"^(.+\.)?({alternatives})(:\d+)?$"


class ScopeProxy:
    def __init__(self, scope_file: Path, log_dir: Path, settings: dict):
        self.scope_file = scope_file
        self.log_dir = log_dir
        cfg = settings.get("proxy", {})
        self.port = int(cfg.get("port") or 0) or free_port()
        self.passthrough = [h.lower() for h in cfg.get("passthrough", [])]
        for host in _oob_hosts(settings):
            if host not in self.passthrough:
                self.passthrough.append(host)
        self.body_bytes = int(cfg.get("log_body_bytes", 4096))
        self.confdir = paths.config_dir() / "mitmproxy"
        self.process: subprocess.Popen | None = None
        self._log_handle = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ca_cert(self) -> Path:
        return self.confdir / "mitmproxy-ca-cert.pem"

    @property
    def ca_bundle(self) -> Path:
        return paths.config_dir() / "ca-bundle.pem"

    @property
    def traffic_log(self) -> Path:
        return self.log_dir / "traffic.jsonl"

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    # ---------------------------------------------------------------- start
    def start(self, timeout: float = 45.0) -> None:
        if self.running():
            return
        binary = mitmdump_bin()
        if not binary:
            raise ProxyError("mitmproxy is not installed. Run: hunt update")
        if not self.scope_file.exists():
            raise ProxyError(f"No scope file yet ({self.scope_file}). The intake phase must run first.")
        self.confdir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            binary, "--listen-host", "127.0.0.1", "--listen-port", str(self.port),
            "-s", str(ADDON),
            "--set", f"confdir={self.confdir}",
            "--set", f"hunter_scope={self.scope_file}",
            "--set", f"hunter_log={self.traffic_log}",
            "--set", f"hunter_body_bytes={self.body_bytes}",
            "--set", f"hunter_passthrough={','.join(self.passthrough)}",
            # Targets often use self-signed or internal certificates.
            "--set", "ssl_insecure=true",
            "--set", "connection_strategy=lazy",
            "--set", "termlog_verbosity=warn",
            "--set", "flow_detail=0",
        ]
        if self.passthrough:
            cmd += ["--set", f"ignore_hosts={_ignore_pattern(self.passthrough)}"]
        self._log_handle = (self.log_dir / "proxy.log").open("a", encoding="utf-8")
        self.process = subprocess.Popen(cmd, stdout=self._log_handle, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, start_new_session=True)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise ProxyError(f"The scope proxy stopped right after starting. See {self.log_dir / 'proxy.log'}")
            if self._port_open() and self.ca_cert.exists():
                self._build_bundle()
                return
            time.sleep(0.3)
        self.stop()
        raise ProxyError("The scope proxy did not start within 45 seconds.")

    def _port_open(self) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex(("127.0.0.1", self.port)) == 0

    def _build_bundle(self) -> None:
        """System CAs plus the proxy CA, so tools that verify certificates
        accept the proxy without turning verification off."""
        parts = []
        for candidate in SYSTEM_CA_FILES:
            if os.path.exists(candidate):
                parts.append(Path(candidate).read_text(encoding="utf-8", errors="replace"))
                break
        parts.append(self.ca_cert.read_text(encoding="utf-8"))
        self.ca_bundle.write_text("\n".join(parts), encoding="utf-8")

    # ----------------------------------------------------------------- stop
    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                try:
                    os.killpg(self.process.pid, sig)
                except (ProcessLookupError, PermissionError):
                    break
                try:
                    self.process.wait(timeout=wait)
                    break
                except subprocess.TimeoutExpired:
                    continue
        self.process = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None

    # ------------------------------------------------------------------ env
    def env(self, base: dict | None = None) -> dict[str, str]:
        """Environment for anything that talks to targets. Model APIs are in
        NO_PROXY so agents reach their provider directly."""
        env = dict(os.environ if base is None else base)
        # Only infrastructure bypasses the guard. Loopback does NOT: lab
        # targets on this server must be scope-checked and logged too.
        no_proxy = ",".join(self.passthrough)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            env[name] = self.url
        env["NO_PROXY"] = env["no_proxy"] = no_proxy
        bundle = str(self.ca_bundle)
        for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            env[name] = bundle
        env["HUNTER_PROXY"] = self.url
        return env

    # ------------------------------------------------------------ self-test
    def self_test(self) -> tuple[bool, str]:
        """Proves the guard is active without sending anything to the
        internet: a request to a reserved, non-existent host must be
        refused by the proxy itself, over HTTP and over HTTPS (CONNECT)."""
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": self.url, "https": self.url}))
        try:
            opener.open(f"http://{SELF_TEST_HOST}/", timeout=10)
            return False, "an out-of-scope HTTP request was NOT blocked"
        except urllib.error.HTTPError as exc:
            if exc.code != 403 or not exc.headers.get("X-Hunter-Blocked"):
                return False, f"unexpected answer to an out-of-scope HTTP request (HTTP {exc.code})"
        except Exception as exc:
            return False, f"the proxy did not answer ({exc})"
        try:
            opener.open(f"https://{SELF_TEST_HOST}/", timeout=10)
            return False, "an out-of-scope HTTPS request was NOT blocked"
        except urllib.error.URLError as exc:
            if "403" not in str(exc.reason):
                return False, f"unexpected answer to an out-of-scope HTTPS request ({exc.reason})"
        except Exception as exc:
            if "403" not in str(exc):
                return False, f"unexpected answer to an out-of-scope HTTPS request ({exc})"
        return True, "out-of-scope HTTP and HTTPS requests are blocked"

    def __enter__(self) -> "ScopeProxy":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
