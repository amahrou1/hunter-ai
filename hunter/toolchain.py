"""Install and locate the external recon/web tools.

Tools are downloaded as released binaries into ~/.local/share/hunter-ai/tools
(no compiler, no sudo, low memory). Each tool has a pinned fallback version;
at install time we try the latest GitHub release first and fall back to the
pin if the API is unreachable. Checksums published by the vendor are verified
when available.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import paths


def tools_dir() -> Path:
    override = os.environ.get("HUNTER_TOOLS_DIR")
    base = Path(override) if override else paths.home() / ".local" / "share" / "hunter-ai" / "tools"
    return base


def _arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


@dataclass
class Tool:
    name: str
    repo: str                  # GitHub owner/repo
    pinned: str                # fallback version tag without leading v
    asset: str                 # filename template; {v}=version {os} {arch}
    archive: str = "zip"       # zip | tar.gz | raw
    binary: str = ""           # name inside the archive (default: tool name)
    purpose: str = ""

    def binary_name(self) -> str:
        return self.binary or self.name


# ProjectDiscovery tools share a naming scheme. ffuf uses tar.gz.
TOOLS: list[Tool] = [
    Tool("subfinder", "projectdiscovery/subfinder", "2.6.6",
         "subfinder_{v}_{os}_{arch}.zip", purpose="passive subdomain discovery"),
    Tool("dnsx", "projectdiscovery/dnsx", "1.2.1",
         "dnsx_{v}_{os}_{arch}.zip", purpose="DNS resolution and probing"),
    Tool("httpx", "projectdiscovery/httpx", "1.6.9",
         "httpx_{v}_{os}_{arch}.zip", purpose="HTTP probing and fingerprinting"),
    Tool("naabu", "projectdiscovery/naabu", "2.3.3",
         "naabu_{v}_{os}_{arch}.zip", purpose="port scanning (only where policy allows)"),
    Tool("katana", "projectdiscovery/katana", "1.1.2",
         "katana_{v}_{os}_{arch}.zip", purpose="crawling"),
    Tool("ffuf", "ffuf/ffuf", "2.1.0",
         "ffuf_{v}_{os}_{arch}.tar.gz", archive="tar.gz", purpose="content and parameter discovery"),
]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}


@dataclass
class ToolResult:
    name: str
    ok: bool
    version: str = ""
    message: str = ""
    path: str = ""


@dataclass
class InstallReport:
    results: list[ToolResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results)


def installed_path(tool: Tool) -> Path | None:
    """Our managed copy first, then anything already on PATH."""
    managed = tools_dir() / tool.binary_name()
    if managed.exists() and os.access(managed, os.X_OK):
        return managed
    found = shutil.which(tool.binary_name())
    return Path(found) if found else None


def tool_version(path: Path, name: str) -> str:
    for args in (["-version"], ["--version"], ["-V"]):
        try:
            proc = subprocess.run([str(path), *args], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = (proc.stdout + proc.stderr).strip()
        if text:
            import re
            match = re.search(r"\d+\.\d+\.\d+", text)
            return match.group(0) if match else text.splitlines()[0][:40]
    return "unknown"


def _get(url: str, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "hunter-ai-installer"})
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def latest_version(tool: Tool) -> str:
    try:
        data = json.loads(_get(f"https://api.github.com/repos/{tool.repo}/releases/latest", timeout=30))
        tag = str(data.get("tag_name", "")).lstrip("v")
        return tag or tool.pinned
    except Exception:
        return tool.pinned


def _extract(blob: bytes, tool: Tool, dest: Path) -> None:
    target = dest / tool.binary_name()
    if tool.archive == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            member = _pick_member(archive.namelist(), tool.binary_name())
            with archive.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
    elif tool.archive == "tar.gz":
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            names = archive.getnames()
            member = _pick_member(names, tool.binary_name())
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError("binary not found in archive")
            with target.open("wb") as out:
                shutil.copyfileobj(extracted, out)
    else:  # raw binary
        target.write_bytes(blob)
    target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)


def _pick_member(names: list[str], binary: str) -> str:
    for name in names:
        if name == binary or name.endswith("/" + binary):
            return name
    for name in names:
        base = name.rsplit("/", 1)[-1]
        if base == binary or base.startswith(binary):
            return name
    raise RuntimeError(f"'{binary}' not found in archive (has: {', '.join(names[:5])})")


def _verify_checksum(blob: bytes, tool: Tool, version: str, asset: str) -> bool | None:
    """Return True/False if a checksum file is available, None if not."""
    for suffix in ("checksums.txt", f"{tool.name}_{version}_checksums.txt"):
        url = f"https://github.com/{tool.repo}/releases/download/v{version}/{suffix}"
        try:
            text = _get(url, timeout=30).decode("utf-8", "replace")
        except Exception:
            continue
        digest = hashlib.sha256(blob).hexdigest()
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*").endswith(asset):
                return parts[0].lower() == digest
    return None


def install_tool(tool: Tool, dest: Path, prefer_latest: bool = True) -> ToolResult:
    version = latest_version(tool) if prefer_latest else tool.pinned
    for candidate in (version, tool.pinned):
        asset = tool.asset.format(v=candidate, os="linux", arch=_arch())
        url = f"https://github.com/{tool.repo}/releases/download/v{candidate}/{asset}"
        try:
            blob = _get(url, timeout=180)
        except Exception as exc:
            last = f"download failed ({exc})"
            continue
        checksum = _verify_checksum(blob, tool, candidate, asset)
        if checksum is False:
            return ToolResult(tool.name, False, candidate, "checksum did not match (download rejected)")
        try:
            dest.mkdir(parents=True, exist_ok=True)
            _extract(blob, tool, dest)
        except Exception as exc:
            return ToolResult(tool.name, False, candidate, f"could not unpack ({exc})")
        path = dest / tool.binary_name()
        verified = " (checksum verified)" if checksum else ""
        return ToolResult(tool.name, True, tool_version(path, tool.name),
                          f"installed{verified}", str(path))
    return ToolResult(tool.name, False, "", last if "last" in dir() else "no release found")


def install_all(only: list[str] | None = None, prefer_latest: bool = True,
                force: bool = False, out=print) -> InstallReport:
    dest = tools_dir()
    report = InstallReport()
    wanted = [TOOLS_BY_NAME[n] for n in only] if only else TOOLS
    for tool in wanted:
        existing = installed_path(tool)
        if existing and not force and str(existing).startswith(str(dest)):
            report.results.append(ToolResult(tool.name, True, tool_version(existing, tool.name),
                                              "already installed", str(existing)))
            out(f"  {tool.name}: already installed")
            continue
        out(f"  {tool.name}: downloading ...")
        result = install_tool(tool, dest, prefer_latest)
        report.results.append(result)
        out(f"  {tool.name}: {result.message}" + (f" ({result.version})" if result.version else ""))
    _write_env_hint(dest)
    return report


def _write_env_hint(dest: Path) -> None:
    """Add the tools dir to PATH in .bashrc so the operator can run the
    tools by hand too."""
    bashrc = paths.home() / ".bashrc"
    marker = "hunter-ai: tools PATH"
    try:
        content = bashrc.read_text(encoding="utf-8") if bashrc.exists() else ""
        if marker not in content:
            with bashrc.open("a", encoding="utf-8") as handle:
                handle.write(f'\n# {marker}\nexport PATH="{dest}:$PATH"\n')
    except OSError:
        pass


def status(out=print) -> bool:
    all_ok = True
    for tool in TOOLS:
        path = installed_path(tool)
        if path:
            out(f"  {tool.name:<10} {tool_version(path, tool.name):<12} {path}")
        else:
            out(f"  {tool.name:<10} MISSING      run: hunt tools install")
            all_ok = False
    return all_ok


def tool_path(name: str) -> Path | None:
    tool = TOOLS_BY_NAME.get(name)
    return installed_path(tool) if tool else None
