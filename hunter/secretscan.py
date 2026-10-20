"""Curated secret detectors (`hk secrets <path>`).

A set of high-signal token patterns - vendor key prefixes and a few structural
forms (JWT, PEM, Google API key) - drawn from the researcher's own dork list.
Scans a file or a directory of files and reports WHICH KIND of secret appears
where, never the value: every hit is masked to its last 4 characters, like the
rest of the kit. Used by the dork phase (over code-search results) and the
jsintel phase (over JS bundles); it does not replace trufflehog/semgrep, it is
the always-available baseline that runs without them installed.

Detection is deliberately conservative on structural patterns to keep false
positives low; prefix tokens are distinctive enough to report directly.
"""

from __future__ import annotations

import re
from pathlib import Path

# (kind, compiled pattern). The pattern's whole match is the token; it is
# masked before display. Prefix tokens use a length bound so a bare prefix in
# prose does not match.
_DETECTORS: list[tuple[str, re.Pattern]] = [
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-oauth", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github-refresh", re.compile(r"\bghr_[A-Za-z0-9]{36}\b")),
    ("gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b")),
    ("gitlab-runner", re.compile(r"\bglrt-[A-Za-z0-9_-]{20}\b")),
    ("openai-proj", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b")),
    ("openai-admin", re.compile(r"\bsk-admin-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("stripe-live", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    ("stripe-test", re.compile(r"\b[rs]k_test_[A-Za-z0-9]{20,}\b")),
    ("stripe-webhook", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b")),
    ("shopify-token", re.compile(r"\bshp(at|ss|pa|ca)_[A-Fa-f0-9]{32}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("postman-key", re.compile(r"\bPMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}\b")),
    ("nvidia-key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{20,}\b")),
    ("grok-key", re.compile(r"\bxai-[A-Za-z0-9]{20,}\b")),
    ("perplexity-key", re.compile(r"\bpplx-[A-Za-z0-9]{20,}\b")),
    ("huggingface", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("notion-token", re.compile(r"\bntn_[A-Za-z0-9]{40,}\b")),
    ("grafana-token", re.compile(r"\bglsa_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("twilio-sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    # A security-placeholder package version (dependency-confusion signal).
    ("npm-security-hold", re.compile(r"\b0\.0\.1-security\b")),
]

# Files worth scanning by extension; others are skipped to stay fast.
_SCANNABLE = {".js", ".mjs", ".cjs", ".ts", ".json", ".map", ".txt", ".env",
              ".yml", ".yaml", ".config", ".cfg", ".ini", ".properties", ".py",
              ".rb", ".php", ".html", ".xml", ".pem", ".key", ".md", ""}
_MAX_FILE = 5_000_000  # skip very large files


def _mask(token: str) -> str:
    token = token.strip()
    if len(token) <= 8:
        return token[:2] + "****"
    return token[:4] + "****" + token[-4:]


def scan_text(text: str) -> list[tuple[str, str]]:
    """Return (kind, masked_token) hits, de-duplicated per (kind, token)."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for kind, pattern in _DETECTORS:
        for m in pattern.finditer(text):
            tok = m.group(0)
            key = (kind, tok)
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, _mask(tok)))
    return out


def scan_file(path: Path) -> list[tuple[str, str]]:
    try:
        if path.stat().st_size > _MAX_FILE:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_text(text)


def scan_path(root: Path) -> list[dict]:
    """Scan a file or a directory tree. Returns one entry per file with hits:
    {"file": <relpath>, "hits": [{"kind":, "masked":}, ...]}."""
    results: list[dict] = []
    files: list[Path]
    if root.is_dir():
        files = [p for p in root.rglob("*")
                 if p.is_file() and p.suffix.lower() in _SCANNABLE]
    elif root.is_file():
        files = [root]
    else:
        return results
    for f in files:
        hits = scan_file(f)
        if hits:
            rel = str(f.relative_to(root)) if root.is_dir() else f.name
            results.append({"file": rel,
                            "hits": [{"kind": k, "masked": v} for k, v in hits]})
    return results
