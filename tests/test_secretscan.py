"""Curated secret detectors: finds high-signal tokens, masks the value, keeps
the kind; false-positive-resistant on prose."""

from __future__ import annotations

from hunter import secretscan


def test_detects_common_vendor_tokens():
    text = (
        "const gh = 'ghp_" + "A" * 36 + "';\n"
        "aws = 'AKIA" + "B" * 16 + "'\n"
        "google = 'AIza" + "C" * 35 + "'\n"
        "stripe = 'sk_live_" + "d" * 24 + "'\n"
        "npm_" + "e" * 36 + "\n"
    )
    hits = dict(secretscan.scan_text(text))
    kinds = set(hits)
    assert "github-pat" in kinds
    assert "aws-access-key" in kinds
    assert "google-api-key" in kinds
    assert "stripe-live" in kinds
    assert "npm-token" in kinds


def test_values_are_masked_never_full():
    token = "ghp_" + "Z" * 36
    hits = secretscan.scan_text(f"key={token}")
    assert len(hits) == 1
    _, masked = hits[0]
    assert token not in masked          # never the full value
    assert masked.startswith("ghp_")    # first 4 kept
    assert "****" in masked


def test_jwt_and_private_key():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghiJKL"
    pem = "-----BEGIN RSA PRIVATE KEY-----"
    kinds = {k for k, _ in secretscan.scan_text(jwt + "\n" + pem)}
    assert "jwt" in kinds
    assert "private-key" in kinds


def test_security_hold_is_flagged():
    kinds = {k for k, _ in secretscan.scan_text('"version": "0.0.1-security"')}
    assert "npm-security-hold" in kinds


def test_prose_does_not_false_positive():
    # bare prefixes in prose must not match (length bounds protect us)
    text = "We use ghp_ tokens and sk- keys and AIza prefixes in general."
    assert secretscan.scan_text(text) == []


def test_scan_path_over_a_directory(tmp_path):
    (tmp_path / "app.js").write_text("token = 'ghp_" + "A" * 36 + "'")
    (tmp_path / "readme.md").write_text("no secrets here")
    (tmp_path / "pic.png").write_bytes(b"\x89PNG not scanned")
    results = secretscan.scan_path(tmp_path)
    files = {r["file"] for r in results}
    assert "app.js" in files
    assert "readme.md" not in files      # no hit
    assert all("pic.png" not in f for f in files)  # wrong extension, skipped


def test_dedup_same_token():
    token = "ghp_" + "Q" * 36
    hits = secretscan.scan_text(f"{token} ... again {token}")
    assert len(hits) == 1
