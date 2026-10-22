"""hk resolves its target from HUNTER_TARGET_DIR (inside a phase) or, run by
hand, from the current directory if it looks like a target. Regression for
`hk: command not found` + `HUNTER_TARGET_DIR is not set` blocking operator use."""

from __future__ import annotations

import os
import pytest

from hunter.kit import Kit


def test_kit_uses_env_target_dir(tmp_path, monkeypatch):
    (tmp_path / "hunt-output").mkdir()
    monkeypatch.setenv("HUNTER_TARGET_DIR", str(tmp_path))
    monkeypatch.chdir("/")
    k = Kit()
    assert k.target.path == tmp_path
    k.state.close()


def test_kit_falls_back_to_cwd(tmp_path, monkeypatch):
    (tmp_path / "hunt-output").mkdir()
    monkeypatch.delenv("HUNTER_TARGET_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    k = Kit()
    assert k.target.path == tmp_path
    k.state.close()


def test_kit_falls_back_to_parent_of_cwd(tmp_path, monkeypatch):
    (tmp_path / "hunt-output").mkdir()
    sub = tmp_path / "hunt-output"
    monkeypatch.delenv("HUNTER_TARGET_DIR", raising=False)
    monkeypatch.chdir(sub)
    k = Kit()
    assert k.target.path == tmp_path
    k.state.close()


def test_kit_errors_clearly_when_no_target(tmp_path, monkeypatch):
    monkeypatch.delenv("HUNTER_TARGET_DIR", raising=False)
    monkeypatch.chdir(tmp_path)   # no hunt-output/ here
    with pytest.raises(SystemExit) as exc:
        Kit()
    assert "could not find a target" in str(exc.value)
