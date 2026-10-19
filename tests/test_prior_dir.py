"""Reference-only harvesting of a previous automation's output folder:
detected per target, surfaced to every agent, never trusted as results."""

from __future__ import annotations

from hunter.target import Target
from hunter.agent_phase import AgentPhase


def test_prior_dir_detected_case_insensitively(tmp_path):
    (tmp_path / "policy.txt").write_text("x")
    (tmp_path / "AI automation").mkdir()
    (tmp_path / "hunt-output").mkdir()      # must be ignored
    assert Target(tmp_path).prior_dir() == tmp_path / "AI automation"


def test_no_prior_dir(tmp_path):
    (tmp_path / "policy.txt").write_text("x")
    (tmp_path / "hunt-output").mkdir()
    assert Target(tmp_path).prior_dir() is None


class _Ctx:
    def __init__(self, target):
        self.target = target


def test_prior_block_tells_agent_reference_only(tmp_path):
    (tmp_path / "ai-automation").mkdir()
    block = AgentPhase()._prior(_Ctx(Target(tmp_path)))
    low = block.lower()
    assert "reference" in low and "never trust its testing" in low
    assert "re-verified" in low or "reproduce from scratch" in low
    assert str(tmp_path / "ai-automation") in block


def test_prior_block_empty_without_folder(tmp_path):
    (tmp_path / "policy.txt").write_text("x")
    assert AgentPhase()._prior(_Ctx(Target(tmp_path))) == ""
