"""Dependency-confusion phase: task wiring and the playbook."""

from __future__ import annotations

from hunter import paths
from hunter.phases.ai_depconf import DepConfusionPhase


class _Ctx:
    def __init__(self, secrets):
        self.secrets = secrets


def test_task_covers_the_method_and_forbids_publishing():
    t = DepConfusionPhase().task(_Ctx({"GITHUB_TOKEN": "x"})).lower()
    assert "dependency confusion" in t
    assert "registry" in t and "unclaimed" in t      # the core cross-reference
    assert "do not publish" in t                      # the exploit step stays manual
    assert "hk depconf" in t                          # reads the playbook


def test_task_still_works_without_a_github_token():
    t = DepConfusionPhase().task(_Ctx({})).lower()
    assert "javascript" in t and "no github token" in t


def test_playbook_file_ships():
    assert (paths.REPO_DIR / "hunter" / "data" / "depconf_playbook.md").is_file()
