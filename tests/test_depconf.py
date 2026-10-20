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


def test_task_requires_confirmed_404_not_a_single_lookup():
    # A transient 429/5xx/timeout must not be read as "unclaimed".
    t = DepConfusionPhase().task(_Ctx({})).lower()
    assert "confirmed 404" in t
    assert "unknown" in t and "retry" in t


def test_task_checks_both_scope_endpoints():
    t = DepConfusionPhase().task(_Ctx({})).lower()
    assert "org endpoint" in t and "user endpoint" in t


def test_task_skips_already_held_security_placeholders():
    t = DepConfusionPhase().task(_Ctx({})).lower()
    assert "0.0.1-security" in t and "already held" in t


def test_task_judges_provenance_first_vs_third_party():
    t = DepConfusionPhase().task(_Ctx({})).lower()
    assert "first-party" in t and "third-party" in t
    assert "seller" in t or "integrator" in t          # not a seller/partner widget


def test_task_sets_severity_by_confidence():
    # Unconfirmed candidate -> medium, not high; reachability caveat stated.
    t = DepConfusionPhase().task(_Ctx({})).lower()
    assert "--severity medium" in t
    assert "unconfirmed" in t and "reachability" in t


def test_phase_version_bumped_for_rerun():
    # A version bump makes the orchestrator re-run the phase with the new logic.
    assert DepConfusionPhase().version != "1.0"


def test_playbook_documents_the_hardening():
    text = (paths.REPO_DIR / "hunter" / "data" / "depconf_playbook.md").read_text()
    low = text.lower()
    assert "confirmed 404" in low                       # false-positive guard
    assert "provenance" in low and "third-party" in low  # first/third-party split
    assert "unconfirmed" in low                          # confidence caveat
    assert "already held" in low                         # security-placeholder skip
