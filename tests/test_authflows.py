"""07b-authflows phase: wiring, run-contract, playbook, scope boundary."""

from __future__ import annotations

from hunter import paths
from hunter.phases import all_phases
from hunter.phases.ai_authflows import AuthFlowsPhase


class _Ctx:
    secrets: dict = {}


def test_registered_after_accounts_before_report():
    ids = [p.id for p in all_phases()]
    assert "07b-authflows" in ids
    assert ids.index("07-accounts") < ids.index("07b-authflows")
    assert ids.index("07b-authflows") < ids.index("11-validate")


def test_requires_accounts():
    assert "07-accounts" in AuthFlowsPhase().requires


def test_contract_covers_the_auth_flows():
    steps = AuthFlowsPhase().must_steps(_Ctx())
    text = " ".join(s.text.lower() for s in steps)
    assert "registration" in text
    assert "reset" in text
    assert "2fa" in text or "mfa" in text
    assert "oauth" in text


def test_task_is_auth_logic_not_idor():
    t = AuthFlowsPhase().task(_Ctx()).lower()
    assert "hk authflows" in t
    assert "not idor" in t or "not object-level" in t   # explicit scope boundary
    assert "test-credentials.txt" in t                  # uses own accounts


def test_playbook_ships_with_run_contract_and_boundary():
    text = (paths.REPO_DIR / "hunter" / "data" / "authflows_playbook.md").read_text()
    assert "MANDATORY RUN CONTRACT" in text
    low = text.lower()
    assert "not object-level" in low or "not idor" in low
    assert "auth-surface.md" in text
