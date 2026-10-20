"""09b-graphql phase: wiring, run-contract, and the two scope boundaries
(no BOLA here; DoS noted not executed)."""

from __future__ import annotations

from hunter import paths
from hunter.phases import all_phases
from hunter.phases.ai_graphql import GraphQLPhase


class _Ctx:
    secrets: dict = {}


def test_registered_before_validation():
    ids = [p.id for p in all_phases()]
    assert "09b-graphql" in ids
    assert ids.index("09b-graphql") < ids.index("11-validate")


def test_contract_has_introspection_and_csrf():
    text = " ".join(s.text.lower() for s in GraphQLPhase().must_steps(_Ctx()))
    assert "introspection" in text
    assert "csrf" in text
    assert "dos" in text and "never execute" in text


def test_task_states_both_boundaries():
    t = GraphQLPhase().task(_Ctx()).lower()
    assert "hk graphql" in t
    # BOLA deferred
    assert "bola" in t or "per-object" in t
    assert "separate" in t
    # DoS not executed
    assert "never executed" in t or "never execute" in t


def test_playbook_ships_with_boundaries():
    text = (paths.REPO_DIR / "hunter" / "data" / "graphql_playbook.md").read_text().lower()
    assert "mandatory run contract" in text
    assert "bola" in text or "per-object" in text
    assert "exclude dos" in text or "dos" in text
