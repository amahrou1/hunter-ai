"""06c-jsintel phase: wiring, run-contract, playbook."""

from __future__ import annotations

from hunter import paths
from hunter.phases import all_phases
from hunter.phases.ai_jsintel import JsIntelPhase


class _Ctx:
    secrets: dict = {}


def test_phase_registered_after_js_before_depconf():
    ids = [p.id for p in all_phases()]
    assert "06c-jsintel" in ids
    assert ids.index("06-js") < ids.index("06c-jsintel") < ids.index("06b-depconf")


def test_requires_map():
    assert "04-map" in JsIntelPhase().requires


def test_run_contract_covers_the_high_value_artifacts():
    steps = JsIntelPhase().must_steps(_Ctx())
    arts = {s.artifact for s in steps}
    for want in ("endpoints.txt", "graphql-ops.txt", "auth.md", "hidden.txt",
                 "roles.txt", "secrets.txt", "sinks.txt"):
        assert want in arts, f"missing contract artifact {want}"


def test_task_points_at_the_playbook_and_auth_bypass():
    t = JsIntelPhase().task(_Ctx()).lower()
    assert "hk jsintel" in t                       # reads the playbook
    assert "authorization" in t and "presence" in t  # the auth-presence bypass
    assert "do not exploit" in t                   # it is a mapping phase


def test_playbook_ships_with_run_contract():
    text = (paths.REPO_DIR / "hunter" / "data" / "jsintel_playbook.md").read_text()
    assert "MANDATORY RUN CONTRACT" in text
    assert "endpoints.txt" in text and "auth.md" in text
