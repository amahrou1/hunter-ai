"""The MANDATORY RUN CONTRACT: every real testing phase front-loads its must-run
steps as a checklist, and the framework can verify the named artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunter import runcontract
from hunter.runcontract import MustStep, render_contract, artifacts_present
from hunter.phases import all_phases
from hunter.agent_phase import AgentPhase


def test_render_contract_is_a_checklist_with_the_contract_language():
    steps = [MustStep("M1", "do the first thing", "a.txt"),
             MustStep("M2", "do the second thing")]
    out = render_contract(steps)
    assert "MANDATORY RUN CONTRACT" in out
    assert "non-optional" in out
    assert "FAILURE" in out                 # summarising instead of producing = failure
    assert "ZERO unchecked boxes" in out
    assert "- [ ] M1: do the first thing  -> artifact: `a.txt`" in out
    assert "- [ ] M2: do the second thing" in out


def test_render_contract_empty_when_no_steps():
    assert render_contract([]) == ""


def test_artifacts_present_reports_missing_and_empty(tmp_path):
    (tmp_path / "there.txt").write_text("content")
    (tmp_path / "empty.txt").write_text("")
    steps = [MustStep("M1", "x", "there.txt"),
             MustStep("M2", "y", "empty.txt"),
             MustStep("M3", "z", "missing.txt"),
             MustStep("M4", "no artifact")]       # not checked
    missing = artifacts_present(tmp_path, steps)
    assert "there.txt" not in missing
    assert "empty.txt" in missing
    assert "missing.txt" in missing
    assert len(missing) == 2


def test_contract_header_is_front_loaded_in_the_full_task():
    """The checklist must be the FIRST thing in the task an agent reads."""
    phase = _first_phase_with_steps()
    full = phase._full_task(_NullCtx())
    assert full.startswith("== MANDATORY RUN CONTRACT")
    # the first MUST step appears early (within the first ~15 lines)
    lines = full.splitlines()
    first_must = next(i for i, l in enumerate(lines) if "] M1:" in l or "] M" in l)
    assert first_must < 15


def test_every_agent_phase_has_a_contract():
    """EVERY AI-driven phase - recon, mapping, discovery, testing, and the
    validate/disprove/report tail - must define a MANDATORY RUN CONTRACT. Only
    the non-agent intake phase is exempt (it is not an AgentPhase)."""
    agent_phases = [p for p in all_phases() if isinstance(p, AgentPhase)]
    assert len(agent_phases) >= 17, "expected ~all phases to be agent-driven"
    for phase in agent_phases:
        steps = phase.must_steps(_NullCtx())
        assert steps, f"{phase.id} has no MANDATORY RUN CONTRACT steps"
        ids = [s.id for s in steps]
        assert len(ids) == len(set(ids)), f"{phase.id} has duplicate step ids"
        assert all(s.text for s in steps), f"{phase.id} has an empty step"


class _NullCtx:
    secrets: dict = {}

    def scope(self):
        class _S:
            rules: dict = {}
        return _S()


def _first_phase_with_steps():
    for phase in all_phases():
        if isinstance(phase, AgentPhase) and phase.must_steps(_NullCtx()):
            return phase
    raise AssertionError("no phase defines must_steps")


def _phase_ids_with_steps():
    return [p.id for p in all_phases()
            if isinstance(p, AgentPhase) and p.must_steps(_NullCtx())]
