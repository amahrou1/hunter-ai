"""Prior-automation mining is scoped per phase: recon/probe/map get a tight
hosts-only hint (so the agent is not pulled off enumeration into reading old
findings); testing phases get the full mining block."""

from __future__ import annotations

from pathlib import Path

from hunter.phases import all_phases
from hunter.phases.ai_recon import AIReconPhase
from hunter.phases.ai_authz import AIAuthzPhase
from hunter.agent_phase import AgentPhase


class _Ctx:
    def __init__(self, prior: Path | None):
        self._prior = prior

    class _T:
        pass

    @property
    def target(self):
        t = _Ctx._T()
        t.prior_dir = lambda: self._prior
        return t


def test_recon_gets_hosts_only_prior_block(tmp_path):
    ctx = _Ctx(tmp_path / "ai_automation")
    block = AIReconPhase()._prior(ctx)
    assert "hosts only" in block.lower()
    assert "hk add host" in block
    # must NOT invite reading findings/notes in recon
    assert "findings" not in block.lower() or "do not read its findings" in block.lower()


def test_testing_phase_gets_full_prior_block(tmp_path):
    ctx = _Ctx(tmp_path / "ai_automation")
    block = AIAuthzPhase()._prior(ctx)
    assert "reference only" in block.lower()
    assert "endpoints" in block.lower()  # full mining


def test_no_prior_dir_means_no_block():
    ctx = _Ctx(None)
    assert AIReconPhase()._prior(ctx) == ""
    assert AIAuthzPhase()._prior(ctx) == ""


def test_recon_probe_map_are_hosts_scoped():
    scoped = {p.id: p.prior_scope for p in all_phases() if isinstance(p, AgentPhase)}
    assert scoped["02-recon"] == "hosts"
    assert scoped["03-probe"] == "hosts"
    assert scoped["04-map"] == "hosts"
    # testing phases keep full
    assert scoped["08-authz-logic"] == "full"
