"""01c-expand inside the REAL orchestrator. Unit tests on the phase alone missed
that a DONE-without-handoff phase leaves its dependents BLOCKED (the same trap
as the Binance probe->map stall). These run the dependency gate for real."""

from __future__ import annotations

import pytest

from hunter import scope as sc
from hunter import state as st
from hunter.phases import Phase, PhaseResult
from hunter.phases.ai_expand import ScopeExpandPhase
from tests.test_orchestrator import _orch


class Intake(Phase):
    id, name, version = "00-intake", "intake", "1"

    def __init__(self, scope):
        self.scope = scope

    def run(self, ctx):
        ctx.target.output.mkdir(parents=True, exist_ok=True)
        sc.save(self.scope, ctx.target.scope_file)
        return PhaseResult(st.DONE, "ok")

    def outputs_present(self, ctx):
        return ctx.target.scope_file.exists()


class Intel(Phase):
    id, name, version = "01-intel", "intel", "1"
    requires = ("00-intake",)

    def __init__(self, status=st.DONE):
        self.status = status

    def run(self, ctx):
        return PhaseResult(self.status, "intel result")


class Recon(Phase):
    id, name, version = "02-recon", "recon", "1"
    requires = ("00-intake", "01c-expand")

    def run(self, ctx):
        return PhaseResult(st.DONE, "ok")


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    monkeypatch.setattr("hunter.phases.base.Context.proxy", lambda self: None, raising=False)


def _statuses(target):
    s = st.State(target.state_db)
    out = {p: s.phase(p)["status"] for p in ("00-intake", "01c-expand", "02-recon")}
    s.close()
    return out


def test_plain_scope_expand_does_not_block_recon(make_target, settings_secrets, notifier):
    t = make_target()
    plain = sc.Scope(in_scope=[sc.parse_asset("*.example.com")])
    _orch(t, settings_secrets, notifier, [Intake(plain), Intel(), ScopeExpandPhase(), Recon()]).run()
    assert _statuses(t) == {"00-intake": st.DONE, "01c-expand": st.DONE, "02-recon": st.DONE}


def test_intel_failure_does_not_block_expand_or_recon(make_target, settings_secrets, notifier):
    t = make_target()
    plain = sc.Scope(in_scope=[sc.parse_asset("*.example.com")])
    _orch(t, settings_secrets, notifier,
          [Intake(plain), Intel(st.FAILED), ScopeExpandPhase(), Recon()]).run()
    got = _statuses(t)
    assert got["01c-expand"] == st.DONE and got["02-recon"] == st.DONE


def test_pattern_scope_agent_failure_still_lets_recon_run(make_target, settings_secrets, notifier,
                                                           monkeypatch):
    """A brand pattern where the discovery agent errors out: the code sweep's
    domains stay in scope and recon still runs."""
    from hunter import expand
    import hunter.agent_phase as ap
    monkeypatch.setattr(expand, "resolve_evidence", lambda d, **k: {"resolves": False})
    monkeypatch.setattr(expand, "seed_owner_context", lambda *a, **k: {
        "brand": "acme", "legal_names": [], "seed_domains": set(), "seed_ns_roots": set(),
        "seed_soa_rnames": set(), "seed_spf_includes": set(), "seed_asns": set(), "is_ownership": False})
    monkeypatch.setattr(ap.AgentPhase, "run", lambda self, ctx: PhaseResult(st.BLOCKED, "model error: x"))
    t = make_target()
    pat = sc.Scope(in_scope=[sc.parse_asset("*.acme.de")],
                   rules={"scope_patterns": [{"brand": "acme", "subdomains": True}]})
    _orch(t, settings_secrets, notifier, [Intake(pat), Intel(), ScopeExpandPhase(), Recon()]).run()
    got = _statuses(t)
    assert got["01c-expand"] == st.DONE and got["02-recon"] == st.DONE
