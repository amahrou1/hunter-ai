"""Phase 03, AI: probe and fingerprint, plus port scan for IP scope.

Finds the live HTTP(S) services among the resolved hosts, fingerprints them,
builds each one's 'not found' baseline, scans any in-scope IP/CIDR ranges with
the safe built-in scanner, and re-checks takeover candidates. All through the
scope guard."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase
from .base import Context, PhaseResult


class AIProbePhase(AgentPhase):
    id = "03-probe"
    name = "Probe and fingerprint, per-host baselines, port scan"
    version = "2.0"
    build_step = 4
    requires = ("00-intake", "02-recon")
    role = "prober"
    max_turns = 70
    timeout_minutes = 90

    def task(self, ctx: Context) -> str:
        return (
            "Find and fingerprint the live web services.\n"
            "1. `hk hosts --resolved` for the in-scope resolved hosts. Probe them with httpx "
            "(-json -title -tech-detect -web-server -status-code -content-length -hash sha256 "
            "-ports 80,443,8080,8443 into a file), then `hk import httpx <file>`.\n"
            "2. If the scope has IP or CIDR ranges, run `hk portscan` (it scans only in-scope addresses at "
            "the program's rate, skips firewalls that answer every port, and verifies sensitive services). "
            "Probe the web ports it reports with httpx and import them too.\n"
            "3. `hk baseline` to record each service's 'not found' answer (later fuzzing needs this).\n"
            "4. `hk takeover` to re-check subdomain-takeover candidates.\n"
            "5. Sanity-check: with `hk services` look for the same page repeated on many hosts (a load "
            "balancer default); deprioritise those (`hk priority <host> 10`) and note it.\n"
            "Finish when the live services are fingerprinted and baselined."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        total = store.service_count()
        if total == 0:
            return PhaseResult(st.PARTIAL, "no live web service found yet")
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{total} live service(s); agent did not finish, will continue")
        return PhaseResult(st.DONE, f"{total} live web service(s) fingerprinted")
