"""Phase 03, AI: probe and fingerprint, plus port scan for IP scope.

Finds the live HTTP(S) services among the resolved hosts, fingerprints them,
builds each one's 'not found' baseline, scans any in-scope IP/CIDR ranges with
the safe built-in scanner, and re-checks takeover candidates. All through the
scope guard."""

from __future__ import annotations

from .. import assets as A
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class AIProbePhase(AgentPhase):
    id = "03-probe"
    name = "Probe and fingerprint, per-host baselines, port scan"
    version = "2.0"
    build_step = 4
    requires = ("00-intake", "02-recon")
    role = "prober"
    max_turns = 70
    timeout_minutes = 180

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Probe all resolved in-scope hosts in batched httpx runs (-title -tech-detect "
                     "-status-code, scope rate) and `hk import httpx` until `hk hosts --unprobed` is empty."),
            MustStep("M2", "If the scope has IP/CIDR ranges, run `hk portscan` once and httpx-probe the web "
                     "targets it prints."),
            MustStep("M3", "Run `hk baseline` so every service has its not-found answer (later fuzzing needs it)."),
            MustStep("M4", "Re-check takeover candidates with `hk takeover` and HTTP-probe any flagged host."),
            MustStep("M5", "Virtual-host enumeration: for each distinct in-scope IP with a live web "
                     "service, run `hk vhost <ip-url>` to surface internal/staging apps that answer only to "
                     "a specific Host header (few hunters do this - it finds hidden surface)."),
        ]

    def task(self, ctx: Context) -> str:
        return (
            "Find and fingerprint the live web services. Work in BATCHES, not host by host - you have many "
            "hosts and a time budget.\n"
            "1. Get the hosts still to probe: `hk hosts --unprobed > todo.txt` (on a fresh run this is all "
            "resolved in-scope hosts; on a resumed run it is only what is left - the rest are already done, "
            "do not redo them). Only resolved in-scope hosts are listed, so you will not waste time on the "
            "dead name tail.\n"
            "2. Probe them in ONE httpx run, not one call per host: "
            "`httpx -l todo.txt -json -o httpx.jsonl -title -tech-detect -web-server -status-code "
            "-content-length -hash sha256 -ports 80,443,8080,8443 -timeout 10 -rl <scope rate> -nc`. "
            "Then `hk import httpx httpx.jsonl`. Re-run on any remaining unprobed hosts until none are left.\n"
            "3. If the scope has IP or CIDR ranges, run `hk portscan` once (it scans only in-scope addresses "
            "at the program rate, skips firewalls that answer every port, verifies sensitive services). It "
            "prints web targets - probe those with httpx and import them too.\n"
            "4. `hk baseline` to record each service's 'not found' answer (needed by later fuzzing). This is "
            "one pass over all services; let it run.\n"
            "5. `hk takeover` to re-check subdomain-takeover candidates, and HTTP-probe any flagged host to "
            "see if the provider shows an unclaimed page.\n"
            "6. Sanity-check with `hk services`: if the same page repeats on many hosts (a load-balancer "
            "default), deprioritise them (`hk priority <host> 10`) and note it.\n"
            "7. VIRTUAL HOSTS: for each distinct in-scope IP that has a live web service, run "
            "`hk vhost http://<ip>/` (and the https/port variants where relevant). It fuzzes the Host header "
            "with in-scope names and reports any that answer with a DIFFERENT page than the default - those "
            "are internal/staging apps not in DNS. It records each as a vhost lead and only tries in-scope "
            "names, so anything it finds is in scope to test later.\n"
            "Use `hk progress \"probing\" <done> <total> hosts` as you go. Finish when `hk hosts --unprobed` "
            "is empty and baselines are built. Summarise the live services in ./handoff.md."
        )

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        total = store.service_count()
        if total == 0:
            return PhaseResult(st.PARTIAL, "no live web service found yet")
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"{total} live service(s); agent did not finish, will continue")
        parked = self._cluster(ctx, store)
        suffix = f"; collapsed {parked} infra clone(s) to representatives" if parked else ""
        return PhaseResult(st.DONE, f"{total} live web service(s) fingerprinted{suffix}")

    def _cluster(self, ctx: Context, store: A.Assets) -> int:
        """Collapse infrastructure clones (e.g. thousands of per-event microsites
        on one backend) so the testing phases see distinct apps. Deterministic,
        reversible, logged. Returns how many services were parked to priority 0."""
        cfg = ctx.settings.get("cluster", {}) or {}
        if not cfg.get("enabled", True):
            return 0
        from .. import cluster
        services = store.services()  # all services, any priority
        report = cluster.apply(
            store, services,
            min_cluster=int(cfg.get("min_cluster", cluster.DEFAULT_MIN_CLUSTER)),
            keep=int(cfg.get("keep", cluster.DEFAULT_KEEP)))
        if report["parked"]:
            for c in report["clusters"][:10]:
                ctx.log(f"    clone group {c['parent']} ({c['size']} hosts, status "
                        f"{c['status']}): kept {len(c['kept'])}, parked {c['parked_count']}")
                store.set_host_note(c["kept"][0], cluster_note=(
                    f"representative of {c['size']} same-backend hosts under {c['parent']} "
                    f"(parked {c['parked_count']} clones; restore with hk priority '*.{c['parent']}' 50)"))
            ctx.notify("Infrastructure clones collapsed",
                       f"{report['parked']} clone host(s) across {len(report['clusters'])} group(s) "
                       f"parked to representatives, so testing focuses on distinct apps. "
                       f"Largest: {report['clusters'][0]['parent']} "
                       f"({report['clusters'][0]['size']} hosts).", "info")
        return report["parked"]
