"""Phase 01c, AI-assisted: expand the scope.

For a 'brand on any TLD' pattern (*.autoscout24.*) or an 'all assets owned by
X' scope, this phase discovers the real domains and adds the ones whose
ownership is proven - so later phases test the whole surface without the
researcher finding TLDs by hand.

Split, same as clustering:
- CODE does the deterministic sweep (resolve brand.<suffix> for the common
  TLDs, gather passive evidence, score with hunter/expand.py) and AUTO-ADDS the
  strong-proof domains. No judgement, fully reproducible.
- The AI does the creative discovery that code cannot: reverse-WHOIS and
  passive-source searches with the researcher's keys, reading country-site
  links (hreflang) on pages already in scope, following subsidiaries/brands
  that 01-intel found. It proposes every candidate with `hk candidate add`;
  CODE scores each one and only CODE auto-adds. The agent may `hk candidate
  approve` a review-tier candidate (partial proof) with a reason, never one
  code rejected.

On a plain scope (no pattern, no ownership clause) there is nothing to expand,
so the phase finishes instantly without spending a model call.
"""

from __future__ import annotations

from .. import assets as A
from .. import expand
from .. import scope as sc
from .. import state as st
from ..agent_phase import AgentPhase, MustStep
from .base import Context, PhaseResult


class ScopeExpandPhase(AgentPhase):
    id = "01c-expand"
    name = "Scope expansion: discover and prove owned domains/TLDs"
    version = "1.0"
    build_step = 5
    requires = ("00-intake", "01-intel")
    role = "scanner"
    prior_scope = "hosts"
    max_turns = 80
    timeout_minutes = 60

    # ---- is there anything to expand? -----------------------------------
    def _active(self, ctx: Context) -> bool:
        scope = ctx.scope()
        return bool(scope.scope_patterns() or scope.rules.get("ownership_scope"))

    def must_steps(self, ctx: Context) -> list[MustStep]:
        return [
            MustStep("M1", "Review the code-swept candidates: `hk candidates` shows what the TLD sweep already "
                     "found and scored. The strong-proof ones are already added."),
            MustStep("M2", "Find more owned domains the sweep cannot: reverse-WHOIS / SecurityTrails / crt.sh "
                     "by the owner's legal name, country-site links (hreflang) on in-scope pages, and the "
                     "subsidiaries/brands 01-intel noted. Propose each with `hk candidate add <domain> "
                     "--source <how> --evidence '<json>'`.", "candidates-proposed.txt"),
            MustStep("M3", "For each REVIEW-tier candidate (`hk candidates --tier review`), decide: approve it "
                     "with `hk candidate approve <domain> --reason '<why it is clearly the owner>'` only when "
                     "you are sure, else leave it. Never approve something with no real ownership evidence."),
        ]

    def task(self, ctx: Context) -> str:
        scope = ctx.scope()
        pats = scope.scope_patterns()
        own = scope.rules.get("ownership_scope") or {}
        lines = [
            "Discover the domains this program's scope really covers and prove which belong to the owner, so "
            "the next phases test the whole surface. You only DISCOVER and PROVE ownership here - you do not "
            "test anything, and you do not add domains to scope yourself; `hk candidate` records your "
            "proposals and CODE decides what is added.\n",
            "What the scope says:",
        ]
        if pats:
            for p in pats:
                lines.append(f"- brand pattern: '{p.get('raw', p['brand'])}' -> the brand "
                             f"**{p['brand']}** on any TLD it operates on.")
        if own:
            names = ", ".join(own.get("legal_names") or []) or own.get("owner", "")
            lines.append(f"- ownership scope: assets owned by {own.get('owner')} "
                         f"(legal names: {names or 'unknown'}). Seeds: "
                         f"{', '.join(own.get('seed_domains') or []) or 'none given'}.")
        lines += [
            "\nCODE has already run a TLD sweep (brand.<common-suffix>), scored each by passive evidence "
            "(shared nameservers, certificate org/SANs, registrant org), and AUTO-ADDED the strong-proof "
            "ones. Run `hk candidates` to see them.\n",
            "Your job is the creative discovery code cannot do:",
            "1. Owned domains on unusual TLDs or different names: search crt.sh for the owner's legal name, "
            "use SecurityTrails / VirusTotal / reverse-WHOIS with the keys in the environment, and read "
            "country/locale links (hreflang, language/country switchers) on pages ALREADY in scope (fetch "
            "those through the proxy with curl). Follow the subsidiaries and brands 01-intel recorded.",
            "2. For every domain you find, gather what proves it belongs to the owner - its nameservers, the "
            "organisation on its TLS certificate, its WHOIS/RDAP registrant - and propose it:\n"
            "   `hk candidate add <domain> --source <crt.sh|reverse-whois|hreflang|intel> "
            "--evidence '{\"nameservers\":[...],\"cert_org\":\"...\",\"rdap_org\":\"...\",\"cert_sans\":[...],"
            "\"resolves\":true,\"linked_from_scope\":true}'`\n"
            "   CODE scores the evidence and tells you the tier (auto/review/reject). You cannot overrule it.",
            "3. Review the REVIEW-tier candidates (`hk candidates --tier review`): approve only the ones you "
            "are certain are the owner's, with a one-line reason; leave the rest. Never approve a domain with "
            "no real ownership evidence - a shared Cloudflare IP or a similar name is NOT proof.",
            "\nParking pages, for-sale domains, and domains whose registrant is a different company are NOT in "
            "scope - do not propose them (code rejects them anyway). When done, write ./handoff.md listing "
            "what you added and the strongest evidence for each.",
            "Also write ./candidates-proposed.txt with one line per domain you proposed and its decided tier.",
        ]
        return "\n".join(lines)

    # ---- code sweep ------------------------------------------------------
    def _code_sweep(self, ctx: Context, store: A.Assets) -> tuple[int, int]:
        """Resolve brand.<suffix> for each pattern, score, record candidates,
        auto-add the strong ones. Returns (candidates_recorded, auto_added)."""
        scope = ctx.scope()
        recorded = auto = 0
        for pat in scope.scope_patterns():
            brand = pat["brand"]
            owner = expand.seed_owner_context(
                brand,
                (scope.rules.get("ownership_scope") or {}).get("legal_names") or [],
                _seed_domains(scope, brand),
                ownership=bool(scope.rules.get("ownership_scope")))
            for domain in expand.candidate_domains(brand):
                if store.candidate(domain) is not None:
                    continue  # already seen (resume)
                ev = expand.resolve_evidence(domain)
                if not ev.get("resolves"):
                    continue  # nothing live on this TLD
                verdict = expand.decide(domain, ev, owner)
                tier = "added" if verdict.tier == expand.AUTO else verdict.tier
                store.record_candidate(
                    domain, pattern=brand, source="tld-sweep", tier=tier,
                    subdomains=bool(pat.get("subdomains", True)), evidence=ev,
                    signals=[s.to_dict() for s in verdict.signals], reason=verdict.reason,
                    decided_by="code")
                recorded += 1
                if verdict.tier == expand.AUTO:
                    auto += 1
            ctx.state.db.commit()
        return recorded, auto

    def _sync(self, ctx: Context, store: A.Assets) -> int:
        scope = ctx.scope()
        return expand.sync_scope_expanded(store, scope, ctx.target.scope_file, sc.save)

    def _sweep_pending(self, ctx: Context, store: A.Assets) -> bool:
        """True on the very first run (no tld-sweep candidate recorded yet).
        After that the sweep is done and a re-run only needs to sync."""
        return not any(r["source"] == "tld-sweep" for r in store.candidates())

    # ---- run -------------------------------------------------------------
    def run(self, ctx: Context) -> PhaseResult:
        store = ctx.assets()
        if not self._active(ctx):
            return PhaseResult(st.DONE, "scope is explicit; nothing to expand")
        # A re-run triggered only by new candidates from a later phase (recon/
        # jsintel) just needs the sync - the discovery agent already ran. Don't
        # spend another model call: sync and finish.
        if self.outputs_present(ctx) and not self._sweep_pending(ctx, store):
            added = self._sync(ctx, store)
            ctx.log(f"01c-expand re-sync: {added} domain(s) in scope after new candidates")
            return PhaseResult(st.DONE, f"{added} domain(s) added to scope by discovery")
        ctx.progress(f"{self.name}: TLD sweep", None, None)
        recorded, auto = self._code_sweep(ctx, store)
        added = self._sync(ctx, store)
        ctx.log(f"01c-expand: code sweep recorded {recorded} candidate(s), auto-added {auto}; "
                f"{added} now in scope")
        # Now let the AI do the creative discovery and review the rest.
        result = super().run(ctx)
        # Re-sync after the agent approved/added more.
        added = self._sync(ctx, store)
        if result.status == st.DONE:
            return PhaseResult(st.DONE, f"{added} domain(s) added to scope by discovery")
        return result

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        added = self._sync(ctx, store)
        if not self.outputs_present(ctx):
            return PhaseResult(st.PARTIAL, f"discovery incomplete; {added} added so far, agent will continue")
        return PhaseResult(st.DONE, f"{added} domain(s) added to scope by discovery")

    def needs_rerun(self, ctx: Context, store) -> bool:
        """Re-open when a later phase (recon, jsintel) proposed new candidates
        that are approved/added but not yet reflected in scope.expanded, so the
        discovery sync runs again and recon re-opens for the new roots. Cheap:
        compares admitted candidates against what is already in scope."""
        try:
            scope = ctx.scope()
        except Exception:  # noqa: BLE001
            return False
        in_scope = {a.host for a in (*scope.in_scope, *scope.expanded) if a.host}
        for row in store.candidates():
            if row["tier"] in expand.ADMITTED_TIERS and row["domain"] not in in_scope:
                return True
        return False


def _seed_domains(scope: sc.Scope, brand: str) -> set[str]:
    seeds = set((scope.rules.get("ownership_scope") or {}).get("seed_domains") or [])
    for a in scope.in_scope:
        if a.host and (brand in a.host) and a.kind in ("domain", "wildcard"):
            seeds.add(a.host)
    return seeds
