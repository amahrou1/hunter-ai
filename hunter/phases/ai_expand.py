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
    # Only intake is required. It is ordered after 01-intel so it can use what
    # intel found, but an intel failure must never block recon and the rest.
    requires = ("00-intake",)
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
            MustStep("M2", "Find more in-scope domains the sweep cannot - but ONLY ones the program's scope "
                     "rule covers (for a brand-TLD scope: the SAME brand on other TLDs, NOT other brands even "
                     "under the same parent; for an ownership scope: any owned asset). Use hreflang/country "
                     "links on in-scope pages, crt.sh, reverse-WHOIS. Propose each with `hk candidate add "
                     "<domain> --source <how> --evidence '<json>'`.", "candidates-proposed.txt"),
            MustStep("M3", "For each REVIEW-tier candidate (`hk candidates --tier review`), decide: approve it "
                     "with `hk candidate approve <domain> --reason '<why it is in scope>'` only when you are "
                     "sure it fits the scope rule, else leave it. Code refuses to approve a different-brand "
                     "domain on a brand-TLD program, so do not try."),
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
                lines.append(f"- BRAND-TLD pattern: '{p.get('raw', p['brand'])}' -> the SAME brand "
                             f"**{p['brand']}** on OTHER TLDs. This covers {p['brand']}.de, {p['brand']}.fr, "
                             f"{p['brand']}.hu and so on, PLUS a clear abbreviation of the same brand if the "
                             f"company uses one (e.g. 'as24' for 'autoscout24'). It does NOT cover a DIFFERENT "
                             f"brand, even one the same parent company owns.")
        if own:
            names = ", ".join(own.get("legal_names") or []) or own.get("owner", "")
            lines.append(f"- OWNERSHIP scope: assets owned by {own.get('owner')} "
                         f"(legal names: {names or 'unknown'}). Seeds: "
                         f"{', '.join(own.get('seed_domains') or []) or 'none given'}. Here sibling brands "
                         f"owned by the parent ARE in scope, but code keeps them for your review, never "
                         f"auto-added.")
        scope_kind = "ownership" if own else "brand-TLD"
        lines += [
            "\nCODE has already run a TLD sweep (brand.<common-suffix>), scored each by passive evidence "
            "(shared nameservers, certificate org/SANs, registrant org), and AUTO-ADDED the strong-proof "
            "ones. Run `hk candidates` to see them.\n",
            f"THE SCOPE RULE FOR THIS PROGRAM ({scope_kind}):",
        ]
        if not own:
            lines += [
                "This is a BRAND-TLD scope. The ONLY domains you may propose or approve are the SAME brand "
                f"('{pats[0]['brand'] if pats else ''}') on other TLDs, and a clear abbreviation of it. A "
                "different marketplace/product brand is OUT OF SCOPE even if crt.sh/WHOIS proves the same "
                "parent company (e.g. 'Autonex Gruppe') owns both - common ownership is NOT scope here. Code "
                "will reject a different-brand domain; do not waste turns on them.",
                "So: find the same brand's country sites (hreflang/country switcher links on in-scope pages; "
                "crt.sh for the brand name; the brand on TLDs the sweep did not cover). Propose each with "
                "evidence; code scores it.",
            ]
        else:
            lines += [
                "This is an OWNERSHIP scope, so assets owned by the company ARE in scope including other "
                "brands. Find them: reverse-WHOIS / SecurityTrails by the legal name, crt.sh, brand/footer "
                "maps, the subsidiaries 01-intel recorded. Propose each with ownership evidence. Code "
                "auto-adds same-brand strong proof and keeps sibling brands for your review.",
            ]
        lines += [
            "\nPropose a domain like this:\n"
            "   `hk candidate add <domain> --source <crt.sh|reverse-whois|hreflang|intel> "
            "--evidence '{\"nameservers\":[...],\"cert_org\":\"...\",\"rdap_org\":\"...\",\"cert_sans\":[...],"
            "\"resolves\":true,\"linked_from_scope\":true}'`\n"
            "   CODE scores the evidence and the scope rule, and tells you the tier (auto/review/reject). You "
            "cannot overrule it.",
            "Review the REVIEW-tier candidates (`hk candidates --tier review`): approve only the ones you are "
            "certain belong in scope under the rule above, with a one-line reason; leave the rest. Fetch "
            "in-scope pages for hreflang links through the proxy with curl.",
            "\nParking pages, for-sale domains, and domains whose registrant is a different company are NOT in "
            "scope. When done, write ./handoff.md listing what you added and the strongest evidence for each, "
            "and ./candidates-proposed.txt with one line per domain you proposed and its decided tier.",
        ]
        return "\n".join(lines)

    # ---- code sweep ------------------------------------------------------
    def _code_sweep(self, ctx: Context, store: A.Assets) -> tuple[int, int]:
        """Resolve brand.<suffix> for each pattern, score, record candidates,
        auto-add the strong ones. Returns (candidates_recorded, auto_added)."""
        scope = ctx.scope()
        cfg = (getattr(ctx, "settings", None) or {}).get("scope_expand", {}) or {}
        own = scope.rules.get("ownership_scope") or {}
        auto_mode = expand.auto_mode_for(cfg, bool(own))
        max_auto = int(cfg.get("max_auto_add", 300))
        recorded = auto = 0
        patterns = scope.scope_patterns()
        if not patterns and own:
            # Ownership-only scope: no brand to sweep, but learn the owner
            # context from the seeds so the agent's proposals are scored well.
            owner = expand.seed_owner_context("", own.get("legal_names") or [],
                                              _seed_domains(scope, ""), ownership=True)
            expand.save_owner_context(ctx.state.db, owner)
            ctx.state.db.commit()
        for pat in patterns:
            brand = pat["brand"]
            owner = expand.seed_owner_context(
                brand, own.get("legal_names") or [], _seed_domains(scope, brand), ownership=bool(own))
            expand.save_owner_context(ctx.state.db, owner)
            for domain in expand.candidate_domains(brand):
                if store.candidate(domain) is not None:
                    continue  # already seen (resume)
                ev = expand.resolve_evidence(domain)
                if not ev.get("resolves"):
                    continue  # nothing live on this TLD
                # Certificate-log evidence (passive): names that share a cert
                # with this domain. A cert spanning a known-owned domain is
                # strong proof of the same owner.
                sans = expand.crtsh_names(domain)
                if sans:
                    ev["cert_sans"] = sans
                verdict = expand.decide(domain, ev, owner)
                tier = expand.stored_tier(verdict.tier, auto_mode)
                if tier == "added" and auto >= max_auto:
                    tier = "review"   # cap: anything beyond goes to the agent
                if verdict.tier == expand.DECLINE and not any(
                        s.strength == expand.REJECT for s in verdict.signals):
                    # Live, but no ownership evidence either way yet. Not a
                    # rejection: the agent's job is to investigate these.
                    tier = "unverified"
                store.record_candidate(
                    domain, pattern=brand, source="tld-sweep", tier=tier,
                    subdomains=bool(pat.get("subdomains", True)), evidence=ev,
                    signals=[s.to_dict() for s in verdict.signals], reason=verdict.reason,
                    decided_by="code")
                recorded += 1
                if tier == "added":
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
        if self._handoff_written(ctx) and not self._sweep_pending(ctx, store):
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
            return result
        # A model error or an unfinished agent must not block recon: what code
        # proved is already in scope. Settle DONE and say what happened.
        return PhaseResult(st.DONE, f"{added} domain(s) added to scope; discovery agent: "
                                    f"{result.status.lower()} ({result.summary[:80]})")

    def _handoff_written(self, ctx: Context) -> bool:
        return (self._workdir(ctx) / "handoff.md").exists()

    def outputs_present(self, ctx: Context) -> bool:
        # This phase's real output is the candidates table and scope.json's
        # `expanded` list, not a handoff file. A plain scope finishes with no
        # handoff at all, and discovery that ran out of turns still leaves the
        # code-swept domains in scope. Requiring a handoff here would leave
        # 02-recon BLOCKED "waiting for 01c-expand" on every target (the same
        # trap as the Binance probe->map stall). Discovery is enrichment:
        # recon proceeds with whatever is in scope.
        return True

    def check(self, ctx: Context, store: A.Assets) -> PhaseResult:
        added = self._sync(ctx, store)
        if not self._handoff_written(ctx):
            # Still DONE: only DONE is a settled status, and a PARTIAL here would
            # block recon. The code-swept domains are already in scope; the
            # summary says honestly that the agent's part did not finish.
            return PhaseResult(st.DONE, f"{added} domain(s) added to scope; the discovery agent did not "
                                        f"finish its part (recon proceeds with what is proven)")
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
