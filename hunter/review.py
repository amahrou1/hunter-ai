"""Notice and react: tripwires, an AI reviewer, and AI lead follow-up.

Tools are run by code (predictable, cheap, scope-safe). Code alone cannot
tell when a result is a measurement artefact (a firewall that answers every
port, a site that answers every path with the same page, wildcard DNS, a WAF
block wall) or when a lead deserves a closer look. This module adds judgment
without giving up safety:

- Tripwires: cheap detectors that run on every result set. Clear-cut noise
  is handled in code at once; anything they flag is passed to the reviewer.
- Reviewer: after each tool step (and on a tripwire) an AI reads a compact
  observation of the results and answers two questions: can the data be
  trusted, and what deserves a closer look. It replies with actions from a
  fixed allowlist. Code validates every action (scope, rules) before it is
  applied, records it, and tells the operator on Discord.
- Lead follow-up: an AI examines a lead read-only through the scope guard
  (GET/HEAD only) and reports whether it is real, what it exposes, and new
  endpoints it found. Secret values are masked before anything is stored.

The AI can never widen the scope, raise the request rate or break a program
rule: none of those is an allowed action, and its network access goes
through the guard. When unsure, it keeps data (deprioritise, lead) rather
than deleting it.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import assets as A
from . import state as st

# --------------------------------------------------------------------------
# Tripwires (pure functions)
# --------------------------------------------------------------------------


@dataclass
class Tripwire:
    kind: str
    detail: str
    data: dict = field(default_factory=dict)


def same_response(records: list[dict], min_records: int = 30, share: float = 0.6) -> Tripwire | None:
    """Most results share one (status, length): a catch-all page, not real
    hits. records: dicts with "status" and "length"."""
    if len(records) < min_records:
        return None
    counts = Counter((r.get("status"), r.get("length")) for r in records)
    (status, length), top = counts.most_common(1)[0]
    if top >= share * len(records):
        return Tripwire("same-response", f"{top} of {len(records)} results are HTTP {status} with length "
                        f"{length}: probably one catch-all page", {"status": status, "length": length,
                                                                   "count": top, "total": len(records)})
    return None


def wildcard_dns(resolutions: dict[str, list[str]], min_hosts: int = 50, share: float = 0.5) -> Tripwire | None:
    """Many different names resolve to the same address set: wildcard DNS
    (every made-up name exists), so those names are not real hosts."""
    if len(resolutions) < min_hosts:
        return None
    counts = Counter(tuple(sorted(addrs)) for addrs in resolutions.values() if addrs)
    if not counts:
        return None
    addrs, top = counts.most_common(1)[0]
    if top >= share * len(resolutions):
        return Tripwire("wildcard-dns", f"{top} of {len(resolutions)} names resolve to the same address(es) "
                        f"{', '.join(addrs[:3])}: likely wildcard DNS", {"addresses": list(addrs), "count": top})
    return None


def block_wall(entries: list[dict], min_requests: int = 50, share: float = 0.7) -> Tripwire | None:
    """Most recent answers from targets are 403/429/503: a WAF or rate limit
    is blocking us, so results from this period mean little.
    entries: traffic log lines (host, status)."""
    answers = [e for e in entries if not e.get("blocked") and e.get("status")]
    if len(answers) < min_requests:
        return None
    walled = [e for e in answers if e["status"] in (403, 429, 503)]
    if len(walled) >= share * len(answers):
        hosts = Counter(e.get("host") for e in walled).most_common(3)
        codes = Counter(e["status"] for e in walled).most_common()
        return Tripwire("block-wall", f"{len(walled)} of the last {len(answers)} answers were "
                        f"{', '.join(f'{c}x{n}' for c, n in codes)}: we may be blocked or rate limited",
                        {"hosts": [h for h, _ in hosts], "codes": dict(codes)})
    return None


def recent_traffic(log_path, limit: int = 400) -> list[dict]:
    """Last lines of the guard's traffic log."""
    try:
        with open(log_path, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 400_000))
            lines = handle.read().decode("utf-8", "replace").splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# --------------------------------------------------------------------------
# Secret masking
# --------------------------------------------------------------------------

_SECRETS = [
    re.compile(r"(?i)((?:pass(?:word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)"
               r"[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{4,})"),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{10,}\b"),
    re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b"),
    re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{5,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]


def mask(text: str) -> str:
    """Hide secret values; keep their names so the finding stays readable."""
    text = _SECRETS[0].sub(lambda m: m.group(1) + "****", text or "")
    for pattern in _SECRETS[1:]:
        text = pattern.sub(lambda m: m.group(0)[:4] + "****", text)
    return text


# --------------------------------------------------------------------------
# Reviewer
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phase_id TEXT NOT NULL,
    step TEXT NOT NULL,
    trigger TEXT,
    verdict TEXT,
    assessment TEXT,
    actions TEXT NOT NULL DEFAULT '[]',
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS response_filters (
    host TEXT NOT NULL,              -- a host, or * for every host
    status INTEGER,
    length INTEGER,
    reason TEXT,
    created TEXT NOT NULL,
    UNIQUE (host, status, length)
);
"""

ACTIONS = """Allowed actions (anything else is ignored):
  {"type": "filter_response", "host": "<host or *>", "status": 200, "length": 1234, "reason": "..."}
      results with exactly this status and length on that host are noise (a catch-all page);
      they are removed now and ignored from now on
  {"type": "mark_catch_all", "host": "<ip or host>", "reason": "..."}
      the host answers every port or path the same way; its results are not trusted
  {"type": "deprioritize", "host": "<host>", "reason": "..."}
      test it last (keeps the data; use this when unsure instead of deleting)
  {"type": "focus", "host": "<host>", "reason": "..."}
      test it first in every later phase
  {"type": "add_endpoint", "method": "GET", "url": "<full url>", "reason": "..."}
      a request worth testing that is not in the inventory yet
  {"type": "add_lead", "kind": "<short-kind>", "url": "<url>", "evidence": "...", "reason": "..."}
      something that deserves a closer look later
  {"type": "investigate", "url": "<url of an existing lead>", "reason": "..."}
      ask for a read-only follow-up of that lead now
  {"type": "redo_site", "url": "<service base url>", "reason": "..."}
      search this site for hidden paths again (after a filter_response for it)
  {"type": "note", "text": "..."}
      something the operator should know"""

REVIEW_PROMPT = """You are the quality reviewer inside an automated, authorised bug bounty run.
Step just finished: {step} (phase {phase}).
{trigger_text}
Read ./observation.json. It summarises the results of this step: counts, the most
common status/length groups, samples, and any tripwire that fired.

Answer two questions like an experienced bug bounty hunter would:
1. Can these results be trusted, or are they a measurement artefact? Typical
   artefacts: a firewall or load balancer that accepts every port, a site or
   gateway that answers every path with the same page (soft 404), wildcard DNS,
   a WAF or rate limit answering 403/429, a parked or default page repeated on
   many hosts, a tool that was misconfigured.
2. What in these results deserves a closer look (an unusual host, an API, an
   admin or debug interface, an exposed file, an odd parameter)?

Then write ./review.json, valid JSON only:
{{"verdict": "ok | artefact | mixed",
  "assessment": "two or three plain-English sentences for the operator",
  "actions": [ ... ]}}

{actions}

Rules:
- Only hosts and URLs that appear in observation.json. Never anything else.
- Never propose widening the scope, raising the request rate, logging in,
  brute forcing, or anything the program forbids.
- Prefer keeping data: deprioritize or add_lead when unsure; filter_response or
  mark_catch_all only when the evidence clearly shows noise.
- Do not contact any host. Only read the files here.
- An empty actions list is a fine answer when everything looks normal.
Write the file, then reply DONE."""

FOLLOW_PROMPT = """You are following up one lead inside an authorised bug bounty run.
Lead: {kind} at {url}
What is known: {evidence}

Find out, carefully and read-only, whether this is real and what it exposes.
- Use curl or similar. The environment already routes every request through the
  run's scope guard (out-of-scope hosts are refused); do not change proxy settings.
- Only GET, HEAD or OPTIONS. Never send credentials, never log in, never change
  or delete anything, never brute force. At most 30 requests, at most 1 MB read.
- Typical checks: a Swagger/OpenAPI file -> list its endpoints; .git -> can
  objects be read (do not download the whole repository); an .env or config file
  -> which kinds of secrets it holds (never copy their values); a debug/admin
  page -> what it shows without logging in; an open service -> what it answers.
- Never write a secret value anywhere. Write names and "****" instead.

Write ./lead.json, valid JSON only:
{{"status": "confirmed | dismissed | unclear",
  "evidence": "what you saw, with the exact request(s), secrets masked",
  "impact": "what an attacker could do with it, one or two sentences",
  "endpoints": [{{"method": "GET", "url": "<full url found>"}}],
  "next_steps": ["what a tester should try next"]}}
Then reply DONE."""


@dataclass
class ReviewOutcome:
    verdict: str = "skipped"
    assessment: str = ""
    applied: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    investigate: list[str] = field(default_factory=list)
    redo_sites: list[str] = field(default_factory=list)


class Reviewer:
    """Runs the AI reviewer and applies its actions. Best effort: if the AI
    is unavailable the run continues exactly as before."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.store: A.Assets = ctx.assets()
        ctx.state.db.executescript(SCHEMA)

    # ------------------------------------------------------------- filters
    def filters(self, host: str) -> set[tuple]:
        rows = self.ctx.state.db.execute(
            "SELECT status, length FROM response_filters WHERE host=? OR host='*'", (host,))
        return {(r["status"], r["length"]) for r in rows}

    def add_filter(self, host: str, status, length, reason: str) -> int:
        """Record a noise signature and remove matching results. Returns the
        number of results removed."""
        self.ctx.state.db.execute(
            "INSERT OR IGNORE INTO response_filters(host, status, length, reason, created) VALUES(?,?,?,?,?)",
            (host, status, length, reason[:300], st.now()))
        query = "DELETE FROM endpoints WHERE source='discover' AND status IS ? AND length IS ?"
        params: list = [status, length]
        if host != "*":
            query += " AND host=?"
            params.append(host)
        return self.ctx.state.db.execute(query, params).rowcount

    # -------------------------------------------------------------- review
    def review(self, step: str, observation: dict, trigger: Tripwire | None = None) -> ReviewOutcome:
        ctx = self.ctx
        if not ctx.settings.get("review", {}).get("enabled", True):
            return ReviewOutcome()
        workdir = ctx.phase_dir() / "review" / re.sub(r"[^a-z0-9-]+", "-", step.lower())[:40]
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "review.json").unlink(missing_ok=True)
        if trigger:
            observation = {**observation, "tripwire": {"kind": trigger.kind, "detail": trigger.detail,
                                                       **trigger.data}}
        (workdir / "observation.json").write_text(json.dumps(observation, indent=2, default=str)[:200_000],
                                                  encoding="utf-8")
        trigger_text = f"A tripwire fired: {trigger.detail}" if trigger else ""
        prompt = REVIEW_PROMPT.format(step=step, phase=ctx.phase_id, trigger_text=trigger_text, actions=ACTIONS)
        try:
            result = ctx.agent("reviewer", prompt, name=f"review-{step}", workdir=workdir,
                               max_turns=20, timeout_minutes=15, retries=1)
        except Exception as exc:  # noqa: BLE001 - a review must never break the phase
            if type(exc).__name__ in ("AgentFatalError", "ConfigError"):
                raise
            ctx.log(f"review of {step} skipped: {exc}")
            return ReviewOutcome()
        try:
            data = json.loads((workdir / "review.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            ctx.log(f"review of {step}: no usable answer" + (f" ({result.error})" if result.error else ""))
            return ReviewOutcome()
        outcome = ReviewOutcome(verdict=str(data.get("verdict") or "ok")[:20],
                                assessment=mask(str(data.get("assessment") or ""))[:1500])
        allowed_hosts, allowed_urls = _known(observation)
        for action in (data.get("actions") or [])[:40]:
            if not isinstance(action, dict):
                continue
            ok, text = self._apply(action, allowed_hosts, allowed_urls, outcome)
            (outcome.applied if ok else outcome.rejected).append(text)
        ctx.state.db.execute(
            "INSERT INTO reviews(phase_id, step, trigger, verdict, assessment, actions, created) "
            "VALUES(?,?,?,?,?,?,?)",
            (ctx.phase_id, step, trigger.kind if trigger else None, outcome.verdict, outcome.assessment,
             json.dumps({"applied": outcome.applied, "rejected": outcome.rejected}), st.now()))
        self._tell(step, outcome, trigger)
        return outcome

    def _apply(self, action: dict, hosts: set[str], urls: set[str], outcome: ReviewOutcome) -> tuple[bool, str]:
        ctx, store = self.ctx, self.store
        scope = ctx.scope()
        kind = str(action.get("type") or "")
        reason = mask(str(action.get("reason") or ""))[:200]
        host = str(action.get("host") or "").strip().lower()
        url = str(action.get("url") or "").strip()

        def known_host(h: str) -> bool:
            return h in hosts and scope.host_in_scope(h)

        if kind == "filter_response":
            if host != "*" and not known_host(host):
                return False, f"filter_response {host}: host not in this step's results or not in scope"
            status, length = action.get("status"), action.get("length")
            if not isinstance(status, int) or (length is not None and not isinstance(length, int)):
                return False, "filter_response: status and length must be numbers"
            removed = self.add_filter(host, status, length, reason)
            return True, f"ignore HTTP {status} length {length} on {host} ({removed} result(s) removed): {reason}"
        if kind == "mark_catch_all":
            if not known_host(host):
                return False, f"mark_catch_all {host}: not in this step's results"
            store.set_host_note(host, accepts_all=True, catch_all_reason=reason)
            store.set_priority(host, 5)
            return True, f"{host} answers everything the same way; results not trusted: {reason}"
        if kind == "deprioritize":
            if not known_host(host):
                return False, f"deprioritize {host}: not in this step's results"
            store.set_priority(host, 10)
            return True, f"{host} tested last: {reason}"
        if kind == "focus":
            if not known_host(host):
                return False, f"focus {host}: not in this step's results"
            store.set_priority(host, 95)
            return True, f"{host} tested first: {reason}"
        if kind == "add_endpoint":
            method = str(action.get("method") or "GET").upper()
            if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                return False, f"add_endpoint: bad method {method}"
            if not _url_ok(url, hosts, scope):
                return False, f"add_endpoint {url}: host not in this step's results or not in scope"
            store.add_endpoint(method, url, "review")
            return True, f"new request to test: {method} {url} ({reason})"
        if kind == "add_lead":
            if not _url_ok(url, hosts, scope):
                return False, f"add_lead {url}: not in this step's results or not in scope"
            lead_kind = re.sub(r"[^a-z0-9-]+", "-", str(action.get("kind") or "review").lower())[:30]
            store.add_lead(lead_kind, url, "review", mask(str(action.get("evidence") or reason))[:500])
            return True, f"lead {lead_kind}: {url} ({reason})"
        if kind == "investigate":
            if url not in urls and not _url_ok(url, hosts, scope):
                return False, f"investigate {url}: not a known lead"
            outcome.investigate.append(url)
            return True, f"follow up {url}: {reason}"
        if kind == "redo_site":
            if not _url_ok(url, hosts, scope):
                return False, f"redo_site {url}: not in this step's results"
            outcome.redo_sites.append(url)
            return True, f"search {url} again: {reason}"
        if kind == "note":
            text = mask(str(action.get("text") or ""))[:400]
            return (True, f"note: {text}") if text else (False, "empty note")
        return False, f"unknown action '{kind}' ignored"

    def _tell(self, step: str, outcome: ReviewOutcome, trigger: Tripwire | None) -> None:
        self.ctx.log(f"review {step}: {outcome.verdict}; {len(outcome.applied)} action(s), "
                     f"{len(outcome.rejected)} refused")
        for line in outcome.applied:
            self.ctx.log(f"  review action: {line}")
        for line in outcome.rejected:
            self.ctx.log(f"  review refused: {line}")
        interesting = outcome.verdict != "ok" or outcome.applied or trigger
        if not interesting:
            return
        lines = [outcome.assessment] if outcome.assessment else []
        if trigger:
            lines.insert(0, f"Tripwire: {trigger.detail}")
        if outcome.applied:
            lines.append("What I did:")
            lines += [f"- {a}" for a in outcome.applied[:12]]
        if outcome.rejected:
            lines.append(f"Refused {len(outcome.rejected)} suggestion(s) that broke the rules (see run.log).")
        level = "warn" if outcome.verdict != "ok" else "info"
        self.ctx.notify(f"Reviewed: {step}", "\n".join(lines)[:3500], level)

    # ---------------------------------------------------------- follow-up
    def follow_up(self, lead_urls: list[str] | None = None, limit: int = 15) -> list[str]:
        """Investigate leads read-only. Default: content-confirmed leads not
        followed up yet, plus any URLs asked for explicitly."""
        ctx, store = self.ctx, self.store
        if not ctx.settings.get("review", {}).get("follow_up", True):
            return []
        wanted = set(lead_urls or [])
        rows = [r for r in store.leads()
                if r["status"] in ("signature-match", "unverified") and not r["url"].startswith("tcp://")
                and (r["url"] in wanted or (not wanted and r["status"] == "signature-match"))]
        rows = [r for r in rows if r["status"] != "dismissed"][:limit]
        results = []
        scope = ctx.scope()
        for row in rows:
            if not scope.decide_url(row["url"]).allowed:
                continue
            workdir = ctx.phase_dir() / "followup" / f"lead-{row['id']}"
            workdir.mkdir(parents=True, exist_ok=True)
            (workdir / "lead.json").unlink(missing_ok=True)
            prompt = FOLLOW_PROMPT.format(kind=row["kind"], url=row["url"], evidence=row["evidence"] or "-")
            try:
                ctx.agent("tester", prompt, name=f"followup-{row['id']}", workdir=workdir,
                          max_turns=40, timeout_minutes=20, retries=1)
                data = json.loads((workdir / "lead.json").read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                if type(exc).__name__ in ("AgentFatalError", "ConfigError"):
                    raise
                ctx.log(f"follow-up of {row['url']} gave no answer: {exc}")
                continue
            status = {"confirmed": "ai-confirmed", "dismissed": "dismissed"}.get(str(data.get("status")),
                                                                                 "ai-unclear")
            evidence = mask(f"{data.get('evidence') or ''} | impact: {data.get('impact') or '-'} | "
                            f"next: {'; '.join(map(str, data.get('next_steps') or []))}")[:2000]
            ctx.state.db.execute("UPDATE leads SET status=?, evidence=? WHERE id=?", (status, evidence, row["id"]))
            added = 0
            for ep in (data.get("endpoints") or [])[:200]:
                if not isinstance(ep, dict):
                    continue
                ep_url = str(ep.get("url") or "")
                if ep_url and scope.decide_url(ep_url).allowed:
                    if store.add_endpoint(str(ep.get("method") or "GET").upper()[:7], ep_url, "followup"):
                        added += 1
            line = f"{row['kind']} {row['url']}: {status}" + (f", {added} new endpoint(s)" if added else "")
            ctx.log(f"follow-up: {line}")
            results.append(line + (f" - {mask(str(data.get('impact') or ''))[:160]}" if status == "ai-confirmed"
                                   else ""))
        if results:
            confirmed = [r for r in results if ": ai-confirmed" in r]
            ctx.notify("Leads followed up", "\n".join(f"- {r}" for r in results[:15])
                       + "\n\nConfirmed leads still go through validation before any report.",
                       "warn" if confirmed else "info")
        return results


def _known(observation: dict) -> tuple[set[str], set[str]]:
    """Hosts and URLs that appear anywhere in the observation: the reviewer
    may only act on those."""
    text = json.dumps(observation, default=str)
    urls = set(re.findall(r"(?:https?|tcp)://[^\s\"'<>\\]+", text))
    hosts = {(urlsplit(u).hostname or "").lower() for u in urls if u.startswith("http")}
    hosts |= {u[6:].split(":")[0] for u in urls if u.startswith("tcp://")}
    for key in ("host", "hosts", "address"):
        for match in re.findall(rf'"{key}"\s*:\s*"([^"]+)"', text):
            hosts.add(match.lower())
    for match in re.findall(r'"([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})"', text.lower()):
        hosts.add(match)
    hosts.discard("")
    return hosts, urls


def _url_ok(url: str, hosts: set[str], scope) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return parts.scheme in ("http", "https") and host in hosts and scope.decide_url(url).allowed


def top_groups(rows, key, limit: int = 10) -> list[dict]:
    """[{"value": ..., "count": n}] for the most common values of key(row)."""
    counts = Counter(key(r) for r in rows)
    return [{"value": list(v) if isinstance(v, tuple) else v, "count": n} for v, n in counts.most_common(limit)]
