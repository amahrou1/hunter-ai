"""Operator instructions for a run: `hunt tell <target> "<message>"`.

The operator can steer a hunt at any time, also while it runs, from any
terminal. Every message is stored in the run database (safe to write from a
second process) and handled in two ways:

1. Clear actions are applied by code, never by an AI guess:
     add <host|ip|url>      put a host in the inventory (scope-checked)
     focus <host|*.root>    test it first in every later phase
     avoid <host|url|*.root> never touch it; the scope guard blocks it live
     skip <phase>           do not run that phase
     unfocus / unavoid / unskip    undo
     forget <number>        stop showing message <number> to the AI
   Plain English works too ("api.bol.com looks juicy, test it harder",
   "please add 10.1.2.3", "skip the javascript phase"): the words are
   matched to the same actions and the interpretation is shown back.

2. The message itself, as written, is given to every later AI session, so
   softer hints ("the login looks weak") still reach the testing agents.

Nothing here can widen the scope: an added or focused host that is not in
scope is refused, and the reason is shown.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import assets as A
from . import scope as sc
from . import state as st
from .target import Target

SCHEMA = """
CREATE TABLE IF NOT EXISTS instructions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT NOT NULL,
    text TEXT NOT NULL,
    actions TEXT NOT NULL DEFAULT '[]',
    withdrawn INTEGER NOT NULL DEFAULT 0,
    seen INTEGER NOT NULL DEFAULT 0
);
"""

# Action outcomes
DONE = "done"
PENDING = "pending"      # waits for something (usually the scope)
REFUSED = "refused"

SKIPPED_SUMMARY = "skipped on your instruction"

COMMANDS = ("add", "focus", "unfocus", "avoid", "unavoid", "skip", "unskip", "note", "forget")

PHASE_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("01-intel", ("intel", "intelligence", "past reports", "disclosed reports")),
    ("01b-dork-github", ("dork", "dorking", "github dork", "github dorking", "leaked secrets")),
    ("02-recon", ("recon", "subdomain enumeration", "subfinder")),
    ("03-probe", ("probe", "probing", "httpx", "fingerprinting")),
    ("04-map", ("map", "mapping", "crawl", "crawling", "crawler", "spider")),
    ("05-discover", ("discover", "discovery", "fuzz", "fuzzing", "directory", "directories",
                     "content discovery", "brute force", "bruteforce")),
    ("06-js", ("js", "javascript")),
    ("06b-depconf", ("depconf", "dependency confusion", "dependency-confusion", "supply chain", "packages")),
    ("07-accounts", ("accounts", "account creation", "registration", "signup", "sign up", "sign-up")),
    ("08-authz-logic", ("authz", "access control", "idor", "bola", "business logic", "logic")),
    ("09-injection", ("injection", "injections", "xss", "sqli", "sql injection", "ssti", "ssrf")),
    ("10-misconfig", ("misconfig", "misconfiguration", "misconfigurations", "cors", "cache")),
    ("10b-skills", ("skills", "skill pass", "skills pass")),
    ("10c-hunt", ("free hunt", "deep hunt", "deephunt", "creative hunt", "chaining")),
)
PROTECTED = {
    "00-intake": "it builds the scope guard; nothing may run without it",
    "11-validate": "skipping it would turn unconfirmed guesses into report drafts",
    "12-disprove": "skipping it would turn unconfirmed guesses into report drafts",
    "13-report": "it writes the report drafts, which are the point of the run",
}

_NEGATIVE = ("skip", "don't", "dont", "do not", "stop", "avoid", "ignore", "never", "exclude",
             "leave out", "no more", "not test", "not touch")
_NOT_NEGATIVE = ("don't forget", "dont forget", "do not forget", "don't miss", "dont miss",
                 "do not miss", "never forget", "don't skip", "dont skip", "do not skip",
                 "don't ignore", "do not ignore")
_UNDO = ("unskip", "un-skip", "unavoid", "un-avoid", "unfocus", "run again", "rerun", "re-run",
         "enable again", "allow again", "test it again", "resume testing", "you can test")
_ADD = ("add", "include", "new host", "new subdomain", "seed", "also test", "found")

_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_CIDR_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}(?![\d.])")
_IP_RE = re.compile(r"(?<![\d./])\d{1,3}(?:\.\d{1,3}){3}(?![\d./])")
_PHASE_ID_RE = re.compile(r"\b(\d{2}[a-z]?-[a-z][a-z-]*)\b")
_PHASE_NUM_RE = re.compile(r"\bphase\s*(\d{1,2})\b")


def _has(text: str, words) -> bool:
    return any(re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", text) for w in words)


# --------------------------------------------------------------------------
# Parsing (pure functions, no I/O)
# --------------------------------------------------------------------------

def extract_targets(text: str) -> list[str]:
    """Hosts, wildcards, IPs, CIDRs and URLs mentioned in a message, in order."""
    found: list[str] = []

    def keep(item: str) -> None:
        item = item.strip().rstrip(".,;:)!?'\"").lower()
        if item and item not in found:
            found.append(item)

    rest = text
    for match in _URL_RE.findall(text):
        keep(match)
        rest = rest.replace(match, " ")
    for match in _CIDR_RE.findall(rest):
        keep(match)
        rest = rest.replace(match, " ")
    for match in _IP_RE.findall(rest):
        try:
            ipaddress.ip_address(match)
        except ValueError:
            continue
        keep(match)
        rest = rest.replace(match, " ")
    for match in sc._MENTION_RE.finditer(rest):
        token = match.group(0)
        if sc._FILE_EXT.search(token.lower()):
            continue
        keep(token)
    return found


def extract_phases(text: str) -> list[str]:
    """Phase ids named in a message (by id, by number, or by a common word)."""
    lower = text.lower()
    # Remove anything host-like so "account.bol.com" does not read as "accounts".
    for token in extract_targets(text):
        lower = lower.replace(token, " ")
    lower = _URL_RE.sub(" ", lower)
    lower = re.sub(r"\S+\.\S+", " ", lower)
    known = [pid for pid, _ in PHASE_WORDS] + list(PROTECTED)
    known_ids = set(known)
    # "phase 6" means the plainly-numbered phase (06-js), never a sub-phase such
    # as 06b-depconf; sub-phases are named by their full id or by a word.
    by_number = {pid[:2]: pid for pid in known if pid[2:3] == "-"}
    found: list[str] = []

    def keep(pid: str) -> None:
        if pid not in found:
            found.append(pid)

    for match in _PHASE_ID_RE.finditer(lower):
        tok = match.group(1)
        if tok in known_ids:                       # full id, incl. 06b-depconf
            keep(tok)
        elif tok[2:3] == "-" and tok[:2] in by_number:   # plain-numbered id
            keep(by_number[tok[:2]])
    for match in _PHASE_NUM_RE.finditer(lower):
        if match.group(1).zfill(2) in by_number:
            keep(by_number[match.group(1).zfill(2)])
    for pid, words in PHASE_WORDS:
        if _has(lower, words):
            keep(pid)
    for pid, label in (("00-intake", ("intake",)), ("11-validate", ("validate", "validation")),
                       ("12-disprove", ("disprove",)), ("13-report", ("report writing", "reporting"))):
        if _has(lower, label):
            keep(pid)
    return found


def parse(text: str) -> list[dict]:
    """Turn a message into actions: [{"kind": ..., "arg": ...}, ...].
    An empty list means: a note for the AI only."""
    stripped = text.strip()
    first, _, rest = stripped.partition(" ")
    command = first.lower().rstrip(":,")
    targets = extract_targets(stripped)
    phases = extract_phases(stripped)

    if command in COMMANDS:
        if command == "note":
            return []
        if command == "forget":
            return [{"kind": "forget", "arg": n} for n in re.findall(r"\d+", rest)]
        if command in ("skip", "unskip"):
            if phases and targets:
                return []  # one phase for one host: a note for the AI only
            if phases:
                return [{"kind": command, "arg": p} for p in phases]
            undo = "unavoid" if command == "unskip" else "avoid"
            return [{"kind": undo, "arg": t} for t in targets]
        return [{"kind": command, "arg": t} for t in targets]

    lower = stripped.lower()
    softened = lower
    for phrase in _NOT_NEGATIVE:
        softened = softened.replace(phrase, " ")
    undo = _has(lower, _UNDO)
    negative = _has(softened, _NEGATIVE) and not undo

    actions: list[dict] = []
    if targets and phases and (negative or undo):
        # "skip the JS phase on api.x.com": one phase for one host is not
        # something the run can do yet. Keep it as a note for the AI.
        return []
    if targets:
        if undo:
            kind = "unavoid"
        elif negative:
            kind = "avoid"
        elif _has(lower, _ADD):
            kind = "add"
        else:
            kind = "focus"
        actions += [{"kind": kind, "arg": t} for t in targets]
    elif phases:
        if undo:
            actions += [{"kind": "unskip", "arg": p} for p in phases]
        elif negative:
            actions += [{"kind": "skip", "arg": p} for p in phases]
    return actions


# --------------------------------------------------------------------------
# Store and apply
# --------------------------------------------------------------------------

@dataclass
class Instruction:
    id: int
    created: str
    text: str
    actions: list[dict] = field(default_factory=list)
    withdrawn: bool = False

    def lines(self) -> list[str]:
        if not self.actions:
            return ["NOTE  no action found in it; the AI sessions will read it as a hint."]
        tag = {DONE: "OK   ", PENDING: "LATER", REFUSED: "NO   "}
        return [f"{tag.get(a.get('status'), '?    ')} {a['kind']} {a['arg']}: {a.get('reply', '')}"
                for a in self.actions]


class Operator:
    """Reads and applies operator instructions for one target. Safe to use
    from `hunt tell` while the run is active in another process."""

    def __init__(self, target: Target, state: st.State):
        self.target = target
        self.state = state
        self.db = state.db
        self.db.executescript(SCHEMA)

    # ---------------------------------------------------------------- store
    def submit(self, text: str) -> Instruction:
        actions = parse(text)
        for action in actions:
            action["status"] = PENDING
            action["reply"] = ""
        cur = self.db.execute("INSERT INTO instructions(created, text, actions) VALUES(?,?,?)",
                              (st.now(), text.strip(), json.dumps(actions)))
        self.state.event("operator_instruction", None, text.strip()[:500])
        instruction = self.get(cur.lastrowid)
        self._apply(instruction)
        return self.get(instruction.id)

    def get(self, instruction_id: int) -> Instruction | None:
        row = self.db.execute("SELECT * FROM instructions WHERE id=?", (instruction_id,)).fetchone()
        return self._row(row) if row else None

    def all(self) -> list[Instruction]:
        return [self._row(r) for r in self.db.execute("SELECT * FROM instructions ORDER BY id")]

    def _row(self, row) -> Instruction:
        return Instruction(row["id"], row["created"], row["text"], json.loads(row["actions"] or "[]"),
                           bool(row["withdrawn"]))

    def _save(self, instruction: Instruction) -> None:
        self.db.execute("UPDATE instructions SET actions=?, withdrawn=? WHERE id=?",
                        (json.dumps(instruction.actions), int(instruction.withdrawn), instruction.id))

    # ------------------------------------------------------- run integration
    def unseen(self) -> list[Instruction]:
        """Messages the run has not logged yet; marks them seen."""
        rows = list(self.db.execute("SELECT * FROM instructions WHERE seen=0 ORDER BY id"))
        if rows:
            self.db.execute("UPDATE instructions SET seen=1 WHERE id<=?", (rows[-1]["id"],))
        return [self._row(r) for r in rows]

    def apply_pending(self) -> list[str]:
        """Retry actions that were waiting (for example for the scope).
        Returns one line per action that is no longer waiting."""
        lines = []
        for instruction in self.all():
            if any(a.get("status") == PENDING for a in instruction.actions):
                before = [a.get("status") for a in instruction.actions]
                self._apply(instruction)
                after = self.get(instruction.id)
                for old, action in zip(before, after.actions):
                    if old == PENDING and action.get("status") != PENDING:
                        lines.append(f"#{instruction.id} {action['kind']} {action['arg']}: {action['reply']}")
        return lines

    def pop_reruns(self) -> list[str]:
        """Phases the operator's actions need to run again (once)."""
        raw = self.state.get_meta("operator_rerun")
        if not raw:
            return []
        self.state.set_meta("operator_rerun", "[]")
        return json.loads(raw)

    def skipped(self) -> set[str]:
        return set(self._meta_list("operator_skip"))

    def focus(self) -> list[str]:
        return self._meta_list("operator_focus")

    def avoided(self) -> list[str]:
        return sc.avoid_entries(self.target.output)

    def is_focus(self, host: str) -> bool:
        host = host.strip().lower()
        for pattern in self.focus():
            if pattern.startswith("*."):
                root = pattern[2:]
                if host == root or host.endswith("." + root):
                    return True
            elif host == pattern:
                return True
        return False

    def notes_for_agents(self) -> str:
        """Text added to every AI session's system prompt. Empty if the
        operator has said nothing."""
        notes = [i for i in self.all() if not i.withdrawn]
        focus, avoided, skipped = self.focus(), self.avoided(), sorted(self.skipped())
        if not (notes or focus or avoided or skipped):
            return ""
        lines = [
            "## Instructions from the operator (the person running this hunt)",
            "Treat these as their wishes about where to spend effort. They never widen the scope "
            "and never override the program rules; scope is enforced in code and out-of-scope "
            "requests are blocked.",
        ]
        if focus:
            lines.append("Focus first on: " + ", ".join(focus))
        if avoided:
            lines.append("Never touch (blocked by the scope guard): " + ", ".join(avoided))
        if skipped:
            lines.append("Phases the operator turned off: " + ", ".join(skipped))
        if notes:
            lines.append("Their messages, oldest first:")
            lines += [f"- #{n.id} ({n.created[:16].replace('T', ' ')}): {n.text}" for n in notes]
        return "\n".join(lines) + "\n"

    # ---------------------------------------------------------------- apply
    def _apply(self, instruction: Instruction) -> None:
        scope = self._scope()
        for action in instruction.actions:
            if action.get("status") in (DONE, REFUSED):
                continue
            handler = getattr(self, "_do_" + action["kind"], None)
            if handler is None:
                action.update(status=REFUSED, reply="unknown action")
                continue
            status, reply = handler(action["arg"], scope)
            action.update(status=status, reply=reply)
        self._save(instruction)

    def _scope(self) -> sc.Scope | None:
        try:
            return sc.load(self.target.scope_file)
        except (OSError, ValueError, KeyError):
            return None

    def _do_add(self, arg: str, scope: sc.Scope | None) -> tuple[str, str]:
        if _CIDR_RE.fullmatch(arg):
            return REFUSED, ("IP ranges are scanned as a whole by the port-scan phase, which is not "
                             "built yet. Add single IP addresses instead.")
        if arg.startswith("*."):
            return REFUSED, f"give a single host to add; to test {arg} first, use: focus {arg}"
        if scope is None:
            return PENDING, "waits until the scope is ready (after the intake phase)"
        host, decision = self._decide(arg, scope)
        if not decision.allowed:
            return REFUSED, f"not allowed ({decision.reason}). Nothing was sent to it."
        store = A.Assets(self.db)
        new = store.add_host(host, A.IN, "operator")
        resolved = self._resolve(store, host)
        if not resolved:
            return DONE, ("added, but it does not resolve in DNS right now, so it cannot be tested yet. "
                          "Next recon tries again.")
        store.mark_probed([host], False)
        self._request_rerun("03-probe")
        return DONE, ("added; it will be probed and then tested like the others" if new
                      else "already known; it will be probed again")

    def _do_focus(self, arg: str, scope: sc.Scope | None) -> tuple[str, str]:
        if _CIDR_RE.fullmatch(arg):
            return REFUSED, "focus works on hosts or *.domain, not IP ranges"
        if scope is None:
            return PENDING, "waits until the scope is ready (after the intake phase)"
        if arg.startswith("*."):
            pattern = arg
            if not scope.host_in_scope("hunter-check." + arg[2:]) and not scope.host_in_scope(arg[2:]):
                return REFUSED, f"{arg} is not in scope"
            extra = ""
        else:
            host, decision = self._decide(arg, scope)
            if not decision.allowed:
                return REFUSED, f"not allowed ({decision.reason}). Nothing was sent to it."
            pattern = host
            extra = ""
            store = A.Assets(self.db)
            if not store.db.execute("SELECT 1 FROM hosts WHERE host=?", (host,)).fetchone():
                status, reply = self._do_add(host, scope)
                if status == REFUSED:
                    return status, reply
                extra = " It was not known yet: " + reply
        focus = self._meta_list("operator_focus")
        if pattern not in focus:
            focus.append(pattern)
            self._set_meta_list("operator_focus", focus)
        changed = A.Assets(self.db).set_priority(pattern, 100)
        now = f"{changed} live service(s) moved to the top of the queue. " if changed else ""
        return DONE, f"{now}Every later phase tests it first.{extra}"

    def _do_unfocus(self, arg: str, _scope) -> tuple[str, str]:
        focus = self._meta_list("operator_focus")
        if arg not in focus:
            return REFUSED, "it was not in the focus list"
        focus.remove(arg)
        self._set_meta_list("operator_focus", focus)
        A.Assets(self.db).set_priority(arg, 50)
        return DONE, "back to normal priority"

    def _do_avoid(self, arg: str, _scope) -> tuple[str, str]:
        try:
            sc.parse_asset(arg)
        except sc.AssetError:
            return REFUSED, "could not read it as a host, URL, IP or range"
        entries = sc.avoid_entries(self.target.output)
        if arg not in entries:
            sc.save_avoid(self.target.output, entries + [arg])
        A.Assets(self.db).set_priority(arg, 0)
        return DONE, (f"blocked from now on, also in the middle of the run. "
                      f"Undo with: hunt tell {self.target.name} \"unavoid {arg}\"")

    def _do_unavoid(self, arg: str, _scope) -> tuple[str, str]:
        entries = sc.avoid_entries(self.target.output)
        if arg not in entries:
            return REFUSED, "it was not in the avoid list"
        entries.remove(arg)
        sc.save_avoid(self.target.output, entries)
        A.Assets(self.db).set_priority(arg, 50)
        return DONE, "allowed again (if it is in scope)"

    def _do_skip(self, arg: str, _scope) -> tuple[str, str]:
        if arg in PROTECTED:
            return REFUSED, f"{arg} cannot be skipped: {PROTECTED[arg]}"
        skipped = self._meta_list("operator_skip")
        if arg not in skipped:
            skipped.append(arg)
            self._set_meta_list("operator_skip", skipped)
        row = self.state.phase(arg)
        if row and row["status"] == st.RUNNING:
            return DONE, "it is running right now; it finishes this time and will not run again"
        if row and row["status"] in st.SETTLED:
            return DONE, "it already finished; it will not run again"
        return DONE, "it will not run"

    def _do_unskip(self, arg: str, _scope) -> tuple[str, str]:
        skipped = self._meta_list("operator_skip")
        if arg not in skipped:
            return REFUSED, "it was not skipped"
        skipped.remove(arg)
        self._set_meta_list("operator_skip", skipped)
        row = self.state.phase(arg)
        if row and row["summary"] == SKIPPED_SUMMARY:
            self.state.reset_phase(arg, "unskipped by the operator", reset_attempts=True)
            self._request_rerun(arg)
        return DONE, "it will run again"

    def _do_forget(self, arg: str, _scope) -> tuple[str, str]:
        other = self.get(int(arg))
        if other is None:
            return REFUSED, f"there is no message #{arg}"
        other.withdrawn = True
        self._save(other)
        return DONE, (f"message #{arg} is no longer shown to the AI. Actions it already did stay; "
                      f"undo them with unfocus / unavoid / unskip.")

    # -------------------------------------------------------------- helpers
    def _decide(self, arg: str, scope: sc.Scope) -> tuple[str, sc.Decision]:
        if "://" in arg:
            host = (urlsplit(arg).hostname or "").lower()
            return host, scope.decide_url(arg)
        host = sc.normalize_host(arg)
        return host, scope.decide(host)

    def _resolve(self, store: A.Assets, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            store.set_resolution(host, [host])
            return True
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(host, None)
        except (OSError, UnicodeError):
            return False
        addresses = sorted({info[4][0] for info in infos})
        if not addresses:
            return False
        store.set_resolution(host, addresses)
        return True

    def _request_rerun(self, phase_id: str) -> None:
        row = self.state.phase(phase_id)
        if row is None or row["status"] == st.PENDING:
            return  # it has not run yet; it will pick the change up anyway
        pending = self._meta_list("operator_rerun")
        if phase_id not in pending:
            pending.append(phase_id)
            self._set_meta_list("operator_rerun", pending)

    def _meta_list(self, key: str) -> list[str]:
        try:
            value = json.loads(self.state.get_meta(key) or "[]")
        except ValueError:
            return []
        return [str(x) for x in value] if isinstance(value, list) else []

    def _set_meta_list(self, key: str, values: list[str]) -> None:
        self.state.set_meta(key, json.dumps(values))
