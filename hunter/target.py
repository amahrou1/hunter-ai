"""The target folder that the operator prepares by hand."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from . import paths

OUTPUT_DIR_NAME = "hunt-output"
TEMPLATE_MARK = "# [hunter-ai]"

# name -> (required, description)
INPUT_FILES: dict[str, tuple[bool, str]] = {
    "policy.txt": (True, "Program page pasted as is: scope, out of scope, rules, rate limits, headers."),
    "test-credentials.txt": (False, "Accounts you created. Free text is fine, one account per line."),
    "reports.txt": (False, "Your past reports to this program, with status (resolved or open)."),
    "resolved-reports.txt": (False, "Published or disclosed reports from other researchers."),
    "scope-overrides.txt": (False, "Your corrections to the scope: lines like 'in *.foo.com', 'out bar.foo.com'."),
    "subdomains.txt": (False, "Extra hostnames you already know. Seeds only, never scope."),
    "ips.txt": (False, "Extra IP addresses you already know. Seeds only, never scope."),
}

TEMPLATES: dict[str, str] = {
    "policy.txt": (
        f"{TEMPLATE_MARK} Paste the full program page below this line (scope, out of scope, rules).\n"
        f"{TEMPLATE_MARK} Lines that start with '{TEMPLATE_MARK}' are ignored. You can delete them.\n"
    ),
    "test-credentials.txt": (
        f"{TEMPLATE_MARK} Optional. One account per line, free text. Example:\n"
        f"{TEMPLATE_MARK} attacker | app: https://app.example.com | email: a@x.com | password: ... | role: user | tenant: A\n"
        f"{TEMPLATE_MARK} victim   | app: https://app.example.com | email: b@x.com | password: ... | role: user | tenant: B\n"
    ),
    "reports.txt": (
        f"{TEMPLATE_MARK} Optional. Your past reports to this program. Example:\n"
        f"{TEMPLATE_MARK} RESOLVED | IDOR on /api/orders/{{id}} lets user A read user B orders | 2026-05-01\n"
        f"{TEMPLATE_MARK} OPEN     | Stored XSS in profile bio | 2026-09-10\n"
    ),
    "resolved-reports.txt": (
        f"{TEMPLATE_MARK} Optional. Paste disclosed or resolved reports from other researchers, any format.\n"
        f"{TEMPLATE_MARK} If the program has none, leave this file empty or delete it.\n"
    ),
    "scope-overrides.txt": (
        f"{TEMPLATE_MARK} Optional. Your corrections to the scope the AI read from policy.txt. One per line:\n"
        f"{TEMPLATE_MARK}   in *.extra.example.com       (add to scope)\n"
        f"{TEMPLATE_MARK}   out admin.example.com        (never test)\n"
        f"{TEMPLATE_MARK}   header X-Bug-Bounty: yourname (a header every request must carry)\n"
        f"{TEMPLATE_MARK} Saving this file during a run makes the run re-read the scope.\n"
    ),
}

# Inputs that define what may be touched: a change restarts the whole run.
SCOPE_INPUTS = ("policy.txt", "scope-overrides.txt")

# A folder dropped in the target directory holding a PREVIOUS automation's
# output (the operator's old system). The run mines it for reference - hosts,
# endpoints, leads, past findings - but never trusts its testing: everything is
# re-verified from scratch. Matched case-insensitively.
PRIOR_DIR_NAMES = (
    "ai automation", "ai-automation", "ai_automation", "aiautomation",
    "old-automation", "old-system", "previous-run", "prior-run", "prior",
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class TargetError(Exception):
    pass


def valid_name(name: str) -> bool:
    return bool(_NAME_RE.match(name))


def meaningful_text(path: Path) -> str:
    """File content without template lines and without leading/trailing
    blank lines. Empty string if the file does not exist."""
    if not path.exists():
        return ""
    lines = [
        line for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not line.startswith(TEMPLATE_MARK)
    ]
    return "\n".join(lines).strip()


@dataclass
class Target:
    path: Path

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def output(self) -> Path:
        return self.path / OUTPUT_DIR_NAME

    @property
    def state_db(self) -> Path:
        return self.output / "state.db"

    @property
    def logs(self) -> Path:
        return self.output / "logs"

    @property
    def scope_file(self) -> Path:
        return self.output / "scope.json"

    @property
    def scope_review(self) -> Path:
        return self.output / "scope_review.md"

    def prior_dir(self) -> Path | None:
        """A previous automation's output folder dropped in the target dir, if
        present. Reference only - the run re-tests everything from scratch."""
        if not self.path.is_dir():
            return None
        wanted = {n.lower() for n in PRIOR_DIR_NAMES}
        for child in sorted(self.path.iterdir()):
            if child.is_dir() and child.name != OUTPUT_DIR_NAME and child.name.lower() in wanted:
                return child
        return None

    def input_path(self, name: str) -> Path:
        return self.path / name

    def input_text(self, name: str) -> str:
        return meaningful_text(self.input_path(name))

    def has_input(self, name: str) -> bool:
        return bool(self.input_text(name))

    def input_fingerprint(self, name: str) -> str:
        text = self.input_text(name)
        return hashlib.sha256(text.encode()).hexdigest() if text else ""

    def fingerprints(self) -> dict[str, str]:
        return {name: self.input_fingerprint(name) for name in INPUT_FILES}

    def validate(self) -> list[str]:
        """Return a list of problems that stop a run. Empty list means OK."""
        problems = []
        if not self.path.is_dir():
            return [f"The folder {self.path} does not exist."]
        policy = self.input_text("policy.txt")
        if not policy:
            problems.append(
                f"policy.txt is missing or empty in {self.path}. "
                f"Paste the program page into it with: nano {self.input_path('policy.txt')}")
        elif len(policy) < 40:
            problems.append("policy.txt is very short. Paste the whole program page (scope and rules).")
        return problems

    def tmux_session(self) -> str:
        return "hunt-" + re.sub(r"[^A-Za-z0-9_-]", "-", self.name)


def resolve(name_or_path: str) -> Target:
    raw = name_or_path.strip()
    if not raw:
        raise TargetError("Give a target name, for example: hunt start acme")
    candidate = Path(raw).expanduser()
    if "/" in raw or candidate.is_absolute():
        return Target(candidate.resolve())
    if not valid_name(raw):
        raise TargetError(
            f"'{raw}' is not a valid target name. Use letters, numbers, dots, dashes or underscores.")
    return Target((paths.targets_dir() / raw).resolve())


def create(name: str) -> tuple[Target, list[str]]:
    if not valid_name(name):
        raise TargetError(
            f"'{name}' is not a valid target name. Use letters, numbers, dots, dashes or underscores.")
    target = Target((paths.targets_dir() / name).resolve())
    target.path.mkdir(parents=True, exist_ok=True)
    created = []
    for filename, template in TEMPLATES.items():
        file_path = target.input_path(filename)
        if not file_path.exists():
            file_path.write_text(template, encoding="utf-8")
            created.append(filename)
    return target, created


def list_targets() -> list[Target]:
    root = paths.targets_dir()
    if not root.is_dir():
        return []
    return sorted((Target(p) for p in root.iterdir() if p.is_dir()), key=lambda t: t.name)
