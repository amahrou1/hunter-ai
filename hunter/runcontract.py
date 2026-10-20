"""The run contract: a MANDATORY RUN CONTRACT a phase shows its agent up front.

Why this exists (the "first ~150 lines" problem): an agent reading a long
instruction block attends most to the top and the end; a mandatory step or a
"use this helper" line buried in the middle can be skipped entirely. So every
phase states its must-run steps as a short CHECKLIST at the very top of the task
- each step ending in a concrete ARTIFACT the phase can verify - plus the rule
that the whole task is non-optional once the phase is running. The detailed
prose follows; the checklist guarantees the critical steps are seen and that
"summarising instead of producing the artifact" counts as FAILURE, not done.

A phase supplies its steps as MustStep(id, text, artifact). render_contract()
turns them into the header block; artifacts_present() lets check() confirm the
named artifacts actually exist in the work dir.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MustStep:
    id: str            # short tag, e.g. "M1"
    text: str          # what to do
    artifact: str = "" # file it must produce in the work dir (optional)


_HEADER = """== MANDATORY RUN CONTRACT (read this whole task; it is non-optional) ==
You are running this phase now, so the ENTIRE task below is required, not a
menu. Skimming the first few lines is only enough to know what the phase is -
it is NOT enough to run it. Every MUST step ends in a concrete artifact in your
working directory; writing a summary INSTEAD of producing the artifact is a
FAILURE, not "done". Work the checklist to ZERO unchecked boxes, then write
./handoff.md as the final completion gate.

MUST steps for this phase:
{checklist}

Rules: do every box above. If a box genuinely cannot be done on this target,
record why with `hk note` and leave its artifact empty rather than skipping it
silently. If you run out of turns before finishing, stop WITHOUT writing
handoff.md - your artifacts are saved and you will be resumed; never fake
completion.
"""


def render_contract(steps: list[MustStep]) -> str:
    """The checklist header, prepended to a phase's detailed task prose."""
    if not steps:
        return ""
    lines = []
    for s in steps:
        art = f"  -> artifact: `{s.artifact}`" if s.artifact else ""
        lines.append(f"- [ ] {s.id}: {s.text}{art}")
    return _HEADER.format(checklist="\n".join(lines))


def artifacts_present(workdir: Path, steps: list[MustStep]) -> list[str]:
    """Return the artifacts named by the steps that are MISSING or empty.

    A phase's check() uses this to tell "the agent finished the contract" from
    "it stopped early", so a missing artifact becomes PARTIAL (resume) instead
    of a false DONE. Steps without an artifact are not checked here.
    """
    missing: list[str] = []
    for s in steps:
        if not s.artifact:
            continue
        path = workdir / s.artifact
        try:
            if not path.exists() or path.stat().st_size == 0:
                missing.append(s.artifact)
        except OSError:
            missing.append(s.artifact)
    return missing
