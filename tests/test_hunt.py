"""The free-hunt capstone: its challenge framing and, crucially, the
code-enforced effort floor that stops a lazy agent from passing with a shallow
'no bugs' after a few minutes."""

from __future__ import annotations

from hunter import state as st
from hunter.phases.ai_hunt import AIHuntPhase, MIN_HYPOTHESES


def test_task_challenges_effort_not_a_quota():
    t = AIHuntPhase().task(object()).lower()
    # The true "bugs are out there" challenge, the chaining mandate, and the
    # explicit anti-fabrication guardrail must all be present.
    assert "every single day" in t and "chain" in t
    assert "fabricated" in t and ("not asking for a number" in t or "not a quota" in t.replace("-", " "))
    # It must point the agent at the program's own history.
    assert "resolved-reports.txt" in t and "reports.txt" in t


class _Store:
    def __init__(self, finds=()):
        self._finds = list(finds)

    def findings(self, status=None):
        return self._finds


class _Target:
    def __init__(self, output):
        self.output = output


class _Ctx:
    def __init__(self, output):
        self.target = _Target(output)


def _workdir(out):
    return out / "phases" / "10c-hunt" / "work"


def test_shallow_hunt_is_partial(tmp_path):
    """Handoff written but a thin hypotheses log -> PARTIAL, so it re-runs."""
    work = _workdir(tmp_path)
    work.mkdir(parents=True)
    (work / "handoff.md").write_text("done, nothing found", encoding="utf-8")
    (work / "hypotheses-tested.md").write_text("## only one thing\ntried: curl\nverdict: dead\n", encoding="utf-8")
    res = AIHuntPhase().check(_Ctx(tmp_path), _Store())
    assert res.status == st.PARTIAL and "too shallow" in res.summary


def test_deep_hunt_passes(tmp_path):
    work = _workdir(tmp_path)
    work.mkdir(parents=True)
    (work / "handoff.md").write_text("deep hunt summary", encoding="utf-8")
    entries = "".join(f"## hypothesis {i}\ntried: x\nevidence: y\nverdict: dead\n" for i in range(MIN_HYPOTHESES))
    (work / "hypotheses-tested.md").write_text(entries, encoding="utf-8")
    res = AIHuntPhase().check(_Ctx(tmp_path), _Store())
    assert res.status == st.DONE and "deep hunt done" in res.summary


def test_no_handoff_is_partial(tmp_path):
    _workdir(tmp_path).mkdir(parents=True)
    res = AIHuntPhase().check(_Ctx(tmp_path), _Store())
    assert res.status == st.PARTIAL
