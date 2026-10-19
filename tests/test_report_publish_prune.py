"""Two overnight-run fixes:
- the report phase publishes its drafts to hunt-output/reports/ (not the agent
  work dir, where they were invisible);
- renamed/removed phases are pruned from state (no lingering PENDING phantom).
"""

from __future__ import annotations

from hunter import state as st
from hunter.phases.ai_report import AIReportPhase


def test_report_publishes_drafts_from_workdir(tmp_path):
    out = tmp_path / "hunt-output"
    work = out / "phases" / "13-report" / "work"
    (work / "reports").mkdir(parents=True)
    (work / "reports" / "4-dns-leak.md").write_text("# draft", encoding="utf-8")
    (work / "handoff.md").write_text("done", encoding="utf-8")

    class _Store:
        def findings(self, status=None):
            return [object()] if status == "reported" else []

    class _Target:
        def __init__(self, output):
            self.output = output

    class _Ctx:
        def __init__(self, output):
            self.target = _Target(output)

    result = AIReportPhase().check(_Ctx(out), _Store())
    # Published where the operator and `hunt findings` look.
    assert (out / "reports" / "4-dns-leak.md").is_file()
    assert result.status == st.DONE
    assert "1 report draft(s) for 1 confirmed finding(s)" == result.summary


def test_prune_removes_renamed_phases(tmp_path):
    s = st.State(tmp_path / "state.db")
    s.ensure_phase("14-skills", "old skills")      # a renamed/removed phase
    s.ensure_phase("10b-skills", "skills pass")
    s.ensure_phase("00-intake", "intake")
    removed = s.prune_phases(["00-intake", "10b-skills"])
    assert removed == ["14-skills"]
    assert {r["phase_id"] for r in s.phases()} == {"00-intake", "10b-skills"}
