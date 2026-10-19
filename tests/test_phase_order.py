"""The pipeline order must keep every TESTING phase before the
validate -> disprove -> report tail, so findings they produce are always
validated, disproved and reported. The skills pass used to run dead last
(after the report); this guards against that regression."""

from __future__ import annotations

from hunter.phases import all_phases


def test_testing_phases_precede_validation_tail():
    ids = [p.id for p in all_phases()]
    at = ids.index
    # The tail that turns candidates into reports, in order.
    assert at("11-validate") < at("12-disprove") < at("13-report")
    # Every phase that can open a finding runs before validation.
    for testing in ("06b-depconf", "08-authz-logic", "09-injection", "10-misconfig", "10b-skills"):
        assert at(testing) < at("11-validate"), f"{testing} must run before validation"
    # Dependency confusion needs the harvested JS, so it runs after the js phase.
    assert at("06-js") < at("06b-depconf")
    # The optional skills pass is a testing phase, not a post-report step.
    assert at("10-misconfig") < at("10b-skills") < at("11-validate")
    # Report is still the final phase of the run.
    assert ids[-1] == "13-report"
