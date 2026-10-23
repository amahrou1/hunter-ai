"""Tech-fingerprint hints: emits stack-specific hints only for technologies
present, de-duplicated; silent otherwise."""

from __future__ import annotations

from hunter import techhints


def test_hints_for_detected_stack():
    fps = ["Microsoft-IIS/10.0", "ASP.NET", "Kestrel"]
    hints = dict(techhints.hints_for(fps))
    assert "iis" in hints
    assert "asp.net" in hints
    assert "wordpress" not in hints


def test_salesforce_and_swagger():
    hints = {k for k, _ in techhints.hints_for(["Salesforce Lightning", "Swagger UI"])}
    assert "salesforce" in hints or "lightning" in hints
    assert "swagger" in hints


def test_no_match_is_empty():
    assert techhints.hints_for(["generic app", "custom server 1.0"]) == []


def test_dedup_same_keyword():
    hints = techhints.hints_for(["WordPress 6.1", "wordpress plugin xyz"])
    kws = [k for k, _ in hints]
    assert kws.count("wordpress") == 1


def test_case_insensitive():
    assert any(k == "grafana" for k, _ in techhints.hints_for(["GRAFANA v8"]))
