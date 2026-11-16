"""Tests for the five report renderers."""

from __future__ import annotations

import json
from datetime import date, timedelta
from urllib.parse import urlparse

import pytest

from aegis.baseline import Baseline
from aegis.models import AuditReport, BaselineStatus, Finding, Severity, Status
from aegis.report import FORMATS, render_report
from aegis.report.console import render_console
from aegis.report.html import render_html
from aegis.report.json_report import render_json
from aegis.report.markdown import render_markdown
from aegis.report.sarif import SARIF_VERSION, render_sarif


def synthetic_report() -> AuditReport:
    finding = Finding(
        rule_id="AEGIS-9000",
        title='Control with <script>alert("x")</script>',
        severity=Severity.CRITICAL,
        category="Test",
        cis="TEST-1.1",
        status=Status.FAIL,
        message="failed <b>badly</b>",
        path="/etc/example",
    )
    return AuditReport(
        schema_version="1.0",
        tool_version="0.1.0",
        generated_at="2026-01-01T00:00:00Z",
        root="/root<with>markup",
        findings=[finding],
        score=42.0,
        grade="F",
        baseline=BaselineStatus(),
    )


def test_console_quiet_mode_is_a_single_summary_line(vulnerable_report) -> None:
    text = render_console(vulnerable_report, quiet=True, gate_reasons=["critical findings"])
    assert text.count("\n") == 1
    assert text.startswith("3.83 F failed=78 errors=0 gate=FAIL")
    assert "\x1b" not in text


def test_console_full_report_disables_ansi_when_requested(vulnerable_report) -> None:
    text = render_console(vulnerable_report, color=False, gate_reasons=["gate reason"])
    assert "Linux host hardening audit" in text
    assert "Top risks" in text
    assert "Gate: FAIL" in text
    assert "- gate reason" in text
    assert "\x1b[" not in text


def test_console_reports_all_controls_passed(hardened_report) -> None:
    text = render_console(hardened_report, color=False, gate_reasons=[])
    assert "All evaluated controls passed." in text
    assert "Score  100.00" in text
    assert "Gate: PASS" in text


def test_json_report_is_valid_and_complete(vulnerable_report) -> None:
    text = render_json(vulnerable_report)
    assert "\x1b" not in text
    payload = json.loads(text)
    assert payload["schema_version"] == "1.0"
    assert payload["tool_version"] == "0.1.0"
    assert payload["score"] == 3.83
    assert payload["grade"] == "F"
    assert len(payload["findings"]) == 81
    assert payload["summary"]["failed"] == 78
    assert len(payload["categories"]) == 9
    assert payload["ruleset_fingerprint"]


def test_markdown_report_contains_tables_and_findings(vulnerable_report) -> None:
    text = render_markdown(vulnerable_report)
    assert text.startswith("# aegis hardening report")
    assert "**3.83 / 100 - grade F**" in text
    assert "| Severity | Total | Pass | Fail | Error | N/A | Suppressed |" in text
    assert "## Categories" in text
    assert "## Top risks" in text
    assert "AEGIS-0002" in text


def test_html_report_is_standalone_and_complete(vulnerable_report) -> None:
    text = render_html(vulnerable_report)
    assert text.startswith("<!DOCTYPE html>")
    assert "<style>" in text
    assert "<script>" in text
    assert "<link " not in text
    assert "<script src=" not in text
    assert 'id="findings"' in text
    assert "aegis report -" in text
    assert "3.83" in text


def test_html_escapes_untrusted_report_content() -> None:
    text = render_html(synthetic_report())
    assert "<script>alert" not in text
    assert "&lt;script&gt;alert" in text
    assert "&lt;b&gt;badly&lt;/b&gt;" in text
    assert "/root&lt;with&gt;markup" in text


def test_sarif_report_is_valid_2_1_0(vulnerable_report) -> None:
    payload = json.loads(render_sarif(vulnerable_report))
    assert payload["version"] == SARIF_VERSION == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "aegis"
    assert len(run["tool"]["driver"]["rules"]) == 81
    assert len(run["results"]) == 78
    assert run["properties"]["score"] == 3.83
    assert run["properties"]["grade"] == "F"
    levels = {result["level"] for result in run["results"]}
    assert levels == {"error", "warning", "note"}
    result = next(item for item in run["results"] if item["ruleId"] == "AEGIS-0002")
    descriptor = next(item for item in run["tool"]["driver"]["rules"] if item["id"] == "AEGIS-0002")
    assert result["properties"]["severity"] == "critical"
    assert descriptor["properties"]["security-severity"] == "9.5"
    location = result["locations"][0]["physicalLocation"]["artifactLocation"]
    parsed = urlparse(location["uri"])
    assert parsed.scheme == "" and not location["uri"].startswith("/")


def test_sarif_marks_suppressed_findings(vulnerable_report) -> None:
    report = AuditReport.from_dict(vulnerable_report.to_dict())
    critical = next(
        finding.rule_id
        for finding in report.findings
        if finding.is_failing and finding.severity is Severity.CRITICAL
    )
    baseline = Baseline.from_dict(
        [
            {
                "id": critical,
                "reason": "compensating control",
                "expires": (date.today() + timedelta(days=1)).isoformat(),
            }
        ]
    )
    baseline.apply(report.findings)
    payload = json.loads(render_sarif(report))
    results = {item["ruleId"]: item for item in payload["runs"][0]["results"]}
    assert results[critical]["suppressions"][0]["status"] == "accepted"
    assert "compensating control" in results[critical]["suppressions"][0]["justification"]


def test_render_report_registry_and_unknown_format() -> None:
    report = synthetic_report()
    for fmt in FORMATS:
        assert isinstance(render_report(report, fmt, color=False), str)
    with pytest.raises(ValueError, match="unknown report format"):
        render_report(report, "pdf")


def test_console_color_and_gate_states() -> None:
    report = synthetic_report()
    colored = render_console(report, color=True, gate_reasons=["failed"])
    assert "\x1b[" in colored
    not_evaluated = render_console(report, color=False, gate_reasons=None)
    assert "Gate: not evaluated" in not_evaluated
