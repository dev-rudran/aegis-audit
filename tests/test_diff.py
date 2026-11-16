"""Tests for JSON report drift comparison."""

from __future__ import annotations

import json

import pytest

from aegis.diff import DiffError, diff_reports, load_report
from aegis.models import AuditReport, Finding, Severity, Status


def finding(
    rule_id: str,
    status: Status,
    severity: Severity = Severity.HIGH,
    *,
    message: str = "example",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Control {rule_id}",
        severity=severity,
        category="Test",
        cis="TEST-1.1",
        status=status,
        message=message,
    )


def report(score: float, grade: str, findings: list[Finding]) -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        tool_version="0.1.0",
        generated_at="2026-01-01T00:00:00Z",
        root="/",
        findings=findings,
        score=score,
        grade=grade,
    )


def test_diff_classifies_newly_failing_fixed_and_persistent() -> None:
    old = report(
        75.0,
        "C",
        [
            finding("AEGIS-0001", Status.PASS),
            finding("AEGIS-0002", Status.FAIL, Severity.CRITICAL),
            finding("AEGIS-0003", Status.FAIL),
        ],
    )
    new = report(
        80.0,
        "B",
        [
            finding("AEGIS-0001", Status.FAIL, Severity.CRITICAL),
            finding("AEGIS-0002", Status.PASS, Severity.CRITICAL),
            finding("AEGIS-0003", Status.FAIL),
        ],
    )
    result = diff_reports(old, new)
    assert [item.rule_id for item in result.newly_failing] == ["AEGIS-0001"]
    assert [item.rule_id for item in result.newly_fixed] == ["AEGIS-0002"]
    assert [item.rule_id for item in result.still_failing] == ["AEGIS-0003"]
    assert result.score_delta == 5.0
    assert result.regressed is True
    assert result.newly_failing[0].old_status == "pass"
    assert result.newly_failing[0].new_status == "fail"
    assert result.newly_fixed[0].old_status == "fail"


def test_diff_severity_counts() -> None:
    old = report(0.0, "F", [])
    new = report(
        0.0,
        "F",
        [
            finding("AEGIS-0010", Status.FAIL, Severity.CRITICAL),
            finding("AEGIS-0011", Status.FAIL, Severity.CRITICAL),
            finding("AEGIS-0012", Status.FAIL, Severity.MEDIUM),
        ],
    )
    result = diff_reports(old, new)
    deltas = {delta.severity: delta for delta in result.severity_deltas}
    assert deltas[Severity.CRITICAL].newly_failing == 2
    assert deltas[Severity.MEDIUM].newly_failing == 1
    assert deltas[Severity.HIGH].newly_failing == 0


def test_added_and_removed_rules_are_reported() -> None:
    old = report(50.0, "F", [finding("AEGIS-0020", Status.PASS)])
    new = report(50.0, "F", [finding("AEGIS-0021", Status.FAIL)])
    result = diff_reports(old, new)
    assert result.added_rules == ["AEGIS-0021"]
    assert result.removed_rules == ["AEGIS-0020"]
    assert [item.rule_id for item in result.newly_failing] == ["AEGIS-0021"]


def test_improvement_is_not_a_regression() -> None:
    old = report(40.0, "F", [finding("AEGIS-0030", Status.FAIL)])
    new = report(95.0, "A", [finding("AEGIS-0030", Status.PASS)])
    result = diff_reports(old, new)
    assert result.regressed is False
    assert result.score_delta == 55.0
    assert result.newly_fixed


def test_diff_text_and_json_expose_the_same_facts() -> None:
    old = report(10.0, "F", [finding("AEGIS-0040", Status.FAIL)])
    new = report(20.0, "F", [finding("AEGIS-0040", Status.FAIL)])
    result = diff_reports(old, new)
    text = result.to_text()
    assert "aegis drift report" in text
    assert "Delta: +10.00" in text
    assert "Still failing (1)" in text
    payload = json.loads(result.to_json())
    assert payload["old"]["score"] == 10.0
    assert payload["new"]["score"] == 20.0
    assert payload["still_failing"][0]["rule_id"] == "AEGIS-0040"


def test_load_report_round_trips_a_written_report(tmp_path) -> None:
    original = report(72.5, "C", [finding("AEGIS-0050", Status.FAIL)])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(original.to_dict()), encoding="utf-8")
    loaded = load_report(path)
    assert loaded.score == 72.5
    assert loaded.findings[0].rule_id == "AEGIS-0050"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "not found"),
        ("{not json", "cannot parse"),
        ('{"score": 1}', "does not look like"),
        ('{"findings": [{"severity": "nope"}]}', "invalid report structure"),
    ],
)
def test_load_report_rejects_bad_input(tmp_path, content: str | None, message: str) -> None:
    path = tmp_path / "report.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    with pytest.raises(DiffError, match=message):
        load_report(path)
