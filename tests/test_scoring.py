"""Tests for weighted scoring, grading, summaries, and gate evaluation."""

from __future__ import annotations

import pytest

from aegis.models import AuditReport, Finding, Severity, Status
from aegis.scoring import (
    apply_scoring,
    build_summary,
    category_breakdown,
    gate_failures,
    grade_for_score,
    top_risks,
    weighted_score,
)


def finding(
    status: Status,
    severity: Severity,
    *,
    rule_id: str = "AEGIS-9000",
    category: str = "Test",
    suppressed: bool = False,
) -> Finding:
    item = Finding(
        rule_id=rule_id,
        title="Example finding",
        severity=severity,
        category=category,
        cis="TEST-1.1",
        status=status,
        message="example",
    )
    if suppressed:
        item.suppressed = True
        item.suppression_reason = "accepted"
        item.suppression_expires = "2030-01-01"
    return item


def test_weighted_score_uses_severity_weights() -> None:
    findings = [
        finding(Status.PASS, Severity.CRITICAL),
        finding(Status.FAIL, Severity.CRITICAL),
        finding(Status.PASS, Severity.HIGH),
        finding(Status.FAIL, Severity.HIGH),
        finding(Status.PASS, Severity.LOW),
    ]
    assert weighted_score(findings) == pytest.approx(100 * 16 / 31)


def test_not_applicable_and_suppressed_are_excluded() -> None:
    findings = [
        finding(Status.PASS, Severity.CRITICAL),
        finding(Status.NOT_APPLICABLE, Severity.CRITICAL),
        finding(Status.FAIL, Severity.HIGH, suppressed=True),
    ]
    assert weighted_score(findings) == 100.0
    assert weighted_score([finding(Status.NOT_APPLICABLE, Severity.HIGH)]) == 100.0


def test_info_findings_do_not_change_the_score() -> None:
    assert weighted_score([finding(Status.FAIL, Severity.INFO)]) == 100.0


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100.0, "A"),
        (90.0, "A"),
        (89.99, "B"),
        (80.0, "B"),
        (79.99, "C"),
        (70.0, "C"),
        (69.99, "D"),
        (60.0, "D"),
        (59.99, "F"),
        (0.0, "F"),
    ],
)
def test_grade_thresholds(score: float, grade: str) -> None:
    assert grade_for_score(score) == grade


def test_category_breakdown_excludes_na_and_suppressed_from_weight() -> None:
    findings = [
        finding(Status.PASS, Severity.CRITICAL, category="SSH"),
        finding(Status.FAIL, Severity.HIGH, category="SSH"),
        finding(Status.NOT_APPLICABLE, Severity.CRITICAL, category="SSH"),
        finding(Status.FAIL, Severity.CRITICAL, category="Accounts", suppressed=True),
        finding(Status.PASS, Severity.LOW, category="Accounts"),
    ]
    categories = {item.category: item for item in category_breakdown(findings)}
    ssh = categories["SSH"]
    assert ssh.score == pytest.approx(100 * 10 / 15)
    assert (ssh.total, ssh.passed, ssh.failed, ssh.not_applicable) == (3, 1, 1, 1)
    accounts = categories["Accounts"]
    assert accounts.score == 100.0
    assert accounts.suppressed == 1
    assert accounts.total_weight == 1


def test_summary_counts_statuses_and_severities() -> None:
    findings = [
        finding(Status.PASS, Severity.HIGH),
        finding(Status.FAIL, Severity.HIGH),
        finding(Status.ERROR, Severity.MEDIUM),
        finding(Status.NOT_APPLICABLE, Severity.LOW),
        finding(Status.FAIL, Severity.CRITICAL, suppressed=True),
    ]
    summary = build_summary(findings)
    assert summary.total == 5
    assert summary.passed == 1
    assert summary.failed == 1
    assert summary.errors == 1
    assert summary.not_applicable == 1
    assert summary.suppressed == 1
    assert summary.by_severity["high"].passed == 1
    assert summary.by_severity["high"].failed == 1
    assert summary.by_severity["info"].total == 0


def test_top_risks_orders_by_severity_and_limits() -> None:
    findings = [
        finding(Status.FAIL, Severity.MEDIUM, rule_id="AEGIS-9101"),
        finding(Status.FAIL, Severity.CRITICAL, rule_id="AEGIS-9102"),
        finding(Status.FAIL, Severity.HIGH, rule_id="AEGIS-9103"),
        finding(Status.FAIL, Severity.CRITICAL, rule_id="AEGIS-9104", suppressed=True),
        finding(Status.PASS, Severity.CRITICAL, rule_id="AEGIS-9105"),
    ]
    risks = top_risks(findings, limit=2)
    assert [risk.rule_id for risk in risks] == ["AEGIS-9102", "AEGIS-9103"]


def test_apply_scoring_populates_every_derived_field() -> None:
    report = AuditReport(
        schema_version="1.0",
        tool_version="0.1.0",
        generated_at="2026-01-01T00:00:00Z",
        root="/",
        findings=[finding(Status.FAIL, Severity.CRITICAL)],
    )
    apply_scoring(report)
    assert report.score == 0.0
    assert report.grade == "F"
    assert report.summary.failed == 1
    assert report.categories[0].category == "Test"
    assert report.top_risks[0].rule_id == "AEGIS-9000"


def test_gate_fails_on_severity_threshold() -> None:
    findings = [
        finding(Status.FAIL, Severity.CRITICAL, rule_id="AEGIS-9201"),
        finding(Status.FAIL, Severity.HIGH, rule_id="AEGIS-9202"),
        finding(Status.FAIL, Severity.MEDIUM, rule_id="AEGIS-9203"),
    ]
    report = AuditReport("1.0", "0.1.0", "2026-01-01T00:00:00Z", "/", findings=findings)
    assert gate_failures(report, fail_on=Severity.LOW, min_score=None)
    high = gate_failures(report, fail_on=Severity.HIGH, min_score=None)
    assert high and "at or above high" in high[0]
    critical = gate_failures(report, fail_on=Severity.CRITICAL, min_score=None)
    assert critical and "critical=1" in critical[0]
    assert gate_failures(report, fail_on=None, min_score=None) == []


def test_gate_uses_min_score_and_reports_both_reasons() -> None:
    findings = [finding(Status.FAIL, Severity.CRITICAL)]
    report = AuditReport("1.0", "0.1.0", "2026-01-01T00:00:00Z", "/", findings=findings)
    apply_scoring(report)
    reasons = gate_failures(report, fail_on=Severity.HIGH, min_score=50)
    assert len(reasons) == 2
    assert "below --min-score" in reasons[1]
    assert gate_failures(report, fail_on=None, min_score=0) == []
