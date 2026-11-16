"""Tests for the public data model and its JSON round trip."""

from __future__ import annotations

import json
from datetime import date

import pytest

from aegis.models import (
    AuditReport,
    BaselineException,
    BaselineStatus,
    CategoryScore,
    Finding,
    Remediation,
    Rule,
    RuleValidationError,
    Severity,
    Status,
    Summary,
    TopRisk,
    parse_date,
    utc_now_iso,
)


def minimal_rule(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "id": "AEGIS-9000",
        "title": "Example control",
        "description": "An example control description.",
        "severity": "high",
        "category": "Test",
        "cis": "TEST-1.1",
        "check": {"type": "file_exists", "params": {"path": "/etc/example"}},
        "remediation": {"text": "Create the file.", "safe": False},
        "tags": ["test", "example"],
    }
    document.update(overrides)
    return document


def test_severity_parsing_is_case_insensitive_and_rejects_unknown() -> None:
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse(" High ") is Severity.HIGH
    with pytest.raises(ValueError, match="invalid severity"):
        Severity.parse("urgent")
    with pytest.raises(ValueError, match="must be a string"):
        Severity.parse(1)


def test_severity_weights_and_ranking() -> None:
    assert [severity.weight for severity in Severity] == [10, 5, 2, 1, 0]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_status_semantics() -> None:
    assert Status.FAIL.is_failing
    assert Status.ERROR.is_failing
    assert not Status.PASS.is_failing
    assert not Status.NOT_APPLICABLE.is_failing


def test_rule_round_trip_preserves_metadata() -> None:
    rule = Rule.from_dict(
        minimal_rule(
            remediation={
                "text": "Set the directive.",
                "safe": True,
                "command": "echo fixed",
                "fix": {
                    "type": "sshd_set",
                    "path": "/etc/ssh/sshd_config",
                    "key": "X",
                    "value": "y",
                },
            },
            references=["https://example.invalid/control"],
        ),
        allowed_check_types={"file_exists"},
    )
    payload = rule.to_dict()
    assert payload["id"] == "AEGIS-9000"
    assert payload["severity"] == "high"
    assert payload["remediation"]["fix"]["type"] == "sshd_set"
    assert payload["references"] == ["https://example.invalid/control"]
    assert rule.check_type == "file_exists"
    assert rule.params == {"path": "/etc/example"}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"id": "AEGIS-1"}, "id must match"),
        ({"id": 12}, "id must match"),
        ({"severity": "severe"}, "invalid severity"),
        ({"title": ""}, "title must be a non-empty string"),
        ({"category": "bad/../category"}, "invalid characters"),
        ({"check": {"type": "nope", "params": {}}}, "unknown check type"),
    ],
)
def test_rule_validation_rejects_malformed_documents(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(RuleValidationError, match=message):
        Rule.from_dict(minimal_rule(**overrides), allowed_check_types={"file_exists"})


def test_remediation_requires_text_and_known_fix_type() -> None:
    with pytest.raises(RuleValidationError, match="non-empty string"):
        Remediation.from_dict({"text": "", "safe": True})
    with pytest.raises(RuleValidationError, match=r"fix\.type must be one of"):
        Remediation.from_dict({"text": "fix it", "safe": True, "fix": {"type": "run_shell"}})
    with pytest.raises(RuleValidationError, match="safe must be a boolean"):
        Remediation.from_dict({"text": "fix it", "safe": "yes"})


def _finding(rule_id: str, status: Status, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Example",
        severity=severity,
        category="Test",
        cis="TEST-1.1",
        status=status,
        message="example message",
    )


def test_finding_json_includes_suppression_details_only_when_suppressed() -> None:
    finding = _finding("AEGIS-9001", Status.FAIL)
    assert "suppression_reason" not in finding.to_dict()
    finding.suppressed = True
    finding.suppression_reason = "accepted risk"
    finding.suppression_expires = "2030-01-01"
    payload = finding.to_dict()
    assert payload["suppressed"] is True
    assert payload["suppression_reason"] == "accepted risk"
    assert payload["suppression_expires"] == "2030-01-01"


def test_audit_report_json_round_trip() -> None:
    report = AuditReport(
        schema_version="1.0",
        tool_version="0.1.0",
        generated_at="2026-01-01T00:00:00Z",
        root="/srv/image",
        findings=[_finding("AEGIS-9001", Status.FAIL)],
        score=87.5,
        grade="B",
        summary=Summary(total=1, failed=1),
        categories=[CategoryScore("Test", 0.0, 5, 0, 1, 0, 1)],
        top_risks=[TopRisk("AEGIS-9001", "Example", Severity.HIGH, "Test", "message")],
        baseline=BaselineStatus(
            path="baseline.yml",
            active=1,
            suppressed=1,
            expired=[BaselineException("AEGIS-9002", "expired", "2020-01-01", "expired")],
        ),
        errors=["AEGIS-9003: check failed"],
        duration_ms=42,
        ruleset_fingerprint="abc123",
    )
    restored = AuditReport.from_dict(json.loads(json.dumps(report.to_dict())))
    assert restored.score == 87.5
    assert restored.grade == "B"
    assert restored.findings[0].severity is Severity.HIGH
    assert restored.categories[0].category == "Test"
    assert restored.baseline.expired[0].expires == "2020-01-01"
    assert restored.errors == ["AEGIS-9003: check failed"]
    assert restored.ruleset_fingerprint == "abc123"


def test_timestamp_and_date_helpers_are_strict() -> None:
    stamp = utc_now_iso()
    assert stamp.endswith("Z")
    assert "T" in stamp
    assert parse_date("2026-06-01") == date(2026, 6, 1)
    with pytest.raises(ValueError):
        parse_date("01/06/2026")
