"""Tests for time-bound baseline exceptions."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from aegis.baseline import Baseline, BaselineError, is_baseline_suppressed
from aegis.models import Finding, Severity, Status

TODAY = date(2026, 6, 1)


def finding(rule_id: str, status: Status = Status.FAIL) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Example",
        severity=Severity.HIGH,
        category="Test",
        cis="TEST-1.1",
        status=status,
        message="example",
    )


def entry(
    rule_id: str = "AEGIS-0002", expires: date | None = None, reason: str = "risk accepted"
) -> dict:
    return {
        "id": rule_id,
        "reason": reason,
        "expires": (expires or TODAY + timedelta(days=10)).isoformat(),
    }


def test_load_accepts_bare_list(tmp_path) -> None:
    path = tmp_path / "baseline.yml"
    path.write_text("- id: AEGIS-0002\n  reason: test\n  expires: 2026-12-31\n")
    baseline = Baseline.load(path)
    assert len(baseline.entries) == 1
    assert baseline.source == str(path)


def test_from_dict_accepts_mapping_and_list() -> None:
    assert len(Baseline.from_dict({"exceptions": [entry()]}).entries) == 1
    assert len(Baseline.from_dict([entry()]).entries) == 1
    assert len(Baseline.from_dict(None).entries) == 0


def test_active_entry_suppresses_only_failing_findings() -> None:
    baseline = Baseline.from_dict([entry("AEGIS-0002")])
    failing = finding("AEGIS-0002")
    passing = finding("AEGIS-0002", Status.PASS)
    status = baseline.apply([failing, passing], today=TODAY)
    assert failing.suppressed is True
    assert failing.suppression_reason == "risk accepted"
    assert failing.suppression_expires == (TODAY + timedelta(days=10)).isoformat()
    assert passing.suppressed is False
    assert status.active == 1
    assert status.suppressed == 1
    assert status.unused == []
    assert is_baseline_suppressed(failing)


def test_expired_entry_never_suppresses() -> None:
    baseline = Baseline.from_dict([entry(expires=TODAY - timedelta(days=1))])
    failing = finding("AEGIS-0002")
    status = baseline.apply([failing], today=TODAY)
    assert failing.suppressed is False
    assert status.suppressed == 0
    assert len(status.expired) == 1
    assert status.expired[0].state == "expired"
    assert "expired on 2026-05-31" in status.expired[0].detail
    assert status.unused == []


def test_entry_expiring_today_is_still_active() -> None:
    baseline = Baseline.from_dict([entry(expires=TODAY)])
    failing = finding("AEGIS-0002")
    status = baseline.apply([failing], today=TODAY)
    assert failing.suppressed is True
    assert status.expired == []


def test_unused_active_entry_is_reported() -> None:
    baseline = Baseline.from_dict([entry("AEGIS-0009")])
    status = baseline.apply([finding("AEGIS-0002")], today=TODAY)
    assert status.active == 1
    assert status.suppressed == 0
    assert [item.rule_id for item in status.unused] == ["AEGIS-0009"]
    assert status.unused[0].state == "unused"


@pytest.mark.parametrize(
    "document",
    [
        {"exceptions": [{"id": "BAD-ID", "reason": "x", "expires": "2030-01-01"}]},
        {"exceptions": [{"id": "AEGIS-0002", "reason": "", "expires": "2030-01-01"}]},
        {"exceptions": [{"id": "AEGIS-0002", "reason": "x", "expires": "01/01/2030"}]},
        {"exceptions": [{"id": "AEGIS-0002", "reason": "x"}]},
        {"exceptions": "nope"},
    ],
)
def test_invalid_entries_are_rejected(document: dict) -> None:
    with pytest.raises(BaselineError):
        Baseline.from_dict(document)


def test_duplicate_entries_are_rejected() -> None:
    with pytest.raises(BaselineError, match="duplicate"):
        Baseline.from_dict([entry(), entry()])


def test_missing_baseline_file_is_an_error(tmp_path) -> None:
    with pytest.raises(BaselineError, match="not found"):
        Baseline.load(tmp_path / "absent.yml")


def test_invalid_yaml_is_an_error(tmp_path) -> None:
    path = tmp_path / "bad.yml"
    path.write_text("exceptions: [unclosed\n")
    with pytest.raises(BaselineError, match="cannot parse"):
        Baseline.load(path)
