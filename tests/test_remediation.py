"""Tests for structured, safe remediation and its text editors."""

from __future__ import annotations

import stat

import pytest

from aegis.models import AuditReport, Finding, Severity, Status
from aegis.remediation import (
    APPLIED,
    ERROR,
    UNCHANGED,
    WOULD_APPLY,
    FixPlanner,
    edit_assignment,
    edit_sshd_config,
    validate_fix,
)
from aegis.util.fs import RootFS
from tests.helpers import make_rule, write_file


def report_for(rule_id: str, path: str = "/etc/ssh/sshd_config") -> AuditReport:
    finding = Finding(
        rule_id=rule_id,
        title="Synthetic finding",
        severity=Severity.HIGH,
        category="Test",
        cis="TEST-1.1",
        status=Status.FAIL,
        message="not compliant",
        path=path,
    )
    return AuditReport(
        schema_version="1.0",
        tool_version="0.1.0",
        generated_at="2026-01-01T00:00:00Z",
        root="/",
        findings=[finding],
    )


def sshd_rule(rule_id: str = "AEGIS-9000", value: str = "no"):
    return make_rule(
        "sshd",
        {"key": "PermitRootLogin", "value": value},
        rule_id=rule_id,
        fix={
            "type": "sshd_set",
            "path": "/etc/ssh/sshd_config",
            "key": "PermitRootLogin",
            "value": value,
        },
        safe=True,
    )


def test_edit_sshd_updates_first_global_directive_and_preserves_context() -> None:
    text = (
        "# managed by hand\n"
        "Port 22\n"
        "PermitRootLogin yes # temporary\n"
        "PasswordAuthentication no\n"
        "Match User backup\n"
        "    PermitRootLogin yes\n"
    )
    after, changed, added = edit_sshd_config(text, "PermitRootLogin", "no")
    assert changed is True
    assert added is False
    assert "PermitRootLogin no # temporary" in after
    assert "PasswordAuthentication no" in after
    assert "    PermitRootLogin yes" in after
    assert after.count("PermitRootLogin") == 2


def test_edit_sshd_inserts_global_directive_before_match_block() -> None:
    text = "Port 22\nMatch User backup\n    X11Forwarding yes\n"
    after, changed, added = edit_sshd_config(text, "PermitRootLogin", "no")
    assert (changed, added) == (True, True)
    lines = after.splitlines()
    assert lines.index("PermitRootLogin no") < lines.index("Match User backup")


def test_edit_sshd_is_a_noop_when_already_compliant() -> None:
    text = "PermitRootLogin no\n"
    assert edit_sshd_config(text, "PermitRootLogin", "no") == (text, False, False)


def test_edit_assignment_preserves_case_spacing_and_comments() -> None:
    text = (
        "# kernel forwarding\n"
        "net.ipv4.ip_forward = 0\n"
        "Net.IPv4.IP_Forward=0 # temporary\n"
        "unrelated = keep\n"
    )
    after, changed, added = edit_assignment(text, "net.ipv4.ip_forward", "1", separator="=")
    assert (changed, added) == (True, False)
    assert "net.ipv4.ip_forward = 1" in after
    assert "Net.IPv4.IP_Forward=1 # temporary" in after
    assert "unrelated = keep" in after


def test_edit_assignment_appends_and_preserves_key_case() -> None:
    text = "# login defaults\nPASS_MAX_DAYS 99999\n"
    after, changed, added = edit_assignment(
        text, "PASS_MAX_DAYS", "90", separator=None, preserve_separator=True
    )
    assert (changed, added) == (True, False)
    assert "PASS_MAX_DAYS 90" in after

    appended, changed, added = edit_assignment("# only a comment\n", "PASS_MIN_LEN", "14")
    assert (changed, added) == (True, True)
    assert appended.endswith("PASS_MIN_LEN=14\n")


@pytest.mark.parametrize(
    ("fix", "message"),
    [
        ({"type": "unknown", "path": "/x", "key": "k", "value": "v"}, "unsupported fix type"),
        ({"type": "file_mode", "path": "relative", "mode": "0600"}, "requires an absolute path"),
        ({"type": "file_mode", "path": "/x", "mode": "0999"}, "mode"),
        ({"type": "sshd_set", "path": "/x", "value": "v"}, "requires a non-empty key"),
        ({"type": "sshd_set", "path": "/x", "key": "k"}, "requires a scalar value"),
        (
            {"type": "config_set", "path": "/x", "key": "k", "value": "v", "separator": "|"},
            "separator",
        ),
        ({"type": "create_file", "path": "/x"}, "requires string content"),
    ],
)
def test_validate_fix_reports_actionable_errors(fix: dict, message: str) -> None:
    errors = validate_fix(fix)
    assert errors
    assert any(message in item for item in errors)


def test_dry_run_never_writes(fresh_root) -> None:
    path = write_file(fresh_root, "/etc/ssh/sshd_config", "PermitRootLogin yes\n", mode=0o644)
    before = path.read_bytes()
    result = FixPlanner(RootFS(fresh_root)).plan(report_for("AEGIS-9000"), [sshd_rule()])
    assert result.dry_run is True
    assert [item.status for item in result.outcomes] == [WOULD_APPLY]
    assert result.outcomes[0].diff
    assert path.read_bytes() == before
    assert not (path.parent / "sshd_config.aegis.bak").exists()


def test_apply_writes_backup_and_preserves_mode(fresh_root) -> None:
    path = write_file(fresh_root, "/etc/ssh/sshd_config", "PermitRootLogin yes\n", mode=0o640)
    result = FixPlanner(RootFS(fresh_root), apply=True).plan(
        report_for("AEGIS-9000"), [sshd_rule()]
    )
    outcome = result.outcomes[0]
    assert outcome.status == APPLIED
    assert path.read_text() == "PermitRootLogin no\n"
    backup = path.parent / "sshd_config.aegis.bak"
    assert backup.read_text() == "PermitRootLogin yes\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert outcome.backup == "/etc/ssh/sshd_config.aegis.bak"


def test_second_apply_is_idempotent(fresh_root) -> None:
    path = write_file(fresh_root, "/etc/ssh/sshd_config", "PermitRootLogin yes\n", mode=0o640)
    report = report_for("AEGIS-9000")
    FixPlanner(RootFS(fresh_root), apply=True).plan(report, [sshd_rule()])
    second = FixPlanner(RootFS(fresh_root), apply=True).plan(report, [sshd_rule()])
    assert [item.status for item in second.outcomes] == [UNCHANGED]
    assert path.read_text() == "PermitRootLogin no\n"
    assert path.parent.joinpath("sshd_config.aegis.bak").read_text() == "PermitRootLogin yes\n"


def test_unsafe_rule_is_never_applied(fresh_root) -> None:
    path = write_file(fresh_root, "/etc/secret.conf", "data\n", mode=0o666)
    rule = make_rule(
        "file_mode",
        {"path": "/etc/secret.conf", "max_mode": "0600"},
        fix={"type": "file_mode", "path": "/etc/secret.conf", "mode": "0600"},
        safe=False,
    )
    result = FixPlanner(RootFS(fresh_root), apply=True).plan(report_for("AEGIS-9000"), [rule])
    assert result.outcomes == []
    assert result.manual_rules == ["AEGIS-9000"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o666
    assert path.read_text() == "data\n"


def test_missing_text_target_reports_error_without_creating_it(fresh_root) -> None:
    rule = make_rule(
        "auditd",
        {"kind": "config", "key": "space_left_action", "allowed": ["email"]},
        fix={
            "type": "config_set",
            "path": "/etc/audit/auditd.conf",
            "key": "space_left_action",
            "value": "email",
        },
        safe=True,
    )
    result = FixPlanner(RootFS(fresh_root), apply=True).plan(report_for("AEGIS-9000"), [rule])
    assert [item.status for item in result.outcomes] == [ERROR]
    assert "does not exist" in result.outcomes[0].message
    assert not (fresh_root / "etc/audit/auditd.conf").exists()


def test_file_mode_fix_applies_exact_permissions(fresh_root) -> None:
    path = write_file(fresh_root, "/etc/shadow", "secret\n", mode=0o644)
    rule = make_rule(
        "file_mode",
        {"path": "/etc/shadow", "max_mode": "0640"},
        fix={"type": "file_mode", "path": "/etc/shadow", "mode": "0640"},
        safe=True,
    )
    result = FixPlanner(RootFS(fresh_root), apply=True).plan(report_for("AEGIS-9000"), [rule])
    assert result.outcomes[0].status == APPLIED
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert "0644 -> 0640" in result.outcomes[0].message


def test_create_file_fix_is_applied_with_requested_mode(fresh_root) -> None:
    (fresh_root / "etc/security/limits.d").mkdir(parents=True)
    rule = make_rule(
        "file_exists",
        {"path": "/etc/security/limits.d/99-aegis.conf"},
        fix={
            "type": "create_file",
            "path": "/etc/security/limits.d/99-aegis.conf",
            "content": "* hard core 0\n",
            "mode": "0640",
        },
        safe=True,
    )
    report = report_for("AEGIS-9000", "/etc/security/limits.d/99-aegis.conf")
    result = FixPlanner(RootFS(fresh_root), apply=True).plan(report, [rule])
    target = fresh_root / "etc/security/limits.d/99-aegis.conf"
    assert result.outcomes[0].status == APPLIED
    assert target.read_text() == "* hard core 0\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    again = FixPlanner(RootFS(fresh_root), apply=True).plan(report, [rule])
    assert again.outcomes[0].status == UNCHANGED


def test_path_escape_is_refused(fresh_root) -> None:
    rule = make_rule(
        "file_content",
        {"path": "/etc/passwd"},
        fix={
            "type": "config_set",
            "path": "/etc/../../../tmp/aegis-escape.conf",
            "key": "k",
            "value": "v",
        },
        safe=True,
    )
    result = FixPlanner(RootFS(fresh_root), apply=True).plan(report_for("AEGIS-9000"), [rule])
    assert result.outcomes[0].status == ERROR
    assert "escapes audit root" in result.outcomes[0].message
