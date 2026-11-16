"""End-to-end tests for the command-line interface."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, timedelta

import pytest
import yaml

from aegis.cli import main as cli_main
from aegis.engine import audit


def run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    try:
        code = cli_main(list(args))
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_version_subcommands(capsys) -> None:
    code, out, err = run(capsys, "version")
    assert code == 0
    assert out.startswith("aegis 0.1.0 (report schema 1.0)")
    assert err == ""

    code, out, _ = run(capsys, "version", "--json")
    payload = json.loads(out)
    assert payload["tool"] == "aegis"
    assert payload["version"] == "0.1.0"
    assert payload["schema_version"] == "1.0"

    code, out, _ = run(capsys, "--version")
    assert code == 0
    assert out.strip() == "aegis 0.1.0"


def test_default_audit_passes_on_hardened_host(capsys, hardened_root) -> None:
    code, out, err = run(capsys, "--root", str(hardened_root), "--quiet")
    assert code == 0
    assert out.strip() == "100.00 A failed=0 errors=0 gate=PASS"
    assert err == ""


def test_default_gate_fails_on_critical_findings(capsys, vulnerable_root) -> None:
    code, out, err = run(capsys, "--root", str(vulnerable_root), "--quiet")
    assert code == 1
    assert "gate=FAIL" in out
    assert err == ""


def test_fail_on_never_disables_the_gate(capsys, vulnerable_root) -> None:
    code, out, _ = run(capsys, "--root", str(vulnerable_root), "--fail-on", "never", "--quiet")
    assert code == 0
    assert "gate=PASS" in out


def test_min_score_failure_is_reported(capsys, vulnerable_root) -> None:
    code, out, _ = run(capsys, "--root", str(vulnerable_root), "--min-score", "90")
    assert code == 1
    assert "below --min-score 90" in out


def test_invalid_inputs_exit_two(capsys, tmp_path) -> None:
    code, _, err = run(capsys, "--root", str(tmp_path / "missing"), "--quiet")
    assert code == 2
    assert "audit root does not exist" in err

    code, _, err = run(capsys, "--root", str(tmp_path), "--min-score", "101")
    assert code == 2
    assert "between 0 and 100" in err

    baseline = tmp_path / "absent.yml"
    code, _, err = run(capsys, "--baseline", str(baseline), "--root", str(tmp_path))
    assert code == 2
    assert "baseline file not found" in err


def test_output_format_is_inferred_from_extension(capsys, tmp_path, vulnerable_root) -> None:
    report = tmp_path / "reports" / "audit.json"
    code, out, err = run(capsys, "--root", str(vulnerable_root), "--quiet", "--output", str(report))
    assert code == 1
    assert out == ""
    assert f"Report written to {report}" in err
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["grade"] == "F"
    assert len(payload["findings"]) == 81


def test_sarif_can_be_written_to_stdout(capsys, vulnerable_root) -> None:
    code, out, err = run(capsys, "--root", str(vulnerable_root), "-f", "sarif", "-o", "-")
    assert code == 1
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    assert err == ""


def test_baseline_suppresses_critical_gate_failures(capsys, tmp_path, vulnerable_root) -> None:
    report = audit(vulnerable_root)
    critical = [
        finding.rule_id
        for finding in report.findings
        if finding.is_failing and finding.severity.value == "critical"
    ]
    baseline = tmp_path / "baseline.yml"
    baseline.write_text(
        yaml.safe_dump(
            {
                "exceptions": [
                    {
                        "id": rule_id,
                        "reason": "compensating control",
                        "expires": (date.today() + timedelta(days=30)).isoformat(),
                    }
                    for rule_id in critical
                ]
            }
        ),
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "--root", str(vulnerable_root), "--baseline", str(baseline))
    assert code == 0
    assert "5 finding(s) suppressed" in out
    assert "[suppressed]" in out
    assert "Gate: PASS" in out


def test_rules_list_show_and_explain(capsys) -> None:
    code, out, _ = run(capsys, "rules", "list")
    assert code == 0
    assert out.startswith("ID")
    assert "AEGIS-0001" in out
    assert "81 rule(s)." in out

    code, out, _ = run(capsys, "rules", "list", "--json", "--category", "SSH")
    assert code == 0
    payload = json.loads(out)
    assert len(payload) == 13
    assert all(item["category"] == "SSH" for item in payload)

    code, out, _ = run(capsys, "rules", "show", "AEGIS-0002")
    assert code == 0
    document = yaml.safe_load(out)
    assert document["id"] == "AEGIS-0002"
    assert document["check"]["type"] == "sshd"

    code, out, _ = run(capsys, "explain", "AEGIS-0002")
    assert code == 0
    assert "AEGIS-0002  SSH root login is permitted" in out
    assert "safe automatic fix: yes" in out
    assert "CIS Ubuntu Linux 22.04 5.3.7" in out


def test_rules_validation_and_unknown_ids(capsys, tmp_path) -> None:
    code, out, _ = run(capsys, "rules", "validate")
    assert code == 0
    assert "Rule pack valid: 81 rules from 10 file(s)" in out
    assert "Check types exercised: 17 of 18 registered" in out

    code, out, _ = run(capsys, "rules", "validate", "--json")
    payload = json.loads(out)
    assert payload["valid"] is True
    assert payload["rules"] == 81
    assert payload["errors"] == []

    bad = tmp_path / "rules"
    bad.mkdir()
    (bad / "bad.yml").write_text("- id: NOPE\n", encoding="utf-8")
    code, _, err = run(capsys, "rules", "validate", "--rules-dir", str(bad))
    assert code == 2
    assert "Rule pack invalid" in err
    assert "id must match" in err

    code, _, err = run(capsys, "explain", "AEGIS-9999")
    assert code == 2
    assert "unknown rule id" in err

    code, _, err = run(capsys, "rules")
    assert code == 2
    assert "missing rules action" in err


def test_rules_show_requires_a_known_id(capsys) -> None:
    code, _, err = run(capsys, "rules", "show", "AEGIS-0000")
    assert code == 2
    assert "unknown rule id" in err


def test_diff_detects_regression_and_emits_json(
    capsys, tmp_path, hardened_root, vulnerable_root
) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    run(capsys, "--root", str(hardened_root), "-f", "json", "-o", str(old), "--quiet")
    run(capsys, "--root", str(vulnerable_root), "-f", "json", "-o", str(new), "--quiet")

    code, out, _ = run(capsys, "diff", str(old), str(new))
    assert code == 1
    assert "Delta: -96.17" in out
    assert "Newly failing (78)" in out
    assert "Still failing (0)" in out

    code, out, _ = run(capsys, "diff", str(old), str(new), "--json")
    assert code == 1
    payload = json.loads(out)
    assert payload["regressed"] is True
    assert payload["score_delta"] == -96.17
    assert len(payload["newly_failing"]) == 78

    code, _, _ = run(capsys, "diff", str(old), str(new), "--allow-regression", "--json")
    assert code == 0


def test_remediation_dry_run_leaves_files_untouched(capsys, vulnerable_copy) -> None:
    target = vulnerable_copy / "etc/ssh/sshd_config"
    before = target.read_bytes()
    code, _, err = run(capsys, "--root", str(vulnerable_copy), "--remediate", "--quiet")
    assert code == 1
    assert "Remediation plan (dry run):" in err
    assert "WOULD_APPLY  AEGIS-0002" in err
    assert "Manual remediation required" in err
    assert target.read_bytes() == before
    assert not target.with_name("sshd_config.aegis.bak").exists()


def test_apply_writes_fixes_and_reaudits(capsys, vulnerable_copy) -> None:
    target = vulnerable_copy / "etc/ssh/sshd_config"
    code, out, err = run(capsys, "--root", str(vulnerable_copy), "--apply", "--quiet")
    assert code in (0, 1)
    assert "Remediation plan (apply):" in err
    assert "Re-audited after" in err
    assert "applied fix(es): score 3.83 (F) ->" in err
    assert "PermitRootLogin no" in target.read_text()
    assert target.with_name("sshd_config.aegis.bak").read_text().count("PermitRootLogin yes") == 1
    assert "gate=" in out


def test_no_color_and_quiet_flags(capsys, vulnerable_root) -> None:
    code, out, _ = run(capsys, "--root", str(vulnerable_root), "--no-color", "--quiet")
    assert code == 1
    assert "\x1b" not in out
    assert len(out.strip().splitlines()) == 1


def test_module_entrypoint_works_in_a_subprocess(tmp_path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "aegis", "version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.startswith("aegis 0.1.0")


def test_output_directory_is_created(capsys, tmp_path, hardened_root) -> None:
    destination = tmp_path / "deep" / "nested" / "report.md"
    code, _, err = run(capsys, "--root", str(hardened_root), "--quiet", "-o", str(destination))
    assert code == 0
    assert destination.is_file()
    assert "Report written to" in err


def test_explain_rejects_malformed_ids(capsys) -> None:
    code, _, err = run(capsys, "explain", "not-an-id")
    assert code == 2
    assert "unknown rule id" in err
