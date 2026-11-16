"""Tests for rule loading, selection, auditing, and baseline integration."""

from __future__ import annotations

import re
from datetime import date, timedelta

import pytest
import yaml

from aegis.baseline import Baseline
from aegis.engine import (
    RuleLoadError,
    audit,
    collect_rules,
    load_rules,
    rule_fingerprint,
    select_rules,
)
from aegis.models import ID_PATTERN


def test_bundled_pack_is_complete_and_well_formed(rules) -> None:
    assert len(rules) >= 45
    assert len(rules) == 81
    ids = [rule.id for rule in rules]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    assert all(ID_PATTERN.match(rule_id) for rule_id in ids)
    assert all(rule.title and rule.description and rule.cis for rule in rules)
    assert all(rule.remediation.text for rule in rules)
    assert all(rule.tags for rule in rules)
    categories = {rule.category for rule in rules}
    assert categories == {
        "SSH",
        "Crypto",
        "Kernel",
        "Filesystem",
        "Accounts",
        "Logging",
        "Firewall",
        "Packages",
        "Services",
    }
    severities = {rule.severity.value for rule in rules}
    assert {"critical", "high", "medium", "low"} <= severities


def test_structured_fixes_are_declared_safe_and_valid(rules) -> None:
    structured = [rule for rule in rules if rule.remediation.fix is not None]
    assert len(structured) >= 25
    for rule in structured:
        assert rule.remediation.safe is True, rule.id
        assert rule.remediation.fix is not None
        assert rule.remediation.fix["type"] in {
            "sshd_set",
            "sysctl_set",
            "file_mode",
            "file_owner",
            "login_defs_set",
            "pwquality_set",
            "config_set",
            "create_file",
        }


def test_ruleset_fingerprint_is_stable_and_sensitive(rules) -> None:
    fingerprint = rule_fingerprint(rules)
    assert re.fullmatch(r"[0-9a-f]{16}", fingerprint)
    assert rule_fingerprint(list(rules)) == fingerprint
    assert rule_fingerprint(rules[:10]) != fingerprint


def test_rule_selection_by_category_tag_and_exclusion(rules) -> None:
    ssh = select_rules(rules, categories=["ssh"])
    assert ssh and all(rule.category == "SSH" for rule in ssh)
    crypto = select_rules(rules, tags=["crypto"])
    assert crypto and all("crypto" in rule.tags for rule in crypto)
    without_crypto = select_rules(rules, tags=["crypto"], exclude_tags=["crypto"])
    assert without_crypto == []
    everything = select_rules(rules)
    assert everything == rules


def test_audit_hardened_fixture_scores_one_hundred(hardened_root) -> None:
    report = audit(hardened_root)
    assert report.score == 100.0
    assert report.grade == "A"
    assert report.summary.failed == 0
    assert report.summary.errors == 0
    assert report.summary.passed == 81
    assert len(report.findings) == 81
    assert len(report.categories) == 9
    assert report.top_risks == []
    assert not report.errors


def test_audit_vulnerable_fixture_matches_recorded_score(vulnerable_root) -> None:
    report = audit(vulnerable_root)
    assert report.grade == "F"
    assert report.score == pytest.approx(3.8338658146964857)
    assert report.summary.passed == 3
    assert report.summary.failed == 78
    assert report.summary.errors == 0
    assert len(report.top_risks) == 5
    assert report.top_risks[0].severity.value == "critical"


def test_baseline_suppresses_failures_and_changes_the_score(vulnerable_root, tmp_path) -> None:
    initial = audit(vulnerable_root)
    critical = [
        finding.rule_id
        for finding in initial.findings
        if finding.is_failing and finding.severity.value == "critical"
    ]
    assert len(critical) == 5
    document = {
        "exceptions": [
            {
                "id": rule_id,
                "reason": "compensating control in place",
                "expires": (date.today() + timedelta(days=30)).isoformat(),
            }
            for rule_id in critical
        ]
    }
    path = tmp_path / "baseline.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    report = audit(vulnerable_root, baseline=Baseline.load(path))
    assert report.baseline.suppressed == 5
    assert report.score > initial.score
    assert all(finding.suppressed for finding in report.findings if finding.rule_id in critical)


def test_category_filter_limits_the_audit(hardened_root) -> None:
    report = audit(hardened_root, categories=["Kernel"])
    assert len(report.findings) == 14
    assert {finding.category for finding in report.findings} == {"Kernel"}


def test_unknown_or_exclusive_filters_raise(vulnerable_root, rules) -> None:
    with pytest.raises(RuleLoadError, match="no rules matched"):
        audit(vulnerable_root, rules=rules, categories=["Nonexistent"])


def test_collect_rules_reports_every_problem(tmp_path) -> None:
    valid = {
        "id": "AEGIS-8000",
        "title": "Custom control",
        "description": "A custom test control.",
        "severity": "low",
        "category": "Custom",
        "cis": "CUSTOM-1",
        "check": {"type": "file_exists", "params": {"path": "/etc/custom"}},
        "remediation": {"text": "Create the file."},
        "tags": ["custom"],
    }
    bad_params = {**valid, "id": "AEGIS-8001", "check": {"type": "sysctl", "params": {}}}
    unknown_type = {
        **valid,
        "id": "AEGIS-8002",
        "check": {"type": "no_such_check", "params": {}},
    }
    unsafe_fix = {
        **valid,
        "id": "AEGIS-8003",
        "remediation": {
            "text": "Change the mode.",
            "safe": False,
            "fix": {"type": "file_mode", "path": "/etc/custom", "mode": "0600"},
        },
    }
    (tmp_path / "one.yml").write_text(yaml.safe_dump([valid, bad_params]), encoding="utf-8")
    (tmp_path / "two.yml").write_text(yaml.safe_dump([unknown_type, unsafe_fix]), encoding="utf-8")
    (tmp_path / "three.yml").write_text(yaml.safe_dump([valid]), encoding="utf-8")

    found, errors = collect_rules(tmp_path)
    assert [rule.id for rule in found] == ["AEGIS-8000"]
    assert len(errors) == 5
    joined = "\n".join(errors)
    assert "check params" in joined
    assert "unknown check type" in joined
    assert "requires remediation.safe: true" in joined
    assert "duplicate rule id" in joined


def test_load_rules_wraps_collection_errors(tmp_path) -> None:
    (tmp_path / "broken.yml").write_text("rules: [not-a-mapping]\n", encoding="utf-8")
    with pytest.raises(RuleLoadError) as excinfo:
        load_rules(tmp_path)
    assert excinfo.value.errors
    with pytest.raises(RuleLoadError, match=r"invalid rule pack|empty"):
        empty = tmp_path / "empty"
        empty.mkdir()
        load_rules(empty)
