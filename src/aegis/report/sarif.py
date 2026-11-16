"""SARIF 2.1.0 report serializer."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote

from aegis.models import AuditReport, Finding, Severity, Status

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def render_sarif(report: AuditReport) -> str:
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for finding in report.findings:
        if finding.rule_id in rule_index:
            continue
        rule_index[finding.rule_id] = len(rules)
        rules.append(_rule_descriptor(finding))
    results = [
        _result(finding, rule_index[finding.rule_id], report.root)
        for finding in report.findings
        if finding.status in (Status.FAIL, Status.ERROR)
    ]
    payload = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aegis",
                        "fullName": "aegis Linux host hardening auditor",
                        "version": report.tool_version,
                        "informationUri": "https://github.com/dev-rudran/aegis-audit",
                        "semanticVersion": report.tool_version,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": report.generated_at,
                        "endTimeUtc": report.generated_at,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": message},
                                "descriptor": {"id": "AEGIS-AUDIT-ERROR"},
                            }
                            for message in report.errors
                        ],
                    }
                ],
                "results": results,
                "properties": {
                    "score": round(report.score, 2),
                    "grade": report.grade,
                    "root": report.root,
                    "schemaVersion": report.schema_version,
                    "rulesetFingerprint": report.ruleset_fingerprint,
                    "summary": report.summary.to_dict(),
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _rule_descriptor(finding: Finding) -> dict:
    help_text = finding.remediation.text
    if not help_text:
        help_text = "Review the CIS control and remediate the reported condition."
    if finding.remediation.command:
        help_text += f"\n\nSuggested command:\n{finding.remediation.command}"
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {
            "text": f"{finding.title}. Category: {finding.category}. CIS: {finding.cis}."
        },
        "help": {
            "text": help_text,
            "markdown": f"**{finding.title}**\n\n{help_text}\n\nCIS reference: `{finding.cis}`",
        },
        "defaultConfiguration": {"level": LEVEL[finding.severity]},
        "properties": {
            "severity": finding.severity.value,
            "category": finding.category,
            "cis": finding.cis,
            "tags": list(finding.tags),
            "security-severity": SECURITY_SEVERITY[finding.severity],
        },
    }


def _result(finding: Finding, rule_index: int, root: str) -> dict:
    result: dict = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVEL[finding.severity],
        "message": {"text": f"{finding.message} (CIS {finding.cis})"},
        "properties": {
            "severity": finding.severity.value,
            "category": finding.category,
            "cis": finding.cis,
            "status": finding.status.value,
            "suppressed": finding.suppressed,
            "evidence": finding.evidence,
        },
        "partialFingerprints": {
            "aegisFinding/v1": _fingerprint(finding),
        },
    }
    location = _physical_location(finding, root)
    if location is not None:
        result["locations"] = [{"physicalLocation": location}]
    if finding.suppressed:
        result["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": (
                    f"{finding.suppression_reason or 'baseline exception'}; "
                    f"expires {finding.suppression_expires or 'unknown'}"
                ),
            }
        ]
    return result


def _physical_location(finding: Finding, root: str) -> dict | None:
    if not finding.path or not finding.path.startswith("/"):
        return None
    try:
        root_path = Path(root).resolve()
        candidate = (root_path / finding.path.lstrip("/")).resolve()
        if candidate != root_path and root_path not in candidate.parents:
            return None
        if not candidate.is_file():
            return None
    except (OSError, ValueError):
        return None
    relative = finding.path.lstrip("/")
    line = _line_from_evidence(finding, candidate)
    return {
        "artifactLocation": {"uri": quote(relative, safe="/")},
        "region": {"startLine": line, "startColumn": 1},
    }


def _line_from_evidence(finding: Finding, candidate: Path) -> int:
    line = finding.evidence.get("line")
    if isinstance(line, int) and line > 0:
        return line
    return 1


def _fingerprint(finding: Finding) -> str:
    payload = f"{finding.rule_id}\0{finding.path or ''}\0{finding.message}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def is_valid_uri(value: str) -> bool:
    """Utility used by tests to confirm artifact URIs are parseable."""
    from urllib.parse import urlparse

    parsed = urlparse(value)
    return not parsed.scheme and not os.path.isabs(value)
