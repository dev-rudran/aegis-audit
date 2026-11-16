"""Compare two JSON audit reports and describe compliance drift."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.models import SEVERITY_ORDER, AuditReport, Finding, Severity


class DiffError(ValueError):
    """A report file could not be loaded or compared."""


@dataclass
class FindingChange:
    rule_id: str
    title: str
    severity: Severity
    category: str
    old_status: str
    new_status: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "message": self.message,
        }


@dataclass
class SeverityDelta:
    severity: Severity
    newly_failing: int = 0
    still_failing: int = 0
    newly_fixed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "newly_failing": self.newly_failing,
            "still_failing": self.still_failing,
            "newly_fixed": self.newly_fixed,
        }


@dataclass
class DiffReport:
    old_score: float
    new_score: float
    old_grade: str
    new_grade: str
    newly_failing: list[FindingChange] = field(default_factory=list)
    newly_fixed: list[FindingChange] = field(default_factory=list)
    still_failing: list[FindingChange] = field(default_factory=list)
    added_rules: list[str] = field(default_factory=list)
    removed_rules: list[str] = field(default_factory=list)
    severity_deltas: list[SeverityDelta] = field(default_factory=list)

    @property
    def score_delta(self) -> float:
        return self.new_score - self.old_score

    @property
    def regressed(self) -> bool:
        return bool(self.newly_failing) or self.score_delta < 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "old": {"score": round(self.old_score, 2), "grade": self.old_grade},
            "new": {"score": round(self.new_score, 2), "grade": self.new_grade},
            "score_delta": round(self.score_delta, 2),
            "regressed": self.regressed,
            "newly_failing": [item.to_dict() for item in self.newly_failing],
            "newly_fixed": [item.to_dict() for item in self.newly_fixed],
            "still_failing": [item.to_dict() for item in self.still_failing],
            "added_rules": list(self.added_rules),
            "removed_rules": list(self.removed_rules),
            "severity": [item.to_dict() for item in self.severity_deltas],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"

    def to_text(self) -> str:
        lines: list[str] = []
        lines.append("aegis drift report")
        lines.append(
            f"Old: score {self.old_score:.2f} ({self.old_grade})   "
            f"New: score {self.new_score:.2f} ({self.new_grade})   "
            f"Delta: {self.score_delta:+.2f}"
        )
        lines.append(
            f"Newly failing: {len(self.newly_failing)}   "
            f"Still failing: {len(self.still_failing)}   "
            f"Newly fixed: {len(self.newly_fixed)}"
        )
        lines.append("")
        lines.append("Severity      Newly failing   Still failing   Newly fixed")
        for delta in self.severity_deltas:
            lines.append(
                f"{delta.severity.value:<14}{delta.newly_failing:>13}"
                f"{delta.still_failing:>16}{delta.newly_fixed:>14}"
            )
        sections = (
            ("Newly failing", self.newly_failing),
            ("Still failing", self.still_failing),
            ("Newly fixed", self.newly_fixed),
        )
        for title, items in sections:
            lines.append("")
            lines.append(f"{title} ({len(items)})")
            if not items:
                lines.append("  none")
                continue
            for item in items:
                lines.append(
                    f"  {item.rule_id}  [{item.severity.value}] {item.title} "
                    f"({item.old_status} -> {item.new_status})"
                )
                if item.message:
                    lines.append(f"      {item.message}")
        if self.added_rules:
            lines.append("")
            lines.append(
                f"Rules added since the old report ({len(self.added_rules)}): "
                f"{', '.join(self.added_rules)}"
            )
        if self.removed_rules:
            lines.append("")
            lines.append(
                f"Rules removed since the old report ({len(self.removed_rules)}): "
                f"{', '.join(self.removed_rules)}"
            )
        return "\n".join(lines) + "\n"


def load_report(path: str | Path) -> AuditReport:
    location = Path(path)
    if not location.is_file():
        raise DiffError(f"report file not found: {location}")
    try:
        document = json.loads(location.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiffError(f"cannot parse {location}: {exc}") from exc
    if not isinstance(document, dict) or "findings" not in document:
        raise DiffError(f"{location} does not look like an aegis JSON report")
    try:
        return AuditReport.from_dict(document)
    except (KeyError, TypeError, ValueError) as exc:
        raise DiffError(f"{location} has an invalid report structure: {exc}") from exc


def diff_reports(old: AuditReport, new: AuditReport) -> DiffReport:
    old_findings = {finding.rule_id: finding for finding in old.findings}
    new_findings = {finding.rule_id: finding for finding in new.findings}
    result = DiffReport(
        old_score=old.score,
        new_score=new.score,
        old_grade=old.grade,
        new_grade=new.grade,
    )
    deltas = {severity: SeverityDelta(severity) for severity in SEVERITY_ORDER}
    for rule_id in sorted(set(old_findings) | set(new_findings)):
        old_finding = old_findings.get(rule_id)
        new_finding = new_findings.get(rule_id)
        if old_finding is None and new_finding is not None:
            result.added_rules.append(rule_id)
            if new_finding.is_failing:
                change = _change(old_finding, new_finding, "absent")
                result.newly_failing.append(change)
                deltas[new_finding.severity].newly_failing += 1
            continue
        if new_finding is None and old_finding is not None:
            result.removed_rules.append(rule_id)
            continue
        if old_finding is None or new_finding is None:  # pragma: no cover - guarded above
            raise DiffError(f"internal diff state error for {rule_id}")
        old_failing = old_finding.is_failing
        new_failing = new_finding.is_failing
        if new_failing and not old_failing:
            result.newly_failing.append(_change(old_finding, new_finding, old_finding.status.value))
            deltas[new_finding.severity].newly_failing += 1
        elif old_failing and not new_failing:
            result.newly_fixed.append(_change(old_finding, new_finding, old_finding.status.value))
            deltas[new_finding.severity].newly_fixed += 1
        elif old_failing and new_failing:
            result.still_failing.append(_change(old_finding, new_finding, old_finding.status.value))
            deltas[new_finding.severity].still_failing += 1
    result.severity_deltas = [deltas[severity] for severity in SEVERITY_ORDER]
    result.newly_failing.sort(key=lambda item: (-item.severity.rank, item.rule_id))
    result.still_failing.sort(key=lambda item: (-item.severity.rank, item.rule_id))
    result.newly_fixed.sort(key=lambda item: (-item.severity.rank, item.rule_id))
    return result


def _change(old: Finding | None, new: Finding, old_status: str) -> FindingChange:
    return FindingChange(
        rule_id=new.rule_id,
        title=new.title,
        severity=new.severity,
        category=new.category,
        old_status=old_status,
        new_status=new.status.value,
        message=new.message,
    )
