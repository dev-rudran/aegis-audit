"""Weighted compliance scoring, grade calculation, and gate evaluation."""

from __future__ import annotations

from collections import defaultdict

from aegis.models import (
    SEVERITY_ORDER,
    AuditReport,
    CategoryScore,
    Finding,
    Severity,
    SeverityStats,
    Status,
    Summary,
    TopRisk,
)

GRADE_THRESHOLDS: tuple[tuple[float, str], ...] = (
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
)


def weighted_score(findings: list[Finding]) -> float:
    """Return 0-100 using severity weights; NA and suppressed findings are excluded."""
    total = 0
    passed = 0
    for finding in findings:
        if not finding.counts_in_score:
            continue
        weight = finding.severity.weight
        total += weight
        if finding.status is Status.PASS:
            passed += weight
    if total == 0:
        return 100.0
    return 100.0 * passed / total


def grade_for_score(score: float) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def build_summary(findings: list[Finding]) -> Summary:
    summary = Summary(total=len(findings))
    summary.by_severity = {severity.value: SeverityStats() for severity in SEVERITY_ORDER}
    for finding in findings:
        bucket = summary.by_severity[finding.severity.value]
        bucket.total += 1
        if finding.suppressed:
            summary.suppressed += 1
            bucket.suppressed += 1
        elif finding.status is Status.PASS:
            summary.passed += 1
            bucket.passed += 1
        elif finding.status is Status.FAIL:
            summary.failed += 1
            bucket.failed += 1
        elif finding.status is Status.ERROR:
            summary.errors += 1
            bucket.errors += 1
        else:
            summary.not_applicable += 1
            bucket.not_applicable += 1
    return summary


def category_breakdown(findings: list[Finding]) -> list[CategoryScore]:
    totals: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "not_applicable": 0,
            "suppressed": 0,
            "total_weight": 0,
            "passed_weight": 0,
        }
    )
    for finding in findings:
        bucket = totals[finding.category]
        bucket["total"] += 1
        if finding.suppressed:
            bucket["suppressed"] += 1
            continue
        if finding.status is Status.NOT_APPLICABLE:
            bucket["not_applicable"] += 1
            continue
        weight = finding.severity.weight
        bucket["total_weight"] += weight
        if finding.status is Status.PASS:
            bucket["passed"] += 1
            bucket["passed_weight"] += weight
        elif finding.status is Status.FAIL:
            bucket["failed"] += 1
        else:
            bucket["errors"] += 1
    categories: list[CategoryScore] = []
    for name in sorted(totals):
        bucket = totals[name]
        score = (
            100.0 * bucket["passed_weight"] / bucket["total_weight"]
            if bucket["total_weight"]
            else 100.0
        )
        categories.append(
            CategoryScore(
                category=name,
                score=score,
                total_weight=bucket["total_weight"],
                passed_weight=bucket["passed_weight"],
                total=bucket["total"],
                passed=bucket["passed"],
                failed=bucket["failed"],
                errors=bucket["errors"],
                not_applicable=bucket["not_applicable"],
                suppressed=bucket["suppressed"],
            )
        )
    return categories


def top_risks(findings: list[Finding], limit: int = 5) -> list[TopRisk]:
    failing = [finding for finding in findings if finding.is_failing]
    failing.sort(
        key=lambda item: (
            -item.severity.rank,
            -item.severity.weight,
            item.category,
            item.rule_id,
        )
    )
    return [
        TopRisk(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            category=finding.category,
            message=finding.message,
            path=finding.path,
        )
        for finding in failing[:limit]
    ]


def apply_scoring(report: AuditReport) -> AuditReport:
    """Populate score, grade, summary, categories, and top risks in place."""
    report.score = weighted_score(report.findings)
    report.grade = grade_for_score(report.score)
    report.summary = build_summary(report.findings)
    report.categories = category_breakdown(report.findings)
    report.top_risks = top_risks(report.findings)
    return report


def gate_failures(
    report: AuditReport, *, fail_on: Severity | None, min_score: float | None
) -> list[str]:
    """Return human-readable policy violations.  Empty list means the gate passed."""
    reasons: list[str] = []
    if fail_on is not None:
        severities = {severity for severity in Severity if severity.rank >= fail_on.rank}
        offenders = [
            finding
            for finding in report.findings
            if finding.is_failing and finding.severity in severities
        ]
        if offenders:
            counts = ", ".join(
                f"{severity.value}={sum(1 for item in offenders if item.severity is severity)}"
                for severity in SEVERITY_ORDER
                if any(item.severity is severity for item in offenders)
            )
            reasons.append(
                f"{len(offenders)} finding(s) at or above {fail_on.value} severity ({counts})"
            )
    if min_score is not None and report.score < min_score:
        reasons.append(f"score {report.score:.2f} is below --min-score {min_score:g}")
    return reasons
