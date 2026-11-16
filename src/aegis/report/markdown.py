"""Markdown report renderer."""

from __future__ import annotations

from aegis.models import SEVERITY_ORDER, AuditReport, Finding, Status


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _code(value: str | None) -> str:
    if not value:
        return "-"
    return f"`{value.replace('`', '')}`"


def _status_label(finding: Finding) -> str:
    if finding.suppressed:
        return f"{finding.status.value} (suppressed)"
    if finding.status is Status.NOT_APPLICABLE:
        return "n/a"
    return finding.status.value


def render_markdown(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append("# aegis hardening report")
    lines.append("")
    lines.append(f"- **Root:** `{report.root}`")
    lines.append(f"- **Generated:** {report.generated_at}")
    lines.append(f"- **aegis version:** {report.tool_version}")
    lines.append(f"- **Rule set:** {report.ruleset_fingerprint}")
    lines.append("")
    lines.append("## Score")
    lines.append("")
    lines.append(f"**{report.score:.2f} / 100 - grade {report.grade}**")
    lines.append("")
    lines.append(
        f"{report.summary.passed} passed, {report.summary.failed} failed, "
        f"{report.summary.errors} errors, {report.summary.not_applicable} not applicable, "
        f"{report.summary.suppressed} suppressed."
    )
    lines.append("")
    lines.append("| Severity | Total | Pass | Fail | Error | N/A | Suppressed |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for severity in SEVERITY_ORDER:
        stats = report.summary.by_severity.get(severity.value)
        if stats is None or stats.total == 0:
            continue
        lines.append(
            f"| {severity.value} | {stats.total} | {stats.passed} | {stats.failed} | "
            f"{stats.errors} | {stats.not_applicable} | {stats.suppressed} |"
        )
    lines.append("")
    lines.append("## Categories")
    lines.append("")
    lines.append("| Category | Score | Passed weight | Total weight | Pass | Fail | N/A |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for category in sorted(report.categories, key=lambda item: (item.score, item.category)):
        lines.append(
            f"| {_escape(category.category)} | {category.score:.1f} | "
            f"{category.passed_weight} | {category.total_weight} | {category.passed} | "
            f"{category.failed} | {category.not_applicable} |"
        )
    lines.append("")
    if report.top_risks:
        lines.append("## Top risks")
        lines.append("")
        for index, risk in enumerate(report.top_risks, start=1):
            lines.append(
                f"{index}. **{risk.severity.value.upper()}** `{risk.rule_id}` - "
                f"{_escape(risk.title)}"
            )
            lines.append(f"   {_escape(risk.message)}")
        lines.append("")

    failing = [finding for finding in report.findings if finding.is_failing]
    lines.append("## Findings")
    lines.append("")
    if failing:
        lines.append("| Rule | Severity | Category | CIS | Status | Path |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for finding in failing:
            lines.append(
                f"| `{finding.rule_id}` {_escape(finding.title)} | {finding.severity.value} | "
                f"{_escape(finding.category)} | {_escape(finding.cis)} | "
                f"{_status_label(finding)} | {_code(finding.path)} |"
            )
        lines.append("")
        lines.append("## Remediation")
        lines.append("")
        for finding in failing:
            lines.append(f"### {finding.rule_id} - {_escape(finding.title)}")
            lines.append("")
            lines.append(f"- Severity: **{finding.severity.value}**")
            lines.append(f"- CIS: {_escape(finding.cis)}")
            lines.append(f"- Result: {_escape(finding.message)}")
            if finding.path:
                lines.append(f"- Path: {_code(finding.path)}")
            if finding.remediation.text:
                lines.append("")
                lines.append(finding.remediation.text)
            if finding.remediation.command:
                lines.append("")
                lines.append("```sh")
                lines.append(finding.remediation.command)
                lines.append("```")
            lines.append("")
    else:
        lines.append("All evaluated controls passed.")
        lines.append("")

    suppressed = [finding for finding in report.findings if finding.suppressed]
    if suppressed:
        lines.append("## Suppressed findings")
        lines.append("")
        lines.append("| Rule | Severity | Reason | Expires |")
        lines.append("| --- | --- | --- | --- |")
        for finding in suppressed:
            lines.append(
                f"| `{finding.rule_id}` | {finding.severity.value} | "
                f"{_escape(finding.suppression_reason or '')} | "
                f"{finding.suppression_expires or ''} |"
            )
        lines.append("")

    if report.baseline.expired or report.baseline.unused:
        lines.append("## Baseline exceptions")
        lines.append("")
        if report.baseline.expired:
            lines.append("Expired entries (not suppressing):")
            lines.append("")
            for item in report.baseline.expired:
                lines.append(f"- `{item.rule_id}` expired {item.expires}: {_escape(item.reason)}")
            lines.append("")
        if report.baseline.unused:
            lines.append("Unused entries:")
            lines.append("")
            for item in report.baseline.unused:
                lines.append(f"- `{item.rule_id}`: {_escape(item.reason)}")
            lines.append("")

    if report.errors:
        lines.append("## Errors")
        lines.append("")
        for message in report.errors:
            lines.append(f"- {_escape(message)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
