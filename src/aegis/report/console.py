"""Human-readable console reporter."""

from __future__ import annotations

import sys
from io import StringIO

from aegis.models import SEVERITY_ORDER, AuditReport, Finding, Severity, Status
from aegis.util.text import human_join

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

SEVERITY_COLOR = {
    Severity.CRITICAL: RED + BOLD,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: BLUE,
}

STATUS_LABEL = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.ERROR: "ERROR",
    Status.NOT_APPLICABLE: " N/A",
}


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + RESET

    def severity(self, severity: Severity) -> str:
        return self.paint(severity.value.upper(), SEVERITY_COLOR[severity])

    def status(self, status: Status) -> str:
        mapping = {
            Status.PASS: (GREEN,),
            Status.FAIL: (RED,),
            Status.ERROR: (MAGENTA,),
            Status.NOT_APPLICABLE: (DIM,),
        }
        return self.paint(f"[{STATUS_LABEL[status]}]", *mapping[status])


def console_supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def render_console(
    report: AuditReport,
    *,
    color: bool | None = None,
    quiet: bool = False,
    gate_reasons: list[str] | None = None,
) -> str:
    if color is None:
        color = console_supports_color()
    palette = Palette(color and not quiet)
    out = StringIO()
    write = out.write

    if quiet:
        state = "PASS" if not gate_reasons else "FAIL"
        write(
            f"{report.score:.2f} {report.grade} failed={report.summary.failed} "
            f"errors={report.summary.errors} gate={state}\n"
        )
        return out.getvalue()

    write(
        f"{palette.paint('aegis', BOLD, CYAN)} {report.tool_version}  Linux host hardening audit\n"
    )
    write(f"Root: {report.root}\n")
    write(
        f"Rules: {report.summary.total}   Generated: {report.generated_at}   "
        f"Duration: {report.duration_ms} ms\n"
    )
    write("\n")
    write(
        f"  {palette.paint('Score', BOLD)}  {palette.paint(f'{report.score:.2f}', BOLD)}"
        f" / 100    {palette.paint('Grade', BOLD)} {palette.paint(report.grade, BOLD)}\n"
    )
    write(
        f"  {palette.paint('PASS', GREEN)} {report.summary.passed}"
        f"   {palette.paint('FAIL', RED)} {report.summary.failed}"
        f"   {palette.paint('ERROR', MAGENTA)} {report.summary.errors}"
        f"   {palette.paint('N/A', DIM)} {report.summary.not_applicable}"
        f"   {palette.paint('SUPPRESSED', YELLOW)} {report.summary.suppressed}\n"
    )
    write("\n")

    if report.summary.by_severity:
        write("Severity     Total   Pass   Fail  Error    N/A   Suppressed\n")
        for severity in SEVERITY_ORDER:
            stats = report.summary.by_severity.get(severity.value)
            if stats is None or stats.total == 0:
                continue
            write(
                f"{palette.severity(severity):<18} {stats.total:>5} {stats.passed:>6} "
                f"{stats.failed:>6} {stats.errors:>6} {stats.not_applicable:>6} "
                f"{stats.suppressed:>12}\n"
            )
        write("\n")

    if report.categories:
        write("Category                    Score   Weight   Pass   Fail  Error    N/A\n")
        for category in sorted(report.categories, key=lambda item: (item.score, item.category)):
            write(
                f"{category.category[:26]:<26} {category.score:>6.1f} "
                f"{category.passed_weight:>4}/{category.total_weight:<4} "
                f"{category.passed:>6} {category.failed:>6} {category.errors:>6} "
                f"{category.not_applicable:>6}\n"
            )
        write("\n")

    failing = [finding for finding in report.findings if finding.is_failing]
    if failing:
        write(palette.paint("Top risks", BOLD))
        write("\n")
        for index, risk in enumerate(report.top_risks, start=1):
            write(f"  {index}. {palette.severity(risk.severity)} {risk.rule_id}  {risk.title}\n")
            write(f"     {risk.message}\n")
        write("\n")

    by_category: dict[str, list[Finding]] = {}
    for finding in report.findings:
        if finding.status in (Status.FAIL, Status.ERROR) or finding.suppressed:
            by_category.setdefault(finding.category, []).append(finding)
    if by_category:
        write(palette.paint("Findings", BOLD))
        write("\n")
        for category in sorted(by_category):
            write(f"\n{palette.paint(category, BOLD, CYAN)}\n")
            for finding in by_category[category]:
                render_finding(write, palette, finding)
    elif not report.summary.failed and not report.summary.errors:
        write(palette.paint("All evaluated controls passed.", GREEN) + "\n")

    stale = report.baseline.expired
    if stale:
        write("\n" + palette.paint("Stale baseline exceptions (not suppressing)", YELLOW) + "\n")
        for item in stale:
            write(f"  {item.rule_id}  {item.detail or item.reason}\n")
    if report.baseline.unused:
        write("\n" + palette.paint("Unused baseline entries", YELLOW) + "\n")
        for item in report.baseline.unused:
            write(f"  {item.rule_id}  {item.reason}\n")
    if report.baseline.suppressed:
        write(
            f"\nBaseline: {report.baseline.suppressed} finding(s) suppressed, "
            f"{len(report.baseline.expired)} expired, "
            f"{len(report.baseline.unused)} unused.\n"
        )

    if report.errors:
        write("\n" + palette.paint("Audit errors", BOLD, MAGENTA) + "\n")
        for message in report.errors[:20]:
            write(f"  {message}\n")

    write("\n")
    if gate_reasons is None:
        verdict = "not evaluated"
        color_codes: tuple[str, ...] = (DIM,)
    elif gate_reasons:
        verdict = "FAIL"
        color_codes = (RED, BOLD)
    else:
        verdict = "PASS"
        color_codes = (GREEN, BOLD)
    write(
        f"Result: {report.summary.failed} failing, {report.summary.errors} error(s), "
        f"{report.summary.not_applicable} not applicable. "
        f"Score {report.score:.2f} ({report.grade}). Gate: {palette.paint(verdict, *color_codes)}\n"
    )
    if gate_reasons:
        for reason in gate_reasons:
            write(f"  - {reason}\n")
    if report.baseline.suppressed and report.top_risks:
        write(
            "  Note: suppressed findings are excluded from the score and gate. "
            f"Top risk: {human_join([risk.rule_id for risk in report.top_risks[:3]])}.\n"
        )
    return out.getvalue()


def render_finding(write, palette: Palette, finding: Finding) -> None:
    status = palette.status(finding.status)
    suffix = ""
    if finding.suppressed:
        suffix = palette.paint(" [suppressed]", YELLOW)
    write(f"  {status} {finding.rule_id}  {finding.title}{suffix}\n")
    write(f"         {palette.severity(finding.severity)} | {finding.category} | {finding.cis}\n")
    write(f"         {finding.message}\n")
    if finding.suppressed:
        write(
            f"         suppression: {finding.suppression_reason} "
            f"(expires {finding.suppression_expires})\n"
        )
    remediation = finding.remediation
    if remediation.text and (finding.is_failing or finding.suppressed):
        write(f"         fix: {remediation.text}\n")
    if remediation.command and finding.is_failing:
        write(f"         command: {remediation.command}\n")
