"""Report format registry."""

from __future__ import annotations

from collections.abc import Callable

from aegis.models import AuditReport
from aegis.report.console import render_console
from aegis.report.html import render_html
from aegis.report.json_report import render_json
from aegis.report.markdown import render_markdown
from aegis.report.sarif import render_sarif

FORMATS: tuple[str, ...] = ("console", "json", "md", "html", "sarif")


def render_report(
    report: AuditReport,
    fmt: str,
    *,
    color: bool | None = None,
    quiet: bool = False,
    gate_reasons: list[str] | None = None,
) -> str:
    renderers: dict[str, Callable[[AuditReport], str]] = {
        "json": render_json,
        "md": render_markdown,
        "html": render_html,
        "sarif": render_sarif,
    }
    if fmt == "console":
        return render_console(report, color=color, quiet=quiet, gate_reasons=gate_reasons)
    renderer = renderers.get(fmt)
    if renderer is None:
        raise ValueError(f"unknown report format {fmt!r}; expected one of {', '.join(FORMATS)}")
    return renderer(report)


__all__ = ["FORMATS", "render_report"]
