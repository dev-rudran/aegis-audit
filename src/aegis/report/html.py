"""Standalone HTML report renderer.

The output is one file with inline CSS and JavaScript.  It references no
network resources and escapes every dynamic value.
"""

from __future__ import annotations

import html
from typing import Any

from aegis.models import SEVERITY_ORDER, AuditReport, Finding, Severity, Status

SEVERITY_CLASS = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH: "sev-high",
    Severity.MEDIUM: "sev-medium",
    Severity.LOW: "sev-low",
    Severity.INFO: "sev-info",
}

STATUS_CLASS = {
    Status.PASS: "status-pass",
    Status.FAIL: "status-fail",
    Status.ERROR: "status-error",
    Status.NOT_APPLICABLE: "status-na",
}


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_html(report: AuditReport) -> str:
    failing = [finding for finding in report.findings if finding.is_failing]
    title = f"aegis report - {report.root}"
    severity_bars = _severity_bars(report)
    rows = "\n".join(_finding_row(finding) for finding in report.findings)
    category_rows = "\n".join(_category_row(category) for category in report.categories)
    remediation = "\n".join(_remediation_card(finding) for finding in failing)
    baseline = _baseline_block(report)
    errors = _errors_block(report)
    score_width = max(0.0, min(100.0, report.score))
    grade_class = f"grade-{report.grade.lower()}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #0b1020;
  --panel: #111a2e;
  --panel-2: #0e1628;
  --line: #22304d;
  --text: #e6edf7;
  --muted: #8fa3c4;
  --cyan: #22d3ee;
  --green: #34d399;
  --yellow: #fbbf24;
  --red: #f87171;
  --magenta: #e879f9;
  --blue: #60a5fa;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; background: var(--bg); color: var(--text); }}
body {{
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55;
  font-size: 15px;
}}
code, pre, .mono {{
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
}}
a {{ color: var(--cyan); }}
.top {{
  border-bottom: 1px solid var(--line);
  background: linear-gradient(135deg, #0b1020 0%, #0d1730 55%, #0b1c31 100%);
}}
.wrap {{ max-width: 1180px; margin: 0 auto; padding: 28px 24px; }}
.brand {{ display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }}
.brand h1 {{ margin: 0; font-size: 30px; letter-spacing: 0.02em; color: var(--cyan); font-weight: 700; }}
.brand .tagline {{ color: var(--muted); font-size: 15px; }}
.meta {{ margin-top: 14px; color: var(--muted); font-size: 13px; display: flex; gap: 18px; flex-wrap: wrap; }}
.meta b {{ color: var(--text); font-weight: 600; }}
main {{ padding-bottom: 48px; }}
section {{ margin-top: 26px; }}
h2 {{ font-size: 18px; margin: 0 0 14px 0; letter-spacing: 0.01em; }}
h3 {{ font-size: 15px; margin: 0 0 6px 0; }}
.panel {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 20px; }}
.score-grid {{ display: grid; grid-template-columns: minmax(240px, 1.1fr) 2fr; gap: 18px; }}
.score-card {{ display: flex; flex-direction: column; justify-content: center; }}
.score-number {{ font-size: 58px; font-weight: 750; line-height: 1; color: var(--cyan); }}
.score-number small {{ font-size: 20px; color: var(--muted); font-weight: 500; }}
.grade {{ display: inline-flex; width: 54px; height: 54px; border-radius: 50%; align-items: center; justify-content: center;
  font-size: 26px; font-weight: 750; border: 3px solid currentColor; margin-left: 16px; vertical-align: 14px; }}
.grade-a {{ color: var(--green); }}
.grade-b {{ color: var(--cyan); }}
.grade-c {{ color: var(--yellow); }}
.grade-d {{ color: #fb923c; }}
.grade-f {{ color: var(--red); }}
.score-row {{ display: flex; align-items: center; }}
.meter {{ height: 8px; border-radius: 8px; background: #1b2942; overflow: hidden; margin-top: 18px; }}
.meter > span {{ display: block; height: 100%; background: linear-gradient(90deg, var(--red), var(--yellow), var(--green)); }}
.counts {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-top: 20px; }}
.count {{ background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; }}
.count .n {{ font-size: 22px; font-weight: 700; display: block; }}
.count .l {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }}
.c-pass .n {{ color: var(--green); }}
.c-fail .n {{ color: var(--red); }}
.c-error .n {{ color: var(--magenta); }}
.c-na .n {{ color: var(--muted); }}
.c-supp .n {{ color: var(--yellow); }}
.bars {{ display: grid; gap: 10px; }}
.bar-row {{ display: grid; grid-template-columns: 92px 1fr 130px; gap: 12px; align-items: center; font-size: 13px; }}
.bar-track {{ height: 12px; background: #1b2942; border-radius: 6px; overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 6px; }}
.bar-critical {{ background: var(--red); }}
.bar-high {{ background: #fb923c; }}
.bar-medium {{ background: var(--yellow); }}
.bar-low {{ background: var(--cyan); }}
.bar-info {{ background: var(--blue); }}
.bar-label {{ color: var(--muted); text-align: right; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.06em; }}
tbody tr:hover {{ background: #14203a; }}
.table-wrap {{ overflow-x: auto; }}
.sev {{ display: inline-block; min-width: 70px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
.sev-critical {{ color: var(--red); }}
.sev-high {{ color: #fb923c; }}
.sev-medium {{ color: var(--yellow); }}
.sev-low {{ color: var(--cyan); }}
.sev-info {{ color: var(--blue); }}
.status {{ display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 999px; border: 1px solid; }}
.status-pass {{ color: var(--green); border-color: #256b55; }}
.status-fail {{ color: var(--red); border-color: #7a2e2e; }}
.status-error {{ color: var(--magenta); border-color: #7a2f83; }}
.status-na {{ color: var(--muted); border-color: var(--line); }}
.rule {{ color: var(--cyan); white-space: nowrap; }}
.path {{ color: var(--muted); font-size: 12px; word-break: break-all; }}
.toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }}
.toolbar input[type="search"] {{
  background: var(--panel-2); color: var(--text); border: 1px solid var(--line);
  border-radius: 8px; padding: 8px 12px; min-width: 260px; font: inherit; font-size: 13px;
}}
button.filter {{
  background: var(--panel-2); color: var(--text); border: 1px solid var(--line);
  border-radius: 8px; padding: 7px 11px; font: inherit; font-size: 12px; cursor: pointer;
}}
button.filter:hover {{ border-color: var(--cyan); }}
button.filter.active {{ border-color: var(--cyan); color: var(--cyan); background: #102338; }}
.count-note {{ color: var(--muted); font-size: 12px; margin-left: auto; }}
details summary {{ cursor: pointer; color: var(--muted); }}
.remediation-grid {{ display: grid; gap: 14px; }}
.fix-card {{ border: 1px solid var(--line); border-radius: 10px; padding: 16px; background: var(--panel-2); }}
.fix-card .head {{ display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; }}
.fix-card .head .rule {{ font-weight: 700; }}
pre.code {{ background: #070c17; border: 1px solid var(--line); border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 12px; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--line); font-size: 11px; color: var(--muted); }}
.badge-safe {{ color: var(--green); border-color: #256b55; }}
.warning {{ border: 1px solid #6b531f; background: #211b0c; color: #f7d774; border-radius: 10px; padding: 14px 16px; }}
.error-list {{ color: var(--red); }}
footer {{ border-top: 1px solid var(--line); color: var(--muted); font-size: 12px; padding: 20px 0 40px; }}
@media (max-width: 760px) {{
  .score-grid {{ grid-template-columns: 1fr; }}
  .counts {{ grid-template-columns: repeat(2, 1fr); }}
  .bar-row {{ grid-template-columns: 74px 1fr; }}
  .bar-label {{ display: none; }}
}}
@media print {{
  body {{ background: #fff; color: #111; }}
  .toolbar, footer {{ display: none; }}
  .panel, .fix-card, .count {{ background: #fff; border-color: #ccc; }}
}}
</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <div class="brand">
      <h1>aegis</h1>
      <span class="tagline">Linux host hardening, measured.</span>
    </div>
    <div class="meta">
      <span>Root <b>{esc(report.root)}</b></span>
      <span>Generated <b>{esc(report.generated_at)}</b></span>
      <span>Version <b>{esc(report.tool_version)}</b></span>
      <span>Rules <b>{report.summary.total}</b></span>
      <span>Ruleset <b>{esc(report.ruleset_fingerprint)}</b></span>
    </div>
  </div>
</header>
<main class="wrap">
  <section class="score-grid">
    <div class="panel score-card">
      <div class="score-row">
        <div class="score-number">{report.score:.2f}<small> / 100</small></div>
        <div class="grade {grade_class}" title="Grade {esc(report.grade)}">{esc(report.grade)}</div>
      </div>
      <div class="meter" aria-label="Score"><span style="width: {score_width:.2f}%"></span></div>
      <div class="counts">
        <div class="count c-pass"><span class="n">{report.summary.passed}</span><span class="l">Pass</span></div>
        <div class="count c-fail"><span class="n">{report.summary.failed}</span><span class="l">Fail</span></div>
        <div class="count c-error"><span class="n">{report.summary.errors}</span><span class="l">Error</span></div>
        <div class="count c-na"><span class="n">{report.summary.not_applicable}</span><span class="l">N/A</span></div>
        <div class="count c-supp"><span class="n">{report.summary.suppressed}</span><span class="l">Suppressed</span></div>
      </div>
    </div>
    <div class="panel">
      <h2>Severity breakdown</h2>
      <div class="bars">
        {severity_bars}
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>Categories</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Category</th><th>Score</th><th>Weight</th><th>Pass</th><th>Fail</th><th>Error</th><th>N/A</th></tr></thead>
        <tbody>
          {category_rows}
        </tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <h2>Findings</h2>
    <div class="toolbar">
      <input id="search" type="search" placeholder="Search rule, title, category, path, message" aria-label="Search findings">
      <button class="filter active" data-filter="failing" type="button">Failing</button>
      <button class="filter" data-filter="all" type="button">All</button>
      <button class="filter" data-filter="critical" type="button">Critical</button>
      <button class="filter" data-filter="high" type="button">High</button>
      <button class="filter" data-filter="medium" type="button">Medium</button>
      <button class="filter" data-filter="low" type="button">Low</button>
      <button class="filter" data-filter="info" type="button">Info</button>
      <span class="count-note" id="visible-count"></span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Status</th><th>Severity</th><th>Rule</th><th>Title</th><th>Category</th><th>CIS</th><th>Path</th><th>Detail</th></tr></thead>
        <tbody id="findings">
          {rows}
        </tbody>
      </table>
    </div>
  </section>

  <section class="panel">
    <h2>Remediation</h2>
    <div class="remediation-grid">
      {remediation}
    </div>
  </section>

  {baseline}
  {errors}

  <footer>
    Generated by aegis {esc(report.tool_version)} under the MIT License. Findings are produced by read-only checks
    against the audit root. Review every proposed command before running it.
  </footer>
</main>
<script>
(function () {{
  var rows = Array.prototype.slice.call(document.querySelectorAll('#findings tr'));
  var buttons = Array.prototype.slice.call(document.querySelectorAll('button.filter'));
  var search = document.getElementById('search');
  var count = document.getElementById('visible-count');
  var active = 'failing';
  function matches(row) {{
    if (active === 'all') return true;
    if (active === 'failing') return row.getAttribute('data-status') === 'fail' || row.getAttribute('data-status') === 'error';
    return row.getAttribute('data-severity') === active;
  }}
  function apply() {{
    var term = (search.value || '').toLowerCase().trim();
    var visible = 0;
    rows.forEach(function (row) {{
      var text = row.textContent.toLowerCase();
      var show = matches(row) && (!term || text.indexOf(term) !== -1);
      row.style.display = show ? '' : 'none';
      if (show) visible += 1;
    }});
    count.textContent = visible + ' of ' + rows.length + ' shown';
  }}
  buttons.forEach(function (button) {{
    button.addEventListener('click', function () {{
      active = button.getAttribute('data-filter');
      buttons.forEach(function (other) {{ other.classList.toggle('active', other === button); }});
      apply();
    }});
  }});
  search.addEventListener('input', apply);
  apply();
}})();
</script>
</body>
</html>
"""


def _finding_row(finding: Finding) -> str:
    status_value = finding.status.value
    if finding.suppressed:
        status_label = "suppressed"
        status_class = "status-na"
    else:
        status_label = status_value.replace("_", " ")
        status_class = STATUS_CLASS[finding.status]
    detail = f"<div>{esc(finding.message)}</div>"
    remediation = finding.remediation
    if remediation.text and (finding.is_failing or finding.suppressed):
        detail += (
            "<details><summary>Remediation</summary>"
            f"<div>{esc(remediation.text)}</div>"
            + (f'<pre class="code">{esc(remediation.command)}</pre>' if remediation.command else "")
            + "</details>"
        )
    if finding.suppressed:
        detail += (
            f'<div class="path">suppressed: {esc(finding.suppression_reason or "")} '
            f"(expires {esc(finding.suppression_expires or '')})</div>"
        )
    return (
        f'<tr data-status="{esc(status_value)}" data-severity="{esc(finding.severity.value)}">'
        f'<td><span class="status {status_class}">{esc(status_label)}</span></td>'
        f'<td><span class="sev {SEVERITY_CLASS[finding.severity]}">{esc(finding.severity.value)}</span></td>'
        f'<td><span class="rule">{esc(finding.rule_id)}</span></td>'
        f"<td>{esc(finding.title)}</td>"
        f"<td>{esc(finding.category)}</td>"
        f"<td>{esc(finding.cis)}</td>"
        f'<td class="path">{esc(finding.path or "-")}</td>'
        f"<td>{detail}</td>"
        "</tr>"
    )


def _category_row(category) -> str:
    return (
        f"<tr><td>{esc(category.category)}</td><td>{category.score:.1f}</td>"
        f"<td>{category.passed_weight}/{category.total_weight}</td>"
        f"<td>{category.passed}</td><td>{category.failed}</td>"
        f"<td>{category.errors}</td><td>{category.not_applicable}</td></tr>"
    )


def _severity_bars(report: AuditReport) -> str:
    parts: list[str] = []
    for severity in SEVERITY_ORDER:
        stats = report.summary.by_severity.get(severity.value)
        total = stats.total if stats else 0
        failed = (stats.failed + stats.errors) if stats else 0
        percent = (100.0 * failed / total) if total else 0.0
        parts.append(
            '<div class="bar-row">'
            f'<span class="sev {SEVERITY_CLASS[severity]}">{severity.value}</span>'
            f'<span class="bar-track"><span class="bar-fill bar-{severity.value}" '
            f'style="width: {percent:.2f}%"></span></span>'
            f'<span class="bar-label">{failed} failed / {total} total</span>'
            "</div>"
        )
    return "\n        ".join(parts)


def _remediation_card(finding: Finding) -> str:
    remediation = finding.remediation
    safe_badge = (
        '<span class="badge badge-safe">safe fix available</span>'
        if remediation.safe and remediation.fix
        else '<span class="badge">manual action</span>'
    )
    command = f'<pre class="code">{esc(remediation.command)}</pre>' if remediation.command else ""
    path = f'<div class="path">{esc(finding.path)}</div>' if finding.path else ""
    return (
        '<div class="fix-card">'
        '<div class="head">'
        f'<span class="sev {SEVERITY_CLASS[finding.severity]}">{esc(finding.severity.value)}</span>'
        f'<span class="rule">{esc(finding.rule_id)}</span>'
        f"<strong>{esc(finding.title)}</strong>{safe_badge}"
        "</div>"
        f"{path}"
        f"<p>{esc(remediation.text or 'Review the control and apply an appropriate fix.')}</p>"
        "<details><summary>Finding detail</summary>"
        f"<div>{esc(finding.message)}</div>"
        f"{command}"
        "</details>"
        "</div>"
    )


def _baseline_block(report: AuditReport) -> str:
    stale = report.baseline.expired
    unused = report.baseline.unused
    if not stale and not unused:
        return ""
    items: list[str] = []
    for item in stale:
        items.append(
            f"<li><code>{esc(item.rule_id)}</code> expired {esc(item.expires)}: "
            f"{esc(item.detail or item.reason)}</li>"
        )
    for item in unused:
        items.append(f"<li><code>{esc(item.rule_id)}</code> unused: {esc(item.reason)}</li>")
    return (
        '<section class="panel warning"><h2>Baseline exceptions</h2>'
        "<p>Expired exceptions do not suppress findings.</p><ul>"
        + "".join(items)
        + "</ul></section>"
    )


def _errors_block(report: AuditReport) -> str:
    if not report.errors:
        return ""
    items = "".join(f"<li>{esc(message)}</li>" for message in report.errors)
    return (
        f'<section class="panel"><h2>Audit errors</h2><ul class="error-list">{items}</ul></section>'
    )
