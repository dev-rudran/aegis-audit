"""Command-line interface for aegis.

Exit codes are part of the public contract:

* ``0``  the audit gate passed (or the requested command succeeded)
* ``1``  the audit gate failed (or a report diff detected a regression)
* ``2``  usage error, invalid rule pack, unreadable input, or runtime failure
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import json
import os
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

import yaml

from aegis import SCHEMA_VERSION, TOOL_NAME, __version__
from aegis.baseline import Baseline, BaselineError
from aegis.checks import CHECK_TYPES
from aegis.diff import DiffError, diff_reports, load_report
from aegis.engine import (
    AuditEngine,
    RuleLoadError,
    collect_rules,
    default_rules_dir,
    load_rules,
    select_rules,
)
from aegis.models import AuditReport, Rule, Severity, utc_now_iso
from aegis.remediation import FixPlanner, RemediationResult
from aegis.report import FORMATS, render_report
from aegis.scoring import gate_failures
from aegis.util.fs import RootFS

EXIT_PASS = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2

DEFAULT_ROOT = "/"
DEFAULT_FAIL_ON = "critical"

_FORMAT_EXTENSIONS: dict[str, str] = {
    ".json": "json",
    ".md": "md",
    ".markdown": "md",
    ".html": "html",
    ".htm": "html",
    ".sarif": "sarif",
}


class CliError(RuntimeError):
    """A user-facing failure that maps to exit code 2."""


def _score_value(text: str) -> float:
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from exc
    if not 0.0 <= value <= 100.0:
        raise argparse.ArgumentTypeError("score must be between 0 and 100")
    return value


def _audit_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        metavar="PATH",
        default=DEFAULT_ROOT,
        help="audit this filesystem root instead of the live host (default: /)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default=None,
        help="report format; inferred from --output extension when omitted (default: console)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="write the report to PATH instead of stdout ('-' means stdout)",
    )
    parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="YAML file of time-bound exceptions that suppress known failures",
    )
    parser.add_argument(
        "--category",
        action="append",
        metavar="NAME",
        help="only evaluate rules in this category (repeatable)",
    )
    parser.add_argument(
        "--tag",
        action="append",
        metavar="TAG",
        help="only evaluate rules carrying this tag (repeatable)",
    )
    parser.add_argument(
        "--exclude-tag",
        action="append",
        metavar="TAG",
        help="skip rules carrying this tag (repeatable)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "never"),
        default=DEFAULT_FAIL_ON,
        help="fail the gate on findings at or above this severity (default: critical)",
    )
    parser.add_argument(
        "--min-score",
        type=_score_value,
        metavar="N",
        help="fail the gate when the weighted score is below N (0-100)",
    )
    parser.add_argument(
        "--rules-dir",
        metavar="PATH",
        help="load rules from PATH instead of the bundled pack",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="print a remediation plan; nothing is written without --apply",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply safe structured fixes (implies --remediate); writes .aegis.bak backups",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colour in console output",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print one summary line and any gate reasons",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "CIS-aligned Linux host hardening auditor with weighted scoring, "
            "time-bound exceptions, safe remediation, and CI-ready reports."
        ),
        epilog=(
            "Examples:\n"
            "  aegis\n"
            "  aegis --root /mnt/image --format json --output report.json\n"
            "  aegis --fail-on high --min-score 80 --baseline baseline.yml\n"
            "  aegis --remediate            # dry run\n"
            "  aegis --apply                # write safe fixes with backups\n"
            "  aegis diff old.json new.json\n"
            "  aegis explain AEGIS-0012\n"
            "  aegis rules validate\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {__version__}",
        help="print the tool version and exit",
    )
    _audit_options(parser)

    subcommands = parser.add_subparsers(dest="command", metavar="COMMAND")

    audit = subcommands.add_parser(
        "audit",
        help="evaluate the rule pack against a host (default command)",
        description="Evaluate every selected rule and render a report.",
    )
    _audit_options(audit)

    rules = subcommands.add_parser(
        "rules",
        help="inspect and validate rule packs",
        description="Inspect, print, and validate rule definitions.",
    )
    rule_commands = rules.add_subparsers(dest="rules_command", metavar="ACTION")

    rules_list = rule_commands.add_parser(
        "list",
        help="list loaded rules",
        description="List rule identifiers, severities, categories, and titles.",
    )
    _rule_source_options(rules_list)
    rules_list.add_argument("--category", action="append", metavar="NAME")
    rules_list.add_argument("--tag", action="append", metavar="TAG")
    rules_list.add_argument("--json", action="store_true", help="emit a JSON array")

    rules_show = rule_commands.add_parser(
        "show",
        help="print one rule as YAML",
        description="Print the canonical YAML document for a rule identifier.",
    )
    rules_show.add_argument("rule_id", metavar="ID")
    _rule_source_options(rules_show)

    rules_validate = rule_commands.add_parser(
        "validate",
        help="validate a rule pack",
        description="Parse every rule and report schema or parameter errors.",
    )
    _rule_source_options(rules_validate)
    rules_validate.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    explain = subcommands.add_parser(
        "explain",
        help="explain what a rule checks and how to fix it",
        description="Show the intent, check parameters, remediation, and references for a rule.",
    )
    explain.add_argument("rule_id", metavar="ID")
    _rule_source_options(explain)

    diff = subcommands.add_parser(
        "diff",
        help="compare two JSON audit reports",
        description=(
            "Compare an older JSON report with a newer one.  Newly failing controls, "
            "newly fixed controls, persistent failures, and the score delta are reported."
        ),
    )
    diff.add_argument("old_report", metavar="OLD")
    diff.add_argument("new_report", metavar="NEW")
    diff.add_argument("--json", action="store_true", help="emit a JSON diff document")
    diff.add_argument("-o", "--output", metavar="PATH", help="write the diff to PATH")
    diff.add_argument(
        "--allow-regression",
        action="store_true",
        help="exit 0 even when the new report regressed",
    )

    version = subcommands.add_parser(
        "version",
        help="print version information",
        description="Print the aegis version and the report schema version.",
    )
    version.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    return parser


def _rule_source_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rules-dir",
        metavar="PATH",
        help="use the rule pack in PATH instead of the bundled pack",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command is None or args.command == "audit":
            return _command_audit(args)
        if args.command == "rules":
            return _command_rules(args)
        if args.command == "explain":
            return _command_explain(args)
        if args.command == "diff":
            return _command_diff(args)
        if args.command == "version":
            return _command_version(args)
        parser.error(f"unknown command: {args.command}")
    except CliError as exc:
        _error(str(exc))
    except RuleLoadError as exc:
        _error(str(exc))
        for problem in exc.errors:
            print(f"  {problem}", file=sys.stderr)
    except BaselineError as exc:
        _error(str(exc))
    except DiffError as exc:
        _error(str(exc))
    except (FileNotFoundError, NotADirectoryError) as exc:
        _error(str(exc))
    except BrokenPipeError:
        _silence_output()
        return EXIT_PASS
    except KeyboardInterrupt:
        print("aegis: interrupted", file=sys.stderr)
        return 130
    except OSError as exc:
        _error(f"I/O error: {exc}")
    return EXIT_ERROR


def _error(message: str) -> NoReturn:
    print(f"aegis: error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_ERROR)


def _silence_output() -> None:
    """Point stdout and stderr at /dev/null so interpreter shutdown is quiet."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
    except OSError:  # pragma: no cover - extremely constrained environment
        return
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(OSError, ValueError):
            os.dup2(devnull, stream.fileno())


def _severity_for_fail_on(value: str) -> Severity | None:
    if value == "never":
        return None
    return Severity.parse(value)


def _infer_format(output: str | None) -> str | None:
    if not output or output == "-":
        return None
    name = Path(output).name.lower()
    if name.endswith(".sarif.json"):
        return "sarif"
    return _FORMAT_EXTENSIONS.get(Path(name).suffix)


def _selected_rules(args: argparse.Namespace) -> list[Rule]:
    loaded = load_rules(args.rules_dir)
    selected = select_rules(
        loaded,
        categories=args.category,
        tags=args.tag,
        exclude_tags=args.exclude_tag,
    )
    if not selected:
        raise CliError("no rules matched the requested --category/--tag filters")
    return selected


def _load_baseline(path: str | None) -> Baseline | None:
    if not path:
        return None
    return Baseline.load(path)


def _run_audit(
    root: str,
    rules: list[Rule],
    baseline: Baseline | None,
) -> tuple[AuditReport, RootFS]:
    try:
        fs = RootFS(root)
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot audit {root!r}: {exc}") from exc
    engine = AuditEngine(rules, fs.root, baseline=baseline)
    report = engine.run()
    return report, engine.fs


def _command_audit(args: argparse.Namespace) -> int:
    if args.apply:
        args.remediate = True
    fail_on = _severity_for_fail_on(args.fail_on)
    fmt = args.format or _infer_format(args.output) or "console"
    if fmt not in FORMATS:
        raise CliError(f"unknown report format {fmt!r}")

    rules = _selected_rules(args)
    baseline = _load_baseline(args.baseline)
    report, fs = _run_audit(args.root, rules, baseline)
    reasons = gate_failures(report, fail_on=fail_on, min_score=args.min_score)

    remediation: RemediationResult | None = None
    if args.remediate:
        planner = FixPlanner(fs, apply=args.apply)
        remediation = planner.plan(report, rules)
        _print_remediation(remediation)
        if args.apply and remediation.applied:
            previous_score = report.score
            previous_grade = report.grade
            report, _ = _run_audit(args.root, rules, baseline)
            reasons = gate_failures(report, fail_on=fail_on, min_score=args.min_score)
            print(
                f"Re-audited after {len(remediation.applied)} applied fix(es): "
                f"score {previous_score:.2f} ({previous_grade}) -> "
                f"{report.score:.2f} ({report.grade})",
                file=sys.stderr,
            )
        _print_manual_reminder(remediation)

    color: bool | None = None
    if args.no_color or os.environ.get("NO_COLOR") or (args.output and args.output != "-"):
        color = False
    text = render_report(
        report,
        fmt,
        color=color,
        quiet=args.quiet,
        gate_reasons=reasons,
    )
    _write_output(text, args.output)
    return EXIT_GATE_FAILED if reasons else EXIT_PASS


def _write_output(text: str, output: str | None) -> None:
    if not output or output == "-":
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
        return
    path = Path(output).expanduser()
    try:
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot write report to {path}: {exc}") from exc
    print(f"Report written to {path}", file=sys.stderr)


def _print_remediation(result: RemediationResult) -> None:
    mode = "dry run" if result.dry_run else "apply"
    changed = len(result.would_apply) + len(result.applied)
    unchanged = sum(1 for item in result.outcomes if item.status == "unchanged")
    failures = len(result.errors)
    print(
        f"\nRemediation plan ({mode}): {changed} change(s), {unchanged} already compliant, "
        f"{failures} failed, {len(result.manual_rules)} manual control(s)",
        file=sys.stderr,
    )
    for outcome in result.outcomes:
        if outcome.status not in ("would_apply", "applied", "error"):
            continue
        print(
            f"  {outcome.status.upper():<12} {outcome.rule_id}  "
            f"[{outcome.severity.value}] {outcome.title}",
            file=sys.stderr,
        )
        if outcome.path:
            print(f"    target: {outcome.path}", file=sys.stderr)
        if outcome.message:
            print(f"    {outcome.message}", file=sys.stderr)
        for line in outcome.diff[:40]:
            print(f"    {line}", file=sys.stderr)
        if outcome.backup:
            print(f"    backup: {outcome.backup}", file=sys.stderr)
    if result.errors:
        print(f"  {len(result.errors)} fix(es) failed; no partial write was kept.", file=sys.stderr)


def _print_manual_reminder(result: RemediationResult) -> None:
    if not result.manual_rules:
        return
    preview = ", ".join(result.manual_rules[:8])
    suffix = "" if len(result.manual_rules) <= 8 else f", and {len(result.manual_rules) - 8} more"
    print(
        f"Manual remediation required for {len(result.manual_rules)} control(s): "
        f"{preview}{suffix}. Run 'aegis explain ID' for guidance.",
        file=sys.stderr,
    )


def _load_rules_for(args: argparse.Namespace) -> list[Rule]:
    return load_rules(args.rules_dir)


def _find_rule(rules: list[Rule], rule_id: str) -> Rule:
    wanted = rule_id.strip().upper()
    for rule in rules:
        if rule.id == wanted:
            return rule
    suggestions = difflib.get_close_matches(wanted, [rule.id for rule in rules], n=3)
    hint = f"; did you mean {', '.join(suggestions)}?" if suggestions else ""
    raise CliError(f"unknown rule id {rule_id!r}{hint}")


def _command_rules(args: argparse.Namespace) -> int:
    action = getattr(args, "rules_command", None)
    if action is None:
        raise CliError("missing rules action (expected: list, show, validate)")
    if action == "list":
        rules = _load_rules_for(args)
        selected = select_rules(rules, categories=args.category, tags=args.tag)
        if not selected:
            raise CliError("no rules matched the requested filters")
        if args.json:
            payload = [rule.to_dict() for rule in selected]
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
            return EXIT_PASS
        _print_rule_table(selected)
        return EXIT_PASS
    if action == "show":
        rules = _load_rules_for(args)
        rule = _find_rule(rules, args.rule_id)
        document = yaml.safe_dump(rule.to_dict(), sort_keys=False, allow_unicode=True, width=100)
        sys.stdout.write(document)
        return EXIT_PASS
    if action == "validate":
        return _command_validate_rules(args)
    raise CliError(f"unknown rules action: {action}")


def _print_rule_table(rules: list[Rule]) -> None:
    id_width = max(len("ID"), *(len(rule.id) for rule in rules))
    severity_width = max(len("SEVERITY"), *(len(rule.severity.value) for rule in rules))
    category_width = max(len("CATEGORY"), *(len(rule.category) for rule in rules))
    print(
        f"{'ID':<{id_width}}  {'SEVERITY':<{severity_width}}  {'CATEGORY':<{category_width}}  TITLE"
    )
    print(f"{'-' * id_width}  {'-' * severity_width}  {'-' * category_width}  {'-' * 40}")
    for rule in rules:
        print(
            f"{rule.id:<{id_width}}  {rule.severity.value:<{severity_width}}  "
            f"{rule.category:<{category_width}}  {rule.title}"
        )
    print(f"\n{len(rules)} rule(s).")


def _command_validate_rules(args: argparse.Namespace) -> int:
    location = Path(args.rules_dir) if args.rules_dir else default_rules_dir()
    rules, errors = collect_rules(location)
    categories = Counter(rule.category for rule in rules)
    files = (
        len(list(location.glob("*.yml"))) + len(list(location.glob("*.yaml")))
        if location.is_dir()
        else 0
    )
    payload = {
        "valid": not errors,
        "rules": len(rules),
        "files": files,
        "categories": dict(sorted(categories.items())),
        "check_types": sorted({rule.check_type for rule in rules}),
        "errors": errors,
    }
    if getattr(args, "json", False):
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    elif errors:
        print(f"Rule pack invalid: {len(errors)} problem(s)", file=sys.stderr)
        for problem in errors:
            print(f"  {problem}", file=sys.stderr)
    else:
        print(f"Rule pack valid: {len(rules)} rules from {files} file(s) in {location}")
        print(f"Categories: {', '.join(sorted(categories))}")
        print(
            f"Check types exercised: {len(payload['check_types'])} of {len(CHECK_TYPES)} registered"
        )
        for name, count in sorted(categories.items()):
            print(f"  {name:<14} {count:>3}")
    return EXIT_ERROR if errors else EXIT_PASS


def _command_explain(args: argparse.Namespace) -> int:
    rules = _load_rules_for(args)
    rule = _find_rule(rules, args.rule_id)
    write = sys.stdout.write
    write(f"{rule.id}  {rule.title}\n")
    write(f"Severity: {rule.severity.value} (weight {rule.severity.weight})   ")
    write(f"Category: {rule.category}   CIS: {rule.cis}\n")
    write("\n")
    write("Description\n")
    for line in _wrap_block(rule.description):
        write(f"  {line}\n")
    write("\nCheck\n")
    write(f"  type: {rule.check_type}\n")
    if rule.params:
        write("  params:\n")
        for key in sorted(rule.params):
            write(f"    {key}: {_format_value(rule.params[key])}\n")
    else:
        write("  params: {}\n")
    remediation = rule.remediation
    write("\nRemediation\n")
    for line in _wrap_block(remediation.text or "No guidance recorded."):
        write(f"  {line}\n")
    write(f"  safe automatic fix: {'yes' if remediation.safe else 'no'}\n")
    if remediation.fix:
        write(f"  fix: {json.dumps(remediation.fix, sort_keys=True)}\n")
    if remediation.command:
        write(f"  command: {remediation.command}\n")
    if rule.tags:
        write(f"\nTags: {', '.join(rule.tags)}\n")
    if rule.references:
        write("References:\n")
        for reference in rule.references:
            write(f"  {reference}\n")
    return EXIT_PASS


def _wrap_block(text: str, width: int = 96) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        if current and length + len(word) + 1 > width:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += len(word) + (1 if len(current) > 1 else 0)
    if current:
        lines.append(" ".join(current))
    return lines or [""]


def _format_value(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _command_diff(args: argparse.Namespace) -> int:
    old = load_report(args.old_report)
    new = load_report(args.new_report)
    result = diff_reports(old, new)
    text = result.to_json() if args.json else result.to_text()
    _write_output(text, args.output)
    if result.regressed and not args.allow_regression:
        return EXIT_GATE_FAILED
    return EXIT_PASS


def _command_version(args: argparse.Namespace) -> int:
    if args.json:
        payload = {
            "tool": TOOL_NAME,
            "version": __version__,
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now_iso(),
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        print(f"{TOOL_NAME} {__version__} (report schema {SCHEMA_VERSION})")
    return EXIT_PASS


if __name__ == "__main__":  # pragma: no cover - exercised through __main__
    sys.exit(main())
