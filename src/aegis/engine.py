"""Rule loading, check dispatch, aggregation, and baseline application."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import yaml

from aegis import SCHEMA_VERSION, __version__
from aegis.baseline import Baseline
from aegis.checks import CHECK_TYPES, run_check, validate_check
from aegis.checks.base import CheckContext, ParamError
from aegis.models import (
    AuditReport,
    CheckResult,
    Finding,
    Rule,
    RuleValidationError,
    Status,
    utc_now_iso,
)
from aegis.remediation import validate_fix
from aegis.scoring import apply_scoring
from aegis.util.fs import RootFS


class RuleLoadError(ValueError):
    """One or more bundled or custom rules are invalid."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        self.errors = errors or []
        super().__init__(message)


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


def _documents_from_file(path: Path) -> list[tuple[Any, str]]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{path.name}: invalid YAML: {exc}") from exc
    except OSError as exc:
        raise RuleLoadError(f"{path.name}: cannot read: {exc}") from exc
    if document is None:
        return []
    if isinstance(document, list):
        return [(item, path.name) for item in document]
    if isinstance(document, dict) and isinstance(document.get("rules"), list):
        return [(item, path.name) for item in document["rules"]]
    raise RuleLoadError(f"{path.name}: expected a list of rules or a mapping with a 'rules' list")


def load_rules(directory: str | Path | None = None) -> list[Rule]:
    """Load and fully validate a rule pack.

    Raises :class:`RuleLoadError` with every discovered problem, not just the
    first one.
    """
    rules, errors = collect_rules(directory)
    if errors:
        raise RuleLoadError(f"invalid rule pack ({len(errors)} problem(s))", errors)
    if not rules:
        raise RuleLoadError("rule pack is empty")
    return rules


def collect_rules(
    directory: str | Path | None = None,
) -> tuple[list[Rule], list[str]]:
    location = Path(directory) if directory is not None else default_rules_dir()
    if not location.is_dir():
        return [], [f"rule directory does not exist: {location}"]
    files = sorted(location.glob("*.yml")) + sorted(location.glob("*.yaml"))
    if not files:
        return [], [f"no .yml or .yaml rule files in {location}"]
    rules: list[Rule] = []
    errors: list[str] = []
    seen: dict[str, str] = {}
    for path in files:
        try:
            documents = _documents_from_file(path)
        except RuleLoadError as exc:
            errors.append(str(exc))
            continue
        for raw, source in documents:
            rule_id = raw.get("id") if isinstance(raw, dict) else "<unknown>"
            label = f"{source}:{rule_id}"
            try:
                rule = Rule.from_dict(raw, allowed_check_types=set(CHECK_TYPES))
            except RuleValidationError as exc:
                errors.append(f"{source}: {exc.message}")
                continue
            param_errors = validate_check(rule.check_type, rule.params)
            if param_errors:
                for problem in param_errors:
                    errors.append(f"{label}: check params: {problem}")
                continue
            if rule.remediation.fix is not None:
                fix_errors = validate_fix(rule.remediation.fix)
                if fix_errors:
                    for problem in fix_errors:
                        errors.append(f"{label}: remediation fix: {problem}")
                    continue
                if not rule.remediation.safe:
                    errors.append(
                        f"{label}: structured remediation requires remediation.safe: true"
                    )
                    continue
            if rule.id in seen:
                errors.append(f"{source}: duplicate rule id {rule.id} (also in {seen[rule.id]})")
                continue
            seen[rule.id] = source
            rules.append(rule)
    rules.sort(key=lambda item: item.id)
    return rules, errors


def rule_fingerprint(rules: list[Rule]) -> str:
    payload = json.dumps(
        [rule.to_dict() for rule in rules], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def select_rules(
    rules: list[Rule],
    *,
    categories: list[str] | None = None,
    tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> list[Rule]:
    selected = rules
    if categories:
        wanted = {item.casefold() for item in categories}
        selected = [rule for rule in selected if rule.category.casefold() in wanted]
    if tags:
        wanted_tags = {item.casefold() for item in tags}
        selected = [
            rule
            for rule in selected
            if wanted_tags.intersection(tag.casefold() for tag in rule.tags)
        ]
    if exclude_tags:
        excluded = {item.casefold() for item in exclude_tags}
        selected = [
            rule
            for rule in selected
            if not excluded.intersection(tag.casefold() for tag in rule.tags)
        ]
    return selected


class AuditEngine:
    """Run a rule pack against a filesystem root."""

    def __init__(
        self,
        rules: list[Rule],
        root: str | Path,
        *,
        baseline: Baseline | None = None,
    ) -> None:
        self.rules = rules
        self.fs = RootFS(root)
        self.baseline = baseline
        self.context = CheckContext(fs=self.fs)

    def run(self) -> AuditReport:
        started = time.monotonic()
        report = AuditReport(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            generated_at=utc_now_iso(),
            root=self.fs.root_str,
            ruleset_fingerprint=rule_fingerprint(self.rules),
        )
        findings: list[Finding] = []
        for rule in self.rules:
            outcome = self._evaluate(rule)
            if outcome.status is Status.ERROR:
                report.errors.append(f"{rule.id}: {outcome.message}")
            findings.append(self._to_finding(rule, outcome))
        findings.sort(
            key=lambda item: (
                -item.severity.rank,
                item.category,
                item.rule_id,
            )
        )
        report.findings = findings
        if self.baseline is not None:
            report.baseline = self.baseline.apply(findings)
        apply_scoring(report)
        report.duration_ms = int((time.monotonic() - started) * 1000)
        return report

    def _evaluate(self, rule: Rule) -> CheckResult:
        try:
            return run_check(rule, self.context)
        except ParamError as exc:
            return CheckResult.error(f"invalid check parameters: {exc}")
        except FileNotFoundError as exc:
            return CheckResult.error(f"required file disappeared during audit: {exc}")
        except PermissionError as exc:
            return CheckResult.error(f"permission denied while evaluating rule: {exc}")
        except (OSError, ValueError) as exc:
            return CheckResult.error(f"check failed: {exc}")
        except Exception as exc:
            return CheckResult.error(f"unexpected check failure: {type(exc).__name__}: {exc}")

    def _to_finding(self, rule: Rule, outcome: CheckResult) -> Finding:
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            category=rule.category,
            cis=rule.cis,
            status=outcome.status,
            message=outcome.message,
            path=outcome.path,
            remediation=rule.remediation,
            tags=rule.tags,
            evidence=dict(outcome.evidence),
        )


def audit(
    root: str | Path,
    *,
    rules: list[Rule] | None = None,
    baseline: Baseline | None = None,
    categories: list[str] | None = None,
    tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> AuditReport:
    """Convenience entry point used by the CLI and tests."""
    loaded = rules if rules is not None else load_rules()
    selected = select_rules(loaded, categories=categories, tags=tags, exclude_tags=exclude_tags)
    if not selected:
        raise RuleLoadError("no rules matched the requested filters")
    return AuditEngine(selected, root, baseline=baseline).run()
