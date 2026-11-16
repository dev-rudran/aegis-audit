"""Typed data model shared by the engine, checks, and reporters.

The JSON representation of :class:`AuditReport` is a public, versioned
interface.  Keep field names stable and additive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any

ID_PATTERN = re.compile(r"^AEGIS-\d{4}$")
CATEGORY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &/_-]{0,63}$")


class Severity(str, Enum):
    """Finding severity.  The string value is used in YAML and JSON."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self]

    @property
    def rank(self) -> int:
        """Higher is more severe."""
        return SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: object) -> Severity:
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(f"severity must be a string, got {type(value).__name__}")
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"invalid severity {value!r}; expected one of: {allowed}") from exc


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Most severe first.  Used by reporters and gate evaluation.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


class Status(str, Enum):
    """Outcome of evaluating one rule."""

    # The string is a status label, not a credential.
    PASS = "pass"  # nosec B105
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"

    @property
    def is_failing(self) -> bool:
        # An unverifiable rule is treated as a failed control.  Silent errors
        # would otherwise inflate the compliance score.
        return self in (Status.FAIL, Status.ERROR)


class FixType(str, Enum):
    """Structured, non-shell remediation actions understood by the fix engine."""

    SSHD_SET = "sshd_set"
    SYSCTL_SET = "sysctl_set"
    FILE_MODE = "file_mode"
    FILE_OWNER = "file_owner"
    LOGIN_DEFS_SET = "login_defs_set"
    PWQUALITY_SET = "pwquality_set"
    CONFIG_SET = "config_set"
    CREATE_FILE = "create_file"


FIX_TYPES: frozenset[str] = frozenset(item.value for item in FixType)


class RuleValidationError(ValueError):
    """Raised when a rule document is malformed."""

    def __init__(self, rule_id: str, message: str) -> None:
        self.rule_id = rule_id
        self.message = message
        super().__init__(f"{rule_id}: {message}")


@dataclass(frozen=True)
class Remediation:
    """Human guidance plus an optional structured, safe fix."""

    text: str
    safe: bool = False
    command: str | None = None
    fix: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"text": self.text, "safe": self.safe}
        if self.command:
            payload["command"] = self.command
        if self.fix:
            payload["fix"] = dict(self.fix)
        return payload

    @classmethod
    def from_dict(
        cls, data: object, rule_id: str = "<unknown>", *, require_text: bool = True
    ) -> Remediation:
        if data is None:
            return cls(text="")
        if isinstance(data, str):
            return cls(text=data)
        if not isinstance(data, dict):
            raise RuleValidationError(rule_id, "remediation must be a mapping or string")
        text = data.get("text", "")
        if not isinstance(text, str) or (require_text and not text.strip()):
            raise RuleValidationError(rule_id, "remediation.text must be a non-empty string")
        safe = data.get("safe", False)
        if not isinstance(safe, bool):
            raise RuleValidationError(rule_id, "remediation.safe must be a boolean")
        command = data.get("command")
        if command is not None and (not isinstance(command, str) or not command.strip()):
            raise RuleValidationError(rule_id, "remediation.command must be a non-empty string")
        fix = data.get("fix")
        if fix is not None:
            if not isinstance(fix, dict):
                raise RuleValidationError(rule_id, "remediation.fix must be a mapping")
            fix_type = fix.get("type")
            if fix_type not in FIX_TYPES:
                allowed = ", ".join(sorted(FIX_TYPES))
                raise RuleValidationError(
                    rule_id,
                    f"remediation.fix.type must be one of: {allowed} (got {fix_type!r})",
                )
            fix = {**fix, "type": str(fix_type)}
        return cls(text=text.strip(), safe=safe, command=command, fix=fix)


@dataclass(frozen=True)
class Rule:
    """A single auditable control loaded from the bundled YAML pack."""

    id: str
    title: str
    description: str
    severity: Severity
    category: str
    cis: str
    check: dict[str, Any]
    remediation: Remediation
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def check_type(self) -> str:
        value = self.check.get("type")
        return str(value) if value is not None else ""

    @property
    def params(self) -> dict[str, Any]:
        raw = self.check.get("params", {})
        return dict(raw) if isinstance(raw, dict) else {}

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "cis": self.cis,
            "check": dict(self.check),
            "remediation": self.remediation.to_dict(),
            "tags": list(self.tags),
        }
        if self.references:
            payload["references"] = list(self.references)
        return payload

    @classmethod
    def from_dict(cls, data: object, allowed_check_types: set[str] | None = None) -> Rule:
        if not isinstance(data, dict):
            raise RuleValidationError("<document>", "rule must be a mapping")

        raw_id = data.get("id")
        rule_id = raw_id if isinstance(raw_id, str) and raw_id else "<missing-id>"
        if not isinstance(raw_id, str) or not ID_PATTERN.match(raw_id):
            raise RuleValidationError(rule_id, "id must match AEGIS-#### (four digits)")

        title = _require_text(data, "title", rule_id, max_len=160)
        description = _require_text(data, "description", rule_id, max_len=2000)

        try:
            severity = Severity.parse(data.get("severity"))
        except ValueError as exc:
            raise RuleValidationError(rule_id, str(exc)) from exc

        category = _require_text(data, "category", rule_id, max_len=64)
        if not CATEGORY_PATTERN.match(category):
            raise RuleValidationError(rule_id, f"category {category!r} contains invalid characters")
        cis = _require_text(data, "cis", rule_id, max_len=120)

        check = data.get("check")
        if not isinstance(check, dict):
            raise RuleValidationError(rule_id, "check must be a mapping with type and params")
        check_type = check.get("type")
        if not isinstance(check_type, str) or not check_type.strip():
            raise RuleValidationError(rule_id, "check.type must be a non-empty string")
        if allowed_check_types is not None and check_type not in allowed_check_types:
            allowed = ", ".join(sorted(allowed_check_types))
            raise RuleValidationError(
                rule_id, f"unknown check type {check_type!r}; expected one of: {allowed}"
            )
        params = check.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise RuleValidationError(rule_id, "check.params must be a mapping")
        check = {"type": check_type, "params": dict(params)}

        remediation = Remediation.from_dict(data.get("remediation"), rule_id)

        tags = data.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) and t.strip() for t in tags):
            raise RuleValidationError(rule_id, "tags must be a list of non-empty strings")
        references = data.get("references", [])
        if not isinstance(references, list) or not all(isinstance(r, str) for r in references):
            raise RuleValidationError(rule_id, "references must be a list of strings")

        return cls(
            id=rule_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            cis=cis,
            check=check,
            remediation=remediation,
            tags=tuple(t.strip() for t in tags),
            references=tuple(references),
        )


def _require_text(data: dict[str, Any], key: str, rule_id: str, max_len: int) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(rule_id, f"{key} must be a non-empty string")
    value = value.strip()
    if len(value) > max_len:
        raise RuleValidationError(rule_id, f"{key} must be at most {max_len} characters")
    return value


@dataclass(frozen=True)
class CheckResult:
    """Raw result returned by a check implementation."""

    status: Status
    message: str
    path: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def passed(cls, message: str, path: str | None = None, **evidence: Any) -> CheckResult:
        return cls(Status.PASS, message, path, evidence)

    @classmethod
    def failed(cls, message: str, path: str | None = None, **evidence: Any) -> CheckResult:
        return cls(Status.FAIL, message, path, evidence)

    @classmethod
    def not_applicable(cls, message: str, path: str | None = None, **evidence: Any) -> CheckResult:
        return cls(Status.NOT_APPLICABLE, message, path, evidence)

    @classmethod
    def error(cls, message: str, path: str | None = None, **evidence: Any) -> CheckResult:
        return cls(Status.ERROR, message, path, evidence)


@dataclass
class Finding:
    """A rule result joined with its rule metadata."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    cis: str
    status: Status
    message: str
    path: str | None = None
    remediation: Remediation = field(default_factory=lambda: Remediation(text=""))
    tags: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: str | None = None
    suppression_expires: str | None = None

    @property
    def is_failing(self) -> bool:
        return self.status.is_failing and not self.suppressed

    @property
    def counts_in_score(self) -> bool:
        return self.status is not Status.NOT_APPLICABLE and not self.suppressed

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "cis": self.cis,
            "status": self.status.value,
            "message": self.message,
            "path": self.path,
            "remediation": self.remediation.to_dict(),
            "tags": list(self.tags),
            "suppressed": self.suppressed,
        }
        if self.evidence:
            payload["evidence"] = self.evidence
        if self.suppressed:
            payload["suppression_reason"] = self.suppression_reason
            payload["suppression_expires"] = self.suppression_expires
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            rule_id=str(data["rule_id"]),
            title=str(data["title"]),
            severity=Severity.parse(data["severity"]),
            category=str(data["category"]),
            cis=str(data.get("cis", "")),
            status=Status(str(data["status"])),
            message=str(data.get("message", "")),
            path=data.get("path"),
            remediation=Remediation.from_dict(data.get("remediation"), require_text=False),
            tags=tuple(data.get("tags", [])),
            evidence=dict(data.get("evidence", {})),
            suppressed=bool(data.get("suppressed", False)),
            suppression_reason=data.get("suppression_reason"),
            suppression_expires=data.get("suppression_expires"),
        )


@dataclass
class SeverityStats:
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    not_applicable: int = 0
    suppressed: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "not_applicable": self.not_applicable,
            "suppressed": self.suppressed,
        }


@dataclass
class Summary:
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    not_applicable: int = 0
    suppressed: int = 0
    by_severity: dict[str, SeverityStats] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "not_applicable": self.not_applicable,
            "suppressed": self.suppressed,
            "by_severity": {k: v.to_dict() for k, v in self.by_severity.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Summary:
        return cls(
            total=int(data.get("total", 0)),
            passed=int(data.get("passed", 0)),
            failed=int(data.get("failed", 0)),
            errors=int(data.get("errors", 0)),
            not_applicable=int(data.get("not_applicable", 0)),
            suppressed=int(data.get("suppressed", 0)),
            by_severity={
                str(k): SeverityStats(**v) for k, v in dict(data.get("by_severity", {})).items()
            },
        )


@dataclass
class CategoryScore:
    category: str
    score: float
    total_weight: int
    passed_weight: int
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    not_applicable: int = 0
    suppressed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "score": round(self.score, 2),
            "total_weight": self.total_weight,
            "passed_weight": self.passed_weight,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "not_applicable": self.not_applicable,
            "suppressed": self.suppressed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CategoryScore:
        return cls(
            category=str(data["category"]),
            score=float(data.get("score", 0.0)),
            total_weight=int(data.get("total_weight", 0)),
            passed_weight=int(data.get("passed_weight", 0)),
            total=int(data.get("total", 0)),
            passed=int(data.get("passed", 0)),
            failed=int(data.get("failed", 0)),
            errors=int(data.get("errors", 0)),
            not_applicable=int(data.get("not_applicable", 0)),
            suppressed=int(data.get("suppressed", 0)),
        )


@dataclass
class TopRisk:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TopRisk:
        return cls(
            rule_id=str(data["rule_id"]),
            title=str(data["title"]),
            severity=Severity.parse(data["severity"]),
            category=str(data["category"]),
            message=str(data.get("message", "")),
            path=data.get("path"),
        )


@dataclass
class BaselineException:
    rule_id: str
    reason: str
    expires: str
    state: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.rule_id,
            "reason": self.reason,
            "expires": self.expires,
            "state": self.state,
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineException:
        return cls(
            rule_id=str(data["id"]),
            reason=str(data.get("reason", "")),
            expires=str(data.get("expires", "")),
            state=str(data.get("state", "")),
            detail=str(data.get("detail", "")),
        )


@dataclass
class BaselineStatus:
    path: str | None = None
    active: int = 0
    suppressed: int = 0
    expired: list[BaselineException] = field(default_factory=list)
    unused: list[BaselineException] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "active": self.active,
            "suppressed": self.suppressed,
            "expired": [item.to_dict() for item in self.expired],
            "unused": [item.to_dict() for item in self.unused],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineStatus:
        return cls(
            path=data.get("path"),
            active=int(data.get("active", 0)),
            suppressed=int(data.get("suppressed", 0)),
            expired=[BaselineException.from_dict(x) for x in data.get("expired", [])],
            unused=[BaselineException.from_dict(x) for x in data.get("unused", [])],
        )


@dataclass
class AuditReport:
    """The complete, JSON-serializable result of one audit run."""

    schema_version: str
    tool_version: str
    generated_at: str
    root: str
    findings: list[Finding] = field(default_factory=list)
    score: float = 100.0
    grade: str = "A"
    summary: Summary = field(default_factory=Summary)
    categories: list[CategoryScore] = field(default_factory=list)
    top_risks: list[TopRisk] = field(default_factory=list)
    baseline: BaselineStatus = field(default_factory=BaselineStatus)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    ruleset_fingerprint: str = ""

    @property
    def gate_failures(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.is_failing]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "root": self.root,
            "score": round(self.score, 2),
            "grade": self.grade,
            "summary": self.summary.to_dict(),
            "categories": [item.to_dict() for item in self.categories],
            "top_risks": [item.to_dict() for item in self.top_risks],
            "findings": [item.to_dict() for item in self.findings],
            "baseline": self.baseline.to_dict(),
            "errors": list(self.errors),
            "duration_ms": self.duration_ms,
            "ruleset_fingerprint": self.ruleset_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditReport:
        return cls(
            schema_version=str(data.get("schema_version", "1.0")),
            tool_version=str(data.get("tool_version", "")),
            generated_at=str(data.get("generated_at", "")),
            root=str(data.get("root", "")),
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            score=float(data.get("score", 0.0)),
            grade=str(data.get("grade", "F")),
            summary=Summary.from_dict(dict(data.get("summary", {}))),
            categories=[CategoryScore.from_dict(item) for item in data.get("categories", [])],
            top_risks=[TopRisk.from_dict(item) for item in data.get("top_risks", [])],
            baseline=BaselineStatus.from_dict(dict(data.get("baseline", {}))),
            errors=[str(item) for item in data.get("errors", [])],
            duration_ms=int(data.get("duration_ms", 0)),
            ruleset_fingerprint=str(data.get("ruleset_fingerprint", "")),
        )


def utc_now_iso() -> str:
    """Timestamp with second precision, always UTC."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_date(value: str) -> date:
    """Parse a strict YYYY-MM-DD date."""
    return date.fromisoformat(value)
