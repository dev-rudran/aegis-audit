"""Time-bound exception baselines.

A baseline suppresses known failures only until their expiry date.  Expired
entries are surfaced as stale exceptions and never suppress a finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from aegis.models import (
    ID_PATTERN,
    BaselineException,
    BaselineStatus,
    Finding,
    Status,
)
from aegis.util.fs import parse_mode  # noqa: F401 - re-exported for convenience


class BaselineError(ValueError):
    """The baseline document is invalid."""


@dataclass(frozen=True)
class BaselineEntry:
    rule_id: str
    reason: str
    expires: date

    def as_exception(self, state: str, detail: str = "") -> BaselineException:
        return BaselineException(
            rule_id=self.rule_id,
            reason=self.reason,
            expires=self.expires.isoformat(),
            state=state,
            detail=detail,
        )


@dataclass
class Baseline:
    entries: list[BaselineEntry] = field(default_factory=list)
    source: str | None = None

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        location = Path(path)
        if not location.is_file():
            raise BaselineError(f"baseline file not found: {location}")
        try:
            document = yaml.safe_load(location.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise BaselineError(f"cannot parse {location}: {exc}") from exc
        entries = _parse_entries(document, str(location))
        return cls(entries=entries, source=str(location))

    @classmethod
    def from_dict(cls, document: Any, source: str = "<memory>") -> Baseline:
        return cls(entries=_parse_entries(document, source), source=source)

    def apply(self, findings: list[Finding], *, today: date | None = None) -> BaselineStatus:
        current = today or date.today()
        status = BaselineStatus(path=self.source, active=0, suppressed=0)
        active: dict[str, BaselineEntry] = {}
        for entry in self.entries:
            if entry.expires < current:
                status.expired.append(
                    entry.as_exception(
                        "expired", f"expired on {entry.expires.isoformat()}; not suppressed"
                    )
                )
            else:
                active[entry.rule_id] = entry
        status.active = len(active)
        used: set[str] = set()
        for finding in findings:
            entry = active.get(finding.rule_id)
            if entry is None or not finding.status.is_failing:
                continue
            finding.suppressed = True
            finding.suppression_reason = entry.reason
            finding.suppression_expires = entry.expires.isoformat()
            used.add(finding.rule_id)
        status.suppressed = len(used)
        for rule_id, entry in active.items():
            if rule_id not in used:
                status.unused.append(
                    entry.as_exception("unused", "active entry did not match a failing finding")
                )
        return status


def _parse_entries(document: Any, source: str) -> list[BaselineEntry]:
    raw_entries: Any
    if document is None:
        raw_entries = []
    elif isinstance(document, list):
        raw_entries = document
    elif isinstance(document, dict):
        raw_entries = document.get("exceptions", document.get("entries", []))
    else:
        raise BaselineError(f"{source}: expected a mapping with an 'exceptions' list")
    if not isinstance(raw_entries, list):
        raise BaselineError(f"{source}: 'exceptions' must be a list")

    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        location = f"{source}: exceptions[{index}]"
        if not isinstance(raw, dict):
            raise BaselineError(f"{location}: entry must be a mapping")
        rule_id = raw.get("id")
        if not isinstance(rule_id, str) or not ID_PATTERN.match(rule_id):
            raise BaselineError(f"{location}: 'id' must match AEGIS-####")
        if rule_id in seen:
            raise BaselineError(f"{location}: duplicate baseline entry for {rule_id}")
        seen.add(rule_id)
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(f"{location}: 'reason' must be a non-empty string")
        expires_raw = raw.get("expires")
        if isinstance(expires_raw, date):
            expires = expires_raw
        elif isinstance(expires_raw, str):
            try:
                expires = date.fromisoformat(expires_raw.strip())
            except ValueError as exc:
                raise BaselineError(f"{location}: 'expires' must be YYYY-MM-DD") from exc
        else:
            raise BaselineError(f"{location}: 'expires' must be a YYYY-MM-DD date")
        entries.append(BaselineEntry(rule_id=rule_id, reason=reason.strip(), expires=expires))
    return entries


def is_baseline_suppressed(finding: Finding) -> bool:
    """Convenience predicate used by reporters and tests."""
    return finding.suppressed and finding.status in (Status.FAIL, Status.ERROR)
