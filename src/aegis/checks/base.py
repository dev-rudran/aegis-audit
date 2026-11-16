"""Shared helpers for check implementations and their parameter validators."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from aegis.models import CheckResult, Rule
from aegis.util.fs import RootFS
from aegis.util.text import parse_int


class ParamError(ValueError):
    """A check parameter is missing or has the wrong type."""


@dataclass
class CheckContext:
    """Per-run environment shared by all checks."""

    fs: RootFS
    cache: dict[str, Any] = field(default_factory=dict)


class ParamReader:
    """Validated access to a check's ``params`` mapping.

    Collects every problem rather than stopping at the first one so that
    ``aegis rules validate`` can report actionable diagnostics.
    """

    def __init__(self, params: dict[str, Any], allowed: set[str]) -> None:
        self.params = params
        self.allowed = allowed
        self.errors: list[str] = []
        unknown = sorted(set(params) - allowed)
        if unknown:
            self.errors.append(f"unknown parameter(s): {', '.join(unknown)}")

    def str(
        self,
        key: str,
        *,
        required: bool = False,
        default: str | None = None,
        choices: tuple[str, ...] | None = None,
        allow_empty: bool = False,
    ) -> str | None:
        if key not in self.params:
            if required:
                self.errors.append(f"missing required parameter {key!r}")
                return None
            return default
        value = self.params[key]
        if not isinstance(value, str):
            self.errors.append(f"parameter {key!r} must be a string")
            return None
        if not allow_empty and not value.strip():
            self.errors.append(f"parameter {key!r} must not be empty")
            return None
        value = value.strip()
        if choices is not None and value.lower() not in choices:
            self.errors.append(f"parameter {key!r} must be one of: {', '.join(choices)}")
            return None
        return value.lower() if choices is not None else value

    def int(
        self,
        key: str,
        *,
        required: bool = False,
        default: int | None = None,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int | None:
        if key not in self.params:
            if required:
                self.errors.append(f"missing required parameter {key!r}")
            return default
        value = self.params[key]
        if isinstance(value, bool) or not isinstance(value, int):
            self.errors.append(f"parameter {key!r} must be an integer")
            return None
        if minimum is not None and value < minimum:
            self.errors.append(f"parameter {key!r} must be >= {minimum}")
            return None
        if maximum is not None and value > maximum:
            self.errors.append(f"parameter {key!r} must be <= {maximum}")
            return None
        return value

    def bool(self, key: str, *, default: bool = False) -> bool:
        if key not in self.params:
            return default
        value = self.params[key]
        if not isinstance(value, bool):
            self.errors.append(f"parameter {key!r} must be a boolean")
            return default
        return value

    def list(
        self,
        key: str,
        *,
        required: bool = False,
        default: tuple[str, ...] = (),
        item_type: type = str,
        allow_single: bool = True,
    ) -> list[Any]:
        if key not in self.params:
            if required:
                self.errors.append(f"missing required parameter {key!r}")
            return list(default)
        value = self.params[key]
        if allow_single and not isinstance(value, list):
            value = [value]
        if not isinstance(value, list):
            self.errors.append(f"parameter {key!r} must be a list")
            return []
        result: list[Any] = []
        for item in value:
            if item_type is int:
                parsed = item if isinstance(item, int) and not isinstance(item, bool) else None
                if parsed is None:
                    self.errors.append(f"parameter {key!r} must contain integers")
                    continue
                result.append(parsed)
            else:
                if not isinstance(item, str) or not item.strip():
                    self.errors.append(f"parameter {key!r} must contain non-empty strings")
                    continue
                result.append(item.strip())
        return result

    def mode(self, key: str, *, required: bool = False, default: str | None = None) -> int | None:
        value = self.str(key, required=required, default=default)
        if value is None:
            return None
        try:
            from aegis.util.fs import parse_mode

            return parse_mode(value)
        except ValueError as exc:
            self.errors.append(f"parameter {key!r}: {exc}")
            return None

    def regex(self, key: str, *, required: bool = False, default: str | None = None):
        value = self.str(key, required=required, default=default)
        if value is None:
            return None
        try:
            return re.compile(value)
        except re.error as exc:
            self.errors.append(f"parameter {key!r} is not a valid regular expression: {exc}")
            return None

    def finish(self) -> list[str]:
        return list(self.errors)


def ensure_ok(reader: ParamReader) -> None:
    errors = reader.finish()
    if errors:
        raise ParamError("; ".join(errors))


def read_or_none(ctx: CheckContext, path: str) -> str | None:
    return ctx.fs.read_text(path)


def evaluate_scalar(
    actual: str | int | None,
    *,
    allowed: list[str] | None = None,
    exact: str | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
    compare_lower: bool = True,
) -> tuple[bool, str]:
    """Evaluate a scalar against allowed values and/or numeric bounds.

    Returns ``(compliant, human_readable_requirement)``.
    """
    requirements: list[str] = []
    if exact is not None:
        requirements.append(f"= {exact}")
    if allowed:
        requirements.append(f"in {{{', '.join(allowed)}}}")
    if minimum is not None:
        requirements.append(f">= {minimum}")
    if maximum is not None:
        requirements.append(f"<= {maximum}")
    requirement = " ".join(requirements) if requirements else "configured"
    if actual is None:
        return False, requirement

    if isinstance(actual, int):
        if minimum is not None and actual < minimum:
            return False, requirement
        if maximum is not None and actual > maximum:
            return False, requirement
        if allowed:
            values = {_norm(item) for item in allowed}
            if _norm(str(actual)) not in values:
                return False, requirement
        if exact is not None and _norm(str(actual)) != _norm(exact):
            return False, requirement
        return True, requirement

    text = actual.strip()
    normalized = _norm(text) if compare_lower else text
    if allowed:
        values = {_norm(item) if compare_lower else item for item in allowed}
        if normalized not in values:
            return False, requirement
        return True, requirement
    if exact is not None:
        if normalized != (_norm(exact) if compare_lower else exact):
            return False, requirement
        return True, requirement

    number = parse_int(text)
    if minimum is not None and (number is None or number < minimum):
        return False, requirement
    if maximum is not None and (number is None or number > maximum):
        return False, requirement
    return True, requirement


def _norm(value: str) -> str:
    return " ".join(value.strip().strip("'\"").split()).lower()


def numeric_in_range(
    value: str | int | None, *, minimum: int | None = None, maximum: int | None = None
) -> bool:
    if value is None:
        return False
    number = value if isinstance(value, int) else parse_int(value)
    if number is None:
        return False
    if minimum is not None and number < minimum:
        return False
    return maximum is None or number <= maximum


def merge_check(
    rule: Rule,
    ctx: CheckContext,
    message: str,
    *,
    path: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> CheckResult:
    return CheckResult.failed(message, path=path, **(evidence or {}))


def service_unit_state(ctx: CheckContext, name: str) -> tuple[bool, str]:
    """Return ``(enabled, detail)`` for a systemd unit, using symlinks only.

    This deliberately inspects the offline filesystem rather than asking the
    running init system, so it works identically for a live host and a mounted
    image.
    """
    unit = name if "." in name else f"{name}.service"
    fs = ctx.fs
    try:
        if (
            fs.is_symlink(f"/etc/systemd/system/{unit}")
            and fs.readlink(f"/etc/systemd/system/{unit}") == "/dev/null"
        ):
            return False, f"{unit} is masked"
    except (OSError, ValueError):
        pass
    candidates = fs.glob(f"/etc/systemd/system/*.wants/{unit}")
    candidates += fs.glob(f"/etc/systemd/system/*.requires/{unit}")
    if candidates:
        relative = candidates[0].relative_to(fs.root).as_posix()
        return True, f"enabled via /{relative}"
    return False, f"no enablement symlink for {unit} under /etc/systemd/system"


__all__ = [
    "CheckContext",
    "ParamError",
    "ParamReader",
    "ensure_ok",
    "evaluate_scalar",
    "merge_check",
    "numeric_in_range",
    "read_or_none",
    "service_unit_state",
]
