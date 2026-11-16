"""OpenSSH server configuration checks."""

from __future__ import annotations

import posixpath
from typing import Any

from aegis.checks.base import CheckContext, ParamReader
from aegis.models import CheckResult, Rule
from aegis.util.fs import RootEscapeError
from aegis.util.text import normalise_whitespace, parse_bool, unquote

ALLOWED_SSHD = {"key", "value", "default", "missing", "config", "compare"}
MAX_INCLUDE_DEPTH = 8


def validate_sshd(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_SSHD)
    reader.str("key", required=True)
    value = params.get("value")
    if value is None:
        reader.errors.append("missing required parameter 'value'")
    elif not isinstance(value, (str, list)):
        reader.errors.append("parameter 'value' must be a string or list of strings")
    elif isinstance(value, list) and (
        not value or not all(isinstance(item, str) and item.strip() for item in value)
    ):
        reader.errors.append("parameter 'value' must not contain empty values")
    default = params.get("default")
    if default is not None and not isinstance(default, (str, list)):
        reader.errors.append("parameter 'default' must be a string or list of strings")
    reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    reader.str("config", default="/etc/ssh/sshd_config")
    reader.str("compare", default="lower", choices=("lower", "exact"))
    return reader.finish()


def _expand_includes(
    ctx: CheckContext,
    config: str,
    *,
    depth: int,
    seen: set[str],
    directives: list[tuple[str, str, str, int]],
    errors: list[str],
) -> None:
    if depth > MAX_INCLUDE_DEPTH:
        errors.append(f"sshd Include depth exceeded at {config}")
        return
    display = ctx.fs.display(config)
    if display in seen:
        return
    seen.add(display)
    try:
        text = ctx.fs.read_text(config)
    except (OSError, ValueError, RootEscapeError) as exc:
        errors.append(str(exc))
        return
    if text is None:
        if depth == 0:
            errors.append(f"{display} does not exist")
        return
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if lowered == "match" or lowered.startswith("match "):
            # Everything after Match is conditional and is outside the scope of
            # a global directive audit.
            return
        if "=" in line and " " not in line.split("=", 1)[0].strip():
            key, _, value = line.partition("=")
        else:
            parts = line.split(None, 1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else ""
        key = key.strip()
        value = value.strip()
        if key.lower() == "include":
            for pattern in value.split():
                expanded = pattern
                if not pattern.startswith("/"):
                    expanded = posixpath.normpath(
                        posixpath.join(posixpath.dirname(config), pattern)
                    )
                try:
                    matches = ctx.fs.glob(expanded)
                except RootEscapeError as exc:
                    errors.append(str(exc))
                    continue
                for match in matches:
                    relative = match.relative_to(ctx.fs.root).as_posix()
                    _expand_includes(
                        ctx,
                        relative,
                        depth=depth + 1,
                        seen=seen,
                        directives=directives,
                        errors=errors,
                    )
            continue
        directives.append((key.lower(), value, display, lineno))


def _expected_values(rule: Rule) -> list[str]:
    raw = rule.params.get("value")
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return []


def _default_values(rule: Rule) -> list[str]:
    raw = rule.params.get("default")
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return []


def _comparable(value: str, compare: str) -> str:
    value = unquote(normalise_whitespace(value))
    return value.lower() if compare == "lower" else value


def run_sshd(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_SSHD)
    key = reader.str("key", required=True)
    config = reader.str("config", default="/etc/ssh/sshd_config")
    compare = reader.str("compare", default="lower", choices=("lower", "exact"))
    missing = reader.str("missing", default="fail", choices=("fail", "not_applicable"))
    expected = _expected_values(rule)
    defaults = _default_values(rule)
    if key is None or config is None or compare is None or missing is None or not expected:
        return CheckResult.error("invalid rule parameters")
    directives: list[tuple[str, str, str, int]] = []
    errors: list[str] = []
    _expand_includes(
        ctx,
        config.lstrip("/"),
        depth=0,
        seen=set(),
        directives=directives,
        errors=errors,
    )
    display = ctx.fs.display(config)
    normalized_key = key.lower()
    found = next((item for item in directives if item[0] == normalized_key), None)
    accepted = {_comparable(item, compare) for item in expected}
    if found is None:
        if defaults:
            actual = defaults[0]
            source = "built-in default"
            lineno = 0
        else:
            message = f"{display} does not set {key}"
            if errors:
                message += f" ({'; '.join(errors[:2])})"
            if missing == "not_applicable":
                return CheckResult.not_applicable(message, path=display, key=key)
            return CheckResult.failed(message, path=display, key=key, expected=expected)
    else:
        _, actual, source, lineno = found
    compliant = _comparable(actual, compare) in accepted
    evidence = {
        "key": key,
        "actual": actual,
        "expected": expected,
        "source": source,
        "line": lineno,
        "defaulted": found is None,
        "directive_count": len(directives),
    }
    if errors:
        evidence["parse_errors"] = errors[:5]
    if compliant:
        where = "built-in default" if found is None else f"{source}:{lineno}"
        return CheckResult.passed(
            f"{key} {actual!r} is compliant ({where})", path=source, **evidence
        )
    where = "built-in default" if found is None else f"{source}:{lineno}"
    return CheckResult.failed(
        f"{key} is {actual!r}, expected {' or '.join(repr(item) for item in expected)}"
        f" (from {where})",
        path=source,
        **evidence,
    )


def ssh_flag(value: str) -> bool | None:
    """Expose the boolean parser for tests and future rule extensions."""
    return parse_bool(value)
