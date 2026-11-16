"""Checks for file existence, permissions, ownership, content, and world-writable files."""

from __future__ import annotations

import os
import stat as stat_module
from typing import Any

from aegis.checks.base import CheckContext, ParamReader
from aegis.models import CheckResult, Rule
from aegis.util.fs import RootEscapeError, format_mode
from aegis.util.shell import parse_group, parse_passwd

ALLOWED_FILE_EXISTS = {"path", "state", "kind"}
ALLOWED_FILE_MODE = {"path", "max_mode", "exact", "missing"}
ALLOWED_FILE_OWNER = {"path", "owner", "group", "missing"}
ALLOWED_FILE_CONTENT = {"path", "pattern", "state", "ignore_case", "multiline", "missing"}
ALLOWED_WORLD_WRITABLE = {"root", "max_depth", "max_entries", "exclude_dirs", "max_reported"}


def validate_file_exists(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_FILE_EXISTS)
    reader.str("path", required=True)
    reader.str("state", default="present", choices=("present", "absent"))
    reader.str("kind", default="any", choices=("any", "file", "dir"))
    return reader.finish()


def run_file_exists(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_FILE_EXISTS)
    path = reader.str("path", required=True)
    state = reader.str("state", default="present", choices=("present", "absent"))
    kind = reader.str("kind", default="any", choices=("any", "file", "dir"))
    if path is None or state is None or kind is None:
        return CheckResult.error("invalid rule parameters")
    try:
        exists = ctx.fs.exists(path)
        if exists and kind == "file":
            exists = ctx.fs.is_file(path)
        elif exists and kind == "dir":
            exists = ctx.fs.is_dir(path)
    except RootEscapeError as exc:
        return CheckResult.error(str(exc), path=path)
    display = ctx.fs.display(path)
    if state == "present":
        if exists:
            return CheckResult.passed(f"{display} exists", path=display)
        return CheckResult.failed(
            f"{display} is missing (expected {kind})", path=display, expected=kind
        )
    if exists:
        return CheckResult.failed(f"{display} exists but must be absent", path=display)
    return CheckResult.passed(f"{display} is absent", path=display)


def validate_file_mode(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_FILE_MODE)
    reader.str("path", required=True)
    reader.mode("max_mode", required=True)
    reader.bool("exact", default=False)
    reader.str("missing", default="not_applicable", choices=("not_applicable", "fail", "pass"))
    return reader.finish()


def run_file_mode(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_FILE_MODE)
    path = reader.str("path", required=True)
    allowed_mode = reader.mode("max_mode", required=True)
    exact = reader.bool("exact", default=False)
    missing = reader.str(
        "missing", default="not_applicable", choices=("not_applicable", "fail", "pass")
    )
    if path is None or allowed_mode is None or missing is None:
        return CheckResult.error("invalid rule parameters")
    display = ctx.fs.display(path)
    try:
        info = ctx.fs.stat(path)
    except FileNotFoundError:
        if missing == "fail":
            return CheckResult.failed(
                f"{display} is missing; cannot verify permissions", path=display
            )
        if missing == "pass":
            return CheckResult.passed(f"{display} is missing (accepted by rule)", path=display)
        return CheckResult.not_applicable(f"{display} is missing", path=display)
    except (RootEscapeError, OSError) as exc:
        return CheckResult.error(str(exc), path=display)
    actual = stat_module.S_IMODE(info.st_mode)
    if exact:
        compliant = actual == allowed_mode
    else:
        compliant = (actual & ~allowed_mode) == 0
    evidence = {
        "actual_mode": format_mode(actual),
        "allowed_mode": format_mode(allowed_mode),
        "exact": exact,
    }
    if compliant:
        return CheckResult.passed(
            f"{display} mode {format_mode(actual)} is within {format_mode(allowed_mode)}",
            path=display,
            **evidence,
        )
    return CheckResult.failed(
        f"{display} mode {format_mode(actual)} exceeds allowed {format_mode(allowed_mode)}",
        path=display,
        **evidence,
    )


def validate_file_owner(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_FILE_OWNER)
    reader.str("path", required=True)
    reader.str("owner", required=True)
    reader.str("group")
    reader.str("missing", default="not_applicable", choices=("not_applicable", "fail", "pass"))
    return reader.finish()


def _resolve_principal(ctx: CheckContext, name: str, kind: str) -> int | None:
    if name.isdigit():
        return int(name, 10)
    if kind == "user":
        text = ctx.fs.read_text("/etc/passwd", default="") or ""
        for account in parse_passwd(text):
            if account.name == name:
                return account.uid
    else:
        text = ctx.fs.read_text("/etc/group", default="") or ""
        for group in parse_group(text):
            if group.name == name:
                return group.gid
    return None


def run_file_owner(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_FILE_OWNER)
    path = reader.str("path", required=True)
    owner = reader.str("owner", required=True)
    group = reader.str("group")
    missing = reader.str(
        "missing", default="not_applicable", choices=("not_applicable", "fail", "pass")
    )
    if path is None or owner is None or missing is None:
        return CheckResult.error("invalid rule parameters")
    display = ctx.fs.display(path)
    try:
        info = ctx.fs.stat(path)
    except FileNotFoundError:
        if missing == "fail":
            return CheckResult.failed(
                f"{display} is missing; cannot verify ownership", path=display
            )
        if missing == "pass":
            return CheckResult.passed(f"{display} is missing (accepted by rule)", path=display)
        return CheckResult.not_applicable(f"{display} is missing", path=display)
    except (RootEscapeError, OSError) as exc:
        return CheckResult.error(str(exc), path=display)

    expected_uid = _resolve_principal(ctx, owner, "user")
    if expected_uid is None:
        return CheckResult.error(
            f"owner {owner!r} does not exist in {display.rsplit('/', 1)[0]}/etc/passwd",
            path=display,
        )
    expected_gid: int | None = None
    if group is not None:
        expected_gid = _resolve_principal(ctx, group, "group")
        if expected_gid is None:
            return CheckResult.error(f"group {group!r} does not exist in /etc/group", path=display)

    problems: list[str] = []
    if info.st_uid != expected_uid:
        problems.append(f"uid {info.st_uid} (expected {expected_uid})")
    if expected_gid is not None and info.st_gid != expected_gid:
        problems.append(f"gid {info.st_gid} (expected {expected_gid})")
    evidence = {
        "actual_uid": info.st_uid,
        "actual_gid": info.st_gid,
        "expected_uid": expected_uid,
        "expected_gid": expected_gid,
    }
    if problems:
        return CheckResult.failed(
            f"{display} ownership is wrong: {'; '.join(problems)}", path=display, **evidence
        )
    return CheckResult.passed(f"{display} is owned by {owner}", path=display, **evidence)


def validate_file_content(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_FILE_CONTENT)
    reader.str("path", required=True)
    reader.regex("pattern", required=True)
    reader.str("state", default="present", choices=("present", "absent"))
    reader.bool("ignore_case", default=False)
    reader.bool("multiline", default=True)
    reader.str(
        "missing",
        default=None,
        choices=("not_applicable", "fail", "pass"),
    )
    return reader.finish()


def run_file_content(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_FILE_CONTENT)
    path = reader.str("path", required=True)
    state = reader.str("state", default="present", choices=("present", "absent"))
    ignore_case = reader.bool("ignore_case", default=False)
    multiline = reader.bool("multiline", default=True)
    missing = reader.str("missing", choices=("not_applicable", "fail", "pass"))
    raw_pattern = reader.str("pattern", required=True)
    if path is None or state is None or raw_pattern is None:
        return CheckResult.error("invalid rule parameters")
    import re

    flags = 0
    if ignore_case:
        flags |= re.IGNORECASE
    if multiline:
        flags |= re.MULTILINE
    try:
        pattern = re.compile(raw_pattern, flags)
    except re.error as exc:
        return CheckResult.error(f"invalid regular expression: {exc}", path=path)
    display = ctx.fs.display(path)
    try:
        text = ctx.fs.read_text(path)
    except (OSError, ValueError) as exc:
        return CheckResult.error(str(exc), path=display)
    if text is None:
        if missing is None:
            missing = "fail" if state == "present" else "pass"
        if missing == "fail":
            return CheckResult.failed(
                f"{display} is missing; cannot evaluate content", path=display
            )
        if missing == "pass":
            return CheckResult.passed(f"{display} is missing (accepted by rule)", path=display)
        return CheckResult.not_applicable(f"{display} is missing", path=display)

    match = pattern.search(text)
    if state == "present" and match:
        line = text.count("\n", 0, match.start()) + 1
        return CheckResult.passed(
            f"{display} contains required pattern on line {line}",
            path=display,
            line=line,
            match=match.group(0)[:200],
        )
    if state == "absent" and not match:
        return CheckResult.passed(f"{display} does not contain the forbidden pattern", path=display)
    if state == "present":
        return CheckResult.failed(f"{display} is missing the required pattern", path=display)
    if match is None:  # pragma: no cover - all state/path combinations are handled above
        return CheckResult.error(f"internal pattern state error for {display}", path=display)
    line = text.count("\n", 0, match.start()) + 1
    offending = text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else ""
    return CheckResult.failed(
        f"{display} contains a forbidden pattern on line {line}",
        path=display,
        line=line,
        match=match.group(0)[:200],
        line_text=offending[:200],
    )


def validate_world_writable(params: dict[str, Any]) -> list[str]:
    reader = ParamReader(params, ALLOWED_WORLD_WRITABLE)
    reader.str("root", default="/")
    reader.int("max_depth", default=8, minimum=1, maximum=32)
    reader.int("max_entries", default=50_000, minimum=1, maximum=1_000_000)
    reader.list("exclude_dirs", default=("proc", "sys", "dev", "run"), item_type=str)
    reader.int("max_reported", default=20, minimum=1, maximum=1000)
    return reader.finish()


def run_world_writable(rule: Rule, ctx: CheckContext) -> CheckResult:
    reader = ParamReader(rule.params, ALLOWED_WORLD_WRITABLE)
    root = reader.str("root", default="/")
    max_depth = reader.int("max_depth", default=8, minimum=1, maximum=32)
    max_entries = reader.int("max_entries", default=50_000, minimum=1, maximum=1_000_000)
    exclude_dirs = reader.list("exclude_dirs", default=("proc", "sys", "dev", "run"), item_type=str)
    max_reported = reader.int("max_reported", default=20, minimum=1, maximum=1000)
    if root is None or max_depth is None or max_entries is None or max_reported is None:
        return CheckResult.error("invalid rule parameters")
    display_root = ctx.fs.display(root)
    violations: list[dict[str, Any]] = []
    scanned = 0
    try:
        for display, info in ctx.fs.walk(
            root,
            max_depth=max_depth,
            max_entries=max_entries,
            exclude_dirs=frozenset(exclude_dirs),
        ):
            scanned += 1
            if not stat_module.S_ISREG(info.st_mode):
                continue
            if info.st_mode & stat_module.S_IWOTH:
                violations.append(
                    {
                        "path": display,
                        "mode": format_mode(info.st_mode),
                        "uid": info.st_uid,
                    }
                )
    except RootEscapeError as exc:
        return CheckResult.error(str(exc), path=display_root)
    evidence = {
        "scanned": scanned,
        "world_writable_count": len(violations),
        "examples": violations[:max_reported],
    }
    if violations:
        examples = ", ".join(item["path"] for item in violations[:5])
        suffix = "" if len(violations) <= 5 else f" (+{len(violations) - 5} more)"
        message = (
            f"found {len(violations)} world-writable file(s) under "
            f"{display_root}: {examples}{suffix}"
        )
        return CheckResult.failed(
            message,
            path=display_root,
            **evidence,
        )
    return CheckResult.passed(
        f"no world-writable files under {display_root} ({scanned} entries scanned)",
        path=display_root,
        **evidence,
    )


def _stat_uid_gid(path: str) -> tuple[int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return info.st_uid, info.st_gid
