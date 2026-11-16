"""Safe, structured remediation engine.

Only rules that declare ``remediation.safe: true`` and a structured ``fix``
block can be applied.  Shell commands are advisory text and are never executed.
Dry-run is the default; ``--apply`` writes with an atomic replacement and a
``.aegis.bak`` backup.
"""

from __future__ import annotations

import contextlib
import difflib
import os
import re
import shutil
import stat as stat_module
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.models import AuditReport, Finding, Rule, Severity
from aegis.util.fs import RootFS, format_mode, parse_mode
from aegis.util.shell import parse_group, parse_passwd

MANUAL = "manual"
WOULD_APPLY = "would_apply"
APPLIED = "applied"
UNCHANGED = "unchanged"
ERROR = "error"
SKIPPED = "skipped"
BACKUP_SUFFIX = ".aegis.bak"


class FixError(RuntimeError):
    """A structured fix could not be planned or applied safely."""


@dataclass
class FixOutcome:
    rule_id: str
    title: str
    severity: Severity
    fix_type: str
    path: str
    status: str
    message: str
    before: str | None = None
    after: str | None = None
    diff: list[str] = field(default_factory=list)
    backup: str | None = None

    @property
    def changed(self) -> bool:
        return self.status in (WOULD_APPLY, APPLIED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "fix_type": self.fix_type,
            "path": self.path,
            "status": self.status,
            "message": self.message,
            "before": self.before,
            "after": self.after,
            "diff": list(self.diff),
            "backup": self.backup,
        }


@dataclass
class RemediationResult:
    dry_run: bool
    outcomes: list[FixOutcome] = field(default_factory=list)
    manual_rules: list[str] = field(default_factory=list)

    @property
    def applied(self) -> list[FixOutcome]:
        return [item for item in self.outcomes if item.status == APPLIED]

    @property
    def would_apply(self) -> list[FixOutcome]:
        return [item for item in self.outcomes if item.status == WOULD_APPLY]

    @property
    def errors(self) -> list[FixOutcome]:
        return [item for item in self.outcomes if item.status == ERROR]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "outcomes": [item.to_dict() for item in self.outcomes],
            "manual_rules": list(self.manual_rules),
        }


def validate_fix(fix: dict[str, Any]) -> list[str]:
    """Validate a structured fix block independently of running it."""
    fix_type = fix.get("type")
    errors: list[str] = []
    if not isinstance(fix_type, str):
        return ["fix.type must be a string"]
    if fix_type not in {
        "sshd_set",
        "sysctl_set",
        "file_mode",
        "file_owner",
        "login_defs_set",
        "pwquality_set",
        "config_set",
        "create_file",
    }:
        return [f"unsupported fix type {fix_type!r}"]
    if fix_type == "create_file":
        if not isinstance(fix.get("path"), str) or not fix["path"].startswith("/"):
            errors.append("create_file requires an absolute path")
        if not isinstance(fix.get("content"), str):
            errors.append("create_file requires string content")
        if "mode" in fix:
            try:
                parse_mode(fix["mode"])
            except ValueError as exc:
                errors.append(f"create_file mode: {exc}")
        return errors
    if not isinstance(fix.get("path"), str) or not fix["path"].startswith("/"):
        errors.append(f"{fix_type} requires an absolute path")
    if fix_type == "file_mode":
        try:
            parse_mode(fix.get("mode"))
        except (TypeError, ValueError) as exc:
            errors.append(f"file_mode mode: {exc}")
        return errors
    if fix_type == "file_owner":
        if not isinstance(fix.get("owner"), str) or not fix["owner"]:
            errors.append("file_owner requires owner")
        if "group" in fix and (not isinstance(fix["group"], str) or not fix["group"]):
            errors.append("file_owner group must be a non-empty string")
        return errors
    if not isinstance(fix.get("key"), str) or not fix["key"].strip():
        errors.append(f"{fix_type} requires a non-empty key")
    if "value" not in fix or not isinstance(fix["value"], (str, int)):
        errors.append(f"{fix_type} requires a scalar value")
    if fix_type == "config_set" and fix.get("separator") not in (None, "=", ":", " "):
        errors.append("config_set separator must be '=', ':', or ' '")
    return errors


class FixPlanner:
    def __init__(self, fs: RootFS, *, apply: bool = False) -> None:
        self.fs = fs
        self.apply = apply

    def plan(self, report: AuditReport, rules: list[Rule]) -> RemediationResult:
        result = RemediationResult(dry_run=not self.apply)
        by_id = {rule.id: rule for rule in rules}
        for finding in report.findings:
            rule = by_id.get(finding.rule_id)
            if rule is None:
                continue
            if not finding.status.is_failing or finding.suppressed:
                continue
            remediation = rule.remediation
            if not remediation.safe or remediation.fix is None:
                if finding.rule_id not in result.manual_rules:
                    result.manual_rules.append(finding.rule_id)
                continue
            fix_errors = validate_fix(remediation.fix)
            if fix_errors:
                result.outcomes.append(
                    self._error_outcome(finding, remediation.fix, "; ".join(fix_errors))
                )
                continue
            try:
                outcome = self._plan_one(finding, remediation.fix)
            except (FixError, OSError, ValueError) as exc:
                outcome = self._error_outcome(finding, remediation.fix, str(exc))
            result.outcomes.append(outcome)
        result.outcomes.sort(key=lambda item: (-item.severity.rank, item.rule_id))
        return result

    def _error_outcome(self, finding: Finding, fix: dict[str, Any], message: str) -> FixOutcome:
        return FixOutcome(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            fix_type=str(fix.get("type", "")),
            path=str(fix.get("path", "")),
            status=ERROR,
            message=message,
        )

    def _plan_one(self, finding: Finding, fix: dict[str, Any]) -> FixOutcome:
        fix_type = str(fix["type"])
        path = str(fix.get("path", ""))
        if fix_type == "file_mode":
            return self._plan_mode(finding, fix, path)
        if fix_type == "file_owner":
            return self._plan_owner(finding, fix, path)
        if fix_type == "create_file":
            return self._plan_create(finding, fix, path)
        return self._plan_text_edit(finding, fix, fix_type, path)

    def _target(self, path: str) -> Path:
        try:
            target = self.fs.resolve(path)
        except ValueError as exc:
            raise FixError(str(exc)) from exc
        if target == self.fs.root:
            raise FixError("refusing to modify the audit root itself")
        return target

    def _outcome(
        self,
        finding: Finding,
        fix_type: str,
        path: str,
        *,
        status: str,
        message: str,
        before: str | None = None,
        after: str | None = None,
        diff: list[str] | None = None,
        backup: str | None = None,
    ) -> FixOutcome:
        return FixOutcome(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            fix_type=fix_type,
            path=path,
            status=status,
            message=message,
            before=before,
            after=after,
            diff=diff or [],
            backup=backup,
        )

    def _plan_mode(self, finding: Finding, fix: dict[str, Any], path: str) -> FixOutcome:
        target = self._target(path)
        if not target.exists():
            raise FixError(f"{path} does not exist")
        current = stat_module.S_IMODE(target.stat().st_mode)
        desired = parse_mode(fix["mode"])
        before = format_mode(current)
        after = format_mode(desired)
        if current == desired:
            return self._outcome(
                finding,
                "file_mode",
                path,
                status=UNCHANGED,
                message=f"{path} already has mode {after}",
                before=before,
                after=after,
            )
        backup = None
        if self.apply:
            backup = self._backup(target, path)
            os.chmod(target, desired)
            current_after = stat_module.S_IMODE(target.stat().st_mode)
            if current_after != desired:
                raise FixError(
                    f"chmod on {path} did not take effect ({format_mode(current_after)})"
                )
        return self._outcome(
            finding,
            "file_mode",
            path,
            status=APPLIED if self.apply else WOULD_APPLY,
            message=f"change mode {before} -> {after}",
            before=before,
            after=after,
            diff=[f"mode {before} -> {after}"],
            backup=backup,
        )

    def _plan_owner(self, finding: Finding, fix: dict[str, Any], path: str) -> FixOutcome:
        target = self._target(path)
        if not target.exists():
            raise FixError(f"{path} does not exist")
        info = target.stat()
        uid = self._resolve_user(str(fix["owner"]))
        gid = info.st_gid if "group" not in fix else self._resolve_group(str(fix["group"]))
        before = f"{info.st_uid}:{info.st_gid}"
        after = f"{uid}:{gid}"
        if info.st_uid == uid and info.st_gid == gid:
            return self._outcome(
                finding,
                "file_owner",
                path,
                status=UNCHANGED,
                message=f"{path} already owned by {after}",
                before=before,
                after=after,
            )
        backup = None
        if self.apply:
            backup = self._backup(target, path)
            os.chown(target, uid, gid)
            info_after = target.stat()
            if info_after.st_uid != uid or info_after.st_gid != gid:
                raise FixError(f"chown on {path} did not take effect")
        return self._outcome(
            finding,
            "file_owner",
            path,
            status=APPLIED if self.apply else WOULD_APPLY,
            message=f"change ownership {before} -> {after}",
            before=before,
            after=after,
            diff=[f"owner {before} -> {after}"],
            backup=backup,
        )

    def _plan_create(self, finding: Finding, fix: dict[str, Any], path: str) -> FixOutcome:
        target = self._target(path)
        content = str(fix["content"])
        if target.exists():
            existing = target.read_text(encoding="utf-8", errors="replace")
            if existing == content:
                return self._outcome(
                    finding,
                    "create_file",
                    path,
                    status=UNCHANGED,
                    message=f"{path} already has the desired content",
                    before=existing,
                    after=content,
                )
            raise FixError(f"{path} already exists with different content; refusing to overwrite")
        desired_mode = parse_mode(fix.get("mode", "0644"))
        backup = None
        if self.apply:
            uid = self._resolve_user(str(fix["owner"])) if "owner" in fix else None
            gid = self._resolve_group(str(fix["group"])) if "group" in fix else None
            self._atomic_write(target, content.encode("utf-8"), desired_mode, uid, gid)
        return self._outcome(
            finding,
            "create_file",
            path,
            status=APPLIED if self.apply else WOULD_APPLY,
            message=f"create {path} with mode {format_mode(desired_mode)}",
            before=None,
            after=content,
            diff=[f"+ create {path}", f"+ mode {format_mode(desired_mode)}"],
            backup=backup,
        )

    def _plan_text_edit(
        self, finding: Finding, fix: dict[str, Any], fix_type: str, path: str
    ) -> FixOutcome:
        target = self._target(path)
        if not target.exists():
            raise FixError(f"{path} does not exist")
        if target.is_symlink():
            raise FixError(f"{path} is a symlink; refusing to replace it")
        before_bytes = target.read_bytes()
        before = before_bytes.decode("utf-8", errors="replace")
        key = str(fix["key"])
        value = str(fix["value"])
        if fix_type == "sshd_set":
            after, changed, added = edit_sshd_config(before, key, value)
        elif fix_type == "sysctl_set":
            after, changed, added = edit_assignment(
                before, key, value, separator="=", key_normalizer=_sysctl_key
            )
        elif fix_type == "login_defs_set":
            after, changed, added = edit_assignment(
                before, key, value, separator=None, preserve_separator=True
            )
        elif fix_type == "pwquality_set":
            after, changed, added = edit_assignment(
                before, key, value, separator="=", key_normalizer=str.lower
            )
        else:
            separator = fix.get("separator", "=")
            after, changed, added = edit_assignment(before, key, value, separator=str(separator))
        if not changed:
            return self._outcome(
                finding,
                fix_type,
                path,
                status=UNCHANGED,
                message=f"{path} already contains {key} {value}",
                before=before,
                after=before,
            )
        diff = list(
            difflib.unified_diff(
                before.splitlines(),
                after.splitlines(),
                fromfile=path,
                tofile=path,
                lineterm="",
                n=2,
            )
        )[:80]
        action = "add" if added else "update"
        backup = None
        if self.apply:
            backup = self._backup(target, path)
            original_mode = stat_module.S_IMODE(target.stat().st_mode)
            info = target.stat()
            self._atomic_write(
                target,
                after.encode("utf-8"),
                original_mode,
                info.st_uid,
                info.st_gid,
            )
        return self._outcome(
            finding,
            fix_type,
            path,
            status=APPLIED if self.apply else WOULD_APPLY,
            message=f"{action} {key} {value} in {path}",
            before=before,
            after=after,
            diff=diff,
            backup=backup,
        )

    def _backup(self, target: Path, display: str) -> str:
        backup = target.with_name(target.name + BACKUP_SUFFIX)
        if backup.is_symlink():
            raise FixError(f"backup path {display}{BACKUP_SUFFIX} is a symlink; refusing to write")
        if not backup.exists():
            shutil.copy2(target, backup)
        return self.fs.display(backup.relative_to(self.fs.root).as_posix())

    def _atomic_write(
        self,
        target: Path,
        data: bytes,
        mode: int,
        uid: int | None,
        gid: int | None,
    ) -> None:
        directory = target.parent
        fd, temporary = tempfile.mkstemp(
            prefix=f".{target.name}.aegis-", suffix=".tmp", dir=directory
        )
        temp_path = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, mode)
            if uid is not None or gid is not None:
                try:
                    os.chown(
                        temp_path,
                        uid if uid is not None else -1,
                        gid if gid is not None else -1,
                    )
                except PermissionError:
                    # Writing as an unprivileged user must not silently change
                    # ownership of a file the user can otherwise edit.
                    if target.exists() and (
                        target.stat().st_uid != os.getuid() or target.stat().st_gid != os.getgid()
                    ):
                        raise
            os.replace(temp_path, target)
            _fsync_directory(directory)
        except Exception:
            with contextlib.suppress(OSError):
                temp_path.unlink()
            raise

    def _resolve_user(self, name: str) -> int:
        if name.isdigit():
            return int(name, 10)
        text = self.fs.read_text("/etc/passwd", default="") or ""
        for account in parse_passwd(text):
            if account.name == name:
                return account.uid
        raise FixError(f"user {name!r} does not exist in the audit root")

    def _resolve_group(self, name: str) -> int:
        if name.isdigit():
            return int(name, 10)
        text = self.fs.read_text("/etc/group", default="") or ""
        for group in parse_group(text):
            if group.name == name:
                return group.gid
        raise FixError(f"group {name!r} does not exist in the audit root")


def _fsync_directory(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sysctl_key(value: str) -> str:
    return value.strip().lower().replace("/", ".")


def edit_assignment(
    text: str,
    key: str,
    value: str,
    *,
    separator: str | None = "=",
    preserve_separator: bool = False,
    key_normalizer=lambda item: item.strip().lower(),
) -> tuple[str, bool, bool]:
    """Replace existing assignments of ``key`` or append one.

    Returns ``(new_text, changed, appended)``.  Inline comments, indentation,
    the original key spelling, and unrelated lines are preserved.
    """
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    matched = False
    changed = False
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        parsed = _parse_assignment_line(line, separator)
        if parsed is None:
            continue
        line_key, key_text, separator_text, value_text, comment = parsed
        if key_normalizer(line_key) != key_normalizer(key):
            continue
        matched = True
        if value_text == value:
            continue
        indent = line[: len(line) - len(line.lstrip())]
        rebuilt = f"{indent}{key_text}{separator_text}{value}"
        if comment:
            rebuilt += f" {comment}"
        if rebuilt != line:
            lines[index] = rebuilt
            changed = True
    if matched:
        if not changed:
            return text, False, False
        return newline.join(lines) + (newline if text.endswith(("\n", "\r")) else ""), True, False
    addition = f"{key}{separator if separator is not None else ' '}{value}"
    if text and not text.endswith(("\n", "\r")):
        text += newline
    return text + addition + newline, True, True


def edit_sshd_config(text: str, key: str, value: str) -> tuple[str, bool, bool]:
    """Update the first global ``key`` directive, preserving the rest.

    Insertion occurs before the first ``Match`` block so the directive stays
    global.  Match-scoped overrides are left untouched.
    """
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    insert_at = len(lines)
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.lower() == "match" or stripped.lower().startswith("match "):
            insert_at = index
            break
        if not stripped or stripped.startswith("#"):
            continue
        parsed = _parse_sshd_line(raw)
        if parsed is None:
            continue
        line_key, key_text, value_text, comment = parsed
        if line_key.lower() != key.lower():
            continue
        if value_text == value:
            return text, False, False
        indent = raw[: len(raw) - len(raw.lstrip())]
        rebuilt = f"{indent}{key_text} {value}"
        if comment:
            rebuilt += f" {comment}"
        lines[index] = rebuilt
        return newline.join(lines) + (newline if text.endswith(("\n", "\r")) else ""), True, False
    addition = f"{key} {value}"
    lines.insert(insert_at, addition)
    return newline.join(lines) + newline, True, True


def _parse_assignment_line(
    line: str, separator: str | None
) -> tuple[str, str, str, str, str] | None:
    indent_len = len(line) - len(line.lstrip())
    body = line[indent_len:]
    body, comment = _split_comment(body)
    if not body.strip():
        return None
    if separator is None:
        match = re.match(r"^(\S+)(\s+)(\S+)\s*$", body)
        if not match:
            return None
        key_text, separator_text, value_text = match.groups()
    else:
        if separator not in body:
            return None
        key_part, _, value_part = body.partition(separator)
        key_text = key_part.rstrip()
        if not key_text or " " in key_text:
            return None
        # Preserve the exact whitespace around the separator.
        leading = key_part[len(key_text) :]
        value_text = value_part.strip()
        if not value_text:
            return None
        trailing = value_part[: len(value_part) - len(value_part.lstrip())]
        separator_text = f"{leading}{separator}{trailing}"
    return key_text.strip(), key_text, separator_text, value_text, comment


def _parse_sshd_line(line: str) -> tuple[str, str, str, str] | None:
    indent_len = len(line) - len(line.lstrip())
    body = line[indent_len:]
    body, comment = _split_comment(body)
    if not body.strip():
        return None
    if "=" in body and " " not in body.split("=", 1)[0].strip():
        key_text, _, value_text = body.partition("=")
    else:
        parts = body.split(None, 1)
        if len(parts) < 2:
            return None
        key_text, value_text = parts
    key_text = key_text.strip()
    value_text = value_text.strip()
    if not key_text:
        return None
    return key_text, key_text, value_text, comment


def _split_comment(value: str) -> tuple[str, str]:
    quote: str | None = None
    for index, char in enumerate(value):
        if quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip(), value[index:].strip()
    return value.rstrip(), ""


def manual_remediation_findings(findings: list[Finding]) -> list[Finding]:
    """Failing findings that have no structured safe fix."""
    return [
        finding
        for finding in findings
        if finding.is_failing and not (finding.remediation.safe and finding.remediation.fix)
    ]


__all__ = [
    "APPLIED",
    "ERROR",
    "UNCHANGED",
    "WOULD_APPLY",
    "FixOutcome",
    "FixPlanner",
    "RemediationResult",
    "edit_assignment",
    "edit_sshd_config",
    "manual_remediation_findings",
    "validate_fix",
]
