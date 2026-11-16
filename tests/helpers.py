"""Shared builders for unit tests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aegis.checks.base import CheckContext
from aegis.models import Remediation, Rule, Severity
from aegis.util.fs import RootFS


def write_file(
    root: str | Path,
    path: str,
    text: str = "",
    *,
    mode: int | None = None,
) -> Path:
    """Create a file inside a fixture root, creating parents as needed."""
    target = Path(root) / path.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    if mode is not None:
        target.chmod(mode)
    return target


def write_symlink(root: str | Path, path: str, target: str) -> Path:
    link = Path(root) / path.lstrip("/")
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)
    return link


def context(root: str | Path) -> CheckContext:
    return CheckContext(fs=RootFS(root))


def make_rule(
    check_type: str,
    params: dict[str, Any],
    *,
    severity: str = "medium",
    rule_id: str = "AEGIS-9000",
    fix: dict[str, Any] | None = None,
    safe: bool = False,
) -> Rule:
    return Rule(
        id=rule_id,
        title="Synthetic test rule",
        description="A synthetic rule used to exercise check behaviour.",
        severity=Severity.parse(severity),
        category="Test",
        cis="TEST-1.1",
        check={"type": check_type, "params": params},
        remediation=Remediation(text="Apply the test remediation.", safe=safe, fix=fix),
        tags=("test",),
    )


def fixture_file(root: str | Path, path: str) -> Path:
    return Path(root) / path.lstrip("/")


def current_ids() -> tuple[int, int]:
    return os.getuid(), os.getgid()
