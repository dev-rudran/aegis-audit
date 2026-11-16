"""Fixture materialization helpers.

Git records only the executable bit, so the committed rootfs trees carry a
manifest of the intended permission bits.  Tests and the prepare script apply
that manifest after copying (or checking out) the tree.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFEST_PATH = FIXTURES / "manifest.json"


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def fixture_path(name: str) -> Path:
    path = FIXTURES / name
    if not path.is_dir():
        raise FileNotFoundError(f"unknown fixture: {name}")
    return path


def apply_manifest(root: str | Path, fixture_name: str) -> list[str]:
    """Apply recorded modes and symlinks.  Returns human-readable problems."""
    root = Path(root)
    manifest = load_manifest()[fixture_name]
    problems: list[str] = []
    for relative, mode in manifest["files"].items():
        path = root / relative.lstrip("/")
        if not path.exists():
            problems.append(f"missing file {relative}")
            continue
        try:
            os.chmod(path, int(mode, 8))
        except OSError as exc:
            problems.append(f"chmod {relative}: {exc}")
    for relative, target in manifest["symlinks"].items():
        path = root / relative.lstrip("/")
        if path.is_symlink() and os.readlink(path) == target:
            continue
        try:
            if path.is_symlink() or path.exists():
                path.unlink()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(target)
        except OSError as exc:
            problems.append(f"symlink {relative}: {exc}")
    dirs = sorted(manifest["dirs"].items(), key=lambda item: item[0].count("/"), reverse=True)
    for relative, mode in dirs:
        path = root / relative.lstrip("/")
        if not path.is_dir():
            problems.append(f"missing directory {relative}")
            continue
        try:
            os.chmod(path, int(mode, 8))
        except OSError as exc:
            problems.append(f"chmod {relative}: {exc}")
    return problems


def materialize(fixture_name: str, destination: str | Path) -> Path:
    """Copy a committed fixture and restore its recorded modes."""
    source = fixture_path(fixture_name)
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=True)
    problems = apply_manifest(destination, fixture_name)
    if problems:
        raise RuntimeError(f"fixture {fixture_name} is incomplete: {'; '.join(problems)}")
    return destination


def check_modes(fixture_name: str) -> list[str]:
    source = fixture_path(fixture_name)
    manifest = load_manifest()[fixture_name]
    problems: list[str] = []
    for relative, mode in manifest["files"].items():
        path = source / relative.lstrip("/")
        if not path.exists():
            problems.append(f"missing {relative}")
            continue
        actual = f"{path.stat().st_mode & 0o7777:04o}"
        if actual != mode:
            problems.append(f"{relative}: mode {actual}, expected {mode}")
    for relative, target in manifest["symlinks"].items():
        path = source / relative.lstrip("/")
        if not path.is_symlink() or os.readlink(path) != target:
            problems.append(f"{relative}: symlink missing or wrong")
    return problems
