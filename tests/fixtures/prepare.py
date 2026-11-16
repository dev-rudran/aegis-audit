#!/usr/bin/env python3
"""Restore fixture permission bits and symlinks after a checkout.

Usage:
    python tests/fixtures/prepare.py
    python tests/fixtures/prepare.py --check

Git stores only the executable bit for regular files, so this script reapplies
the full mode manifest to the committed sample rootfs trees. Tests apply the
same manifest to temporary copies.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.fixturelib import apply_manifest, check_modes  # noqa: E402

FIXTURES = ("rootfs-hardened", "rootfs-vulnerable")


def main(argv: list[str]) -> int:
    check = "--check" in argv
    failures: list[str] = []
    for name in FIXTURES:
        root = REPO_ROOT / "tests" / "fixtures" / name
        if check:
            problems = check_modes(name)
        else:
            problems = apply_manifest(root, name)
        for problem in problems:
            failures.append(f"{name}: {problem}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("fixture modes and symlinks are correct" if check else "fixtures prepared")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
