"""Pytest fixtures and shared setup."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from aegis.engine import load_rules
from aegis.models import Rule
from tests.fixturelib import materialize


@pytest.fixture(scope="session")
def rules() -> list[Rule]:
    return load_rules()


@pytest.fixture(scope="session")
def hardened_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("aegis-hardened") / "root"
    return materialize("rootfs-hardened", destination)


@pytest.fixture(scope="session")
def vulnerable_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    destination = tmp_path_factory.mktemp("aegis-vulnerable") / "root"
    return materialize("rootfs-vulnerable", destination)


@pytest.fixture
def fresh_root(tmp_path: Path) -> Iterator[Path]:
    """An empty audit root for focused check tests."""
    root = tmp_path / "root"
    root.mkdir()
    yield root


@pytest.fixture
def vulnerable_copy(tmp_path: Path) -> Path:
    """A writable copy of the vulnerable fixture, safe for remediation tests."""
    return materialize("rootfs-vulnerable", tmp_path / "root")


@pytest.fixture(scope="session")
def hardened_report(hardened_root: Path):
    from aegis.engine import audit

    return audit(hardened_root)


@pytest.fixture(scope="session")
def vulnerable_report(vulnerable_root: Path):
    from aegis.engine import audit

    return audit(vulnerable_root)
