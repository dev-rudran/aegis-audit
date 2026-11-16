"""Security tests for the root-confined filesystem view."""

from __future__ import annotations

import pytest

from aegis.util.fs import (
    FileTooLargeError,
    RootEscapeError,
    RootFS,
    display_path,
    format_mode,
    parse_mode,
)
from tests.helpers import write_file, write_symlink


def test_traversal_outside_the_root_is_refused(fresh_root) -> None:
    fs = RootFS(fresh_root)
    with pytest.raises(RootEscapeError, match="escapes audit root"):
        fs.resolve("../outside")
    with pytest.raises(RootEscapeError, match="escapes audit root"):
        fs.resolve("/etc/../../outside")


def test_absolute_symlinks_are_reinterpreted_inside_the_root(fresh_root) -> None:
    write_file(fresh_root, "/etc/target", "inside the root\n")
    write_symlink(fresh_root, "/etc/link", "/etc/target")
    fs = RootFS(fresh_root)
    assert fs.read_text("/etc/link") == "inside the root\n"
    assert fs.resolve("/etc/link") == fresh_root / "etc/target"


def test_absolute_symlink_cannot_read_host_files(fresh_root) -> None:
    write_symlink(fresh_root, "/etc/host-passwd", "/etc/passwd")
    fs = RootFS(fresh_root)
    assert fs.resolve("/etc/host-passwd") == fresh_root / "etc/passwd"
    assert fs.read_text("/etc/host-passwd") is None


def test_relative_symlinks_resolve_within_the_root(fresh_root) -> None:
    write_file(fresh_root, "/var/data/value", "ok")
    write_symlink(fresh_root, "/var/data/alias", "value")
    fs = RootFS(fresh_root)
    assert fs.read_text("/var/data/alias") == "ok"


def test_symlink_loops_are_bounded(fresh_root) -> None:
    write_symlink(fresh_root, "/a", "b")
    write_symlink(fresh_root, "/b", "a")
    with pytest.raises(RootEscapeError, match="too many symlinks"):
        RootFS(fresh_root).resolve("/a")


def test_read_text_returns_default_for_missing_and_enforces_size(fresh_root) -> None:
    fs = RootFS(fresh_root)
    assert fs.read_text("/absent", default="fallback") == "fallback"
    write_file(fresh_root, "/grow", "0123456789")
    with pytest.raises(FileTooLargeError):
        fs.read_text("/grow", max_bytes=5)


def test_glob_refuses_parent_segments_and_stays_contained(fresh_root) -> None:
    write_file(fresh_root, "/etc/app/one.conf", "x")
    write_file(fresh_root, "/etc/app/two.conf", "y")
    fs = RootFS(fresh_root)
    matches = fs.glob("/etc/app/*.conf")
    assert [item.name for item in matches] == ["one.conf", "two.conf"]
    with pytest.raises(RootEscapeError):
        fs.glob("../*")


def test_display_and_mode_helpers() -> None:
    assert display_path("etc/passwd") == "/etc/passwd"
    assert display_path("/") == "/"
    assert parse_mode("0640") == 0o640
    assert parse_mode("0o600") == 0o600
    assert parse_mode(0o755) == 0o755
    assert format_mode(0o644) == "0644"
    with pytest.raises(ValueError):
        parse_mode("0999")
    with pytest.raises(ValueError):
        parse_mode(0o10000)
    with pytest.raises(ValueError):
        parse_mode("rw-r--r--")


def test_root_must_exist_and_be_a_directory(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        RootFS(tmp_path / "missing")
    file_path = tmp_path / "file"
    file_path.write_text("x")
    with pytest.raises(NotADirectoryError):
        RootFS(file_path)


def test_walk_does_not_follow_directory_symlinks(fresh_root) -> None:
    write_file(fresh_root, "/real/file", "x")
    write_symlink(fresh_root, "/linked", "/real")
    entries = [path for path, _ in RootFS(fresh_root).walk("/")]
    assert "/real/file" in entries
    assert "/linked/file" not in entries


def test_lstat_and_readlink_expose_link_metadata(fresh_root) -> None:
    write_symlink(fresh_root, "/link", "/target")
    fs = RootFS(fresh_root)
    assert fs.is_symlink("/link")
    assert fs.readlink("/link") == "/target"
    assert fs.resolve("/link") == fresh_root / "target"
