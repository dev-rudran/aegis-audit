"""Filesystem access constrained to an audit root.

Every check reads through :class:`RootFS`.  Paths supplied by rule packs or
users are normalized and resolved before access.  Symlinks are followed using
chroot semantics: an absolute link target such as ``/lib/systemd/...`` refers to
``<root>/lib/systemd/...`` and can never escape the audit root.  This makes it
safe to audit a mounted image or an extracted container filesystem without
reading the host's own configuration.
"""

from __future__ import annotations

import glob as glob_module
import os
import stat as stat_module
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_READ_BYTES = 4 * 1024 * 1024
MAX_SYMLINK_DEPTH = 40


class RootEscapeError(ValueError):
    """A path resolved outside the configured audit root."""


class FileTooLargeError(ValueError):
    """A file exceeded the configured read limit."""


def display_path(relative: str | os.PathLike[str]) -> str:
    """Return ``relative`` as a rooted POSIX path for reports."""
    value = os.fspath(relative).replace(os.sep, "/")
    value = value.lstrip("/")
    return "/" + value if value else "/"


def parse_mode(value: str | int) -> int:
    """Parse an octal mode such as ``0640`` or ``0o640``."""
    if isinstance(value, int):
        if value < 0 or value > 0o7777:
            raise ValueError(f"mode out of range: {value!r}")
        return value
    if not isinstance(value, str):
        raise ValueError(f"mode must be an octal string, got {type(value).__name__}")
    text = value.strip().lower()
    if text.startswith("0o"):
        text = text[2:]
    if not text or any(ch not in "01234567" for ch in text):
        raise ValueError(f"invalid octal mode: {value!r}")
    mode = int(text, 8)
    if mode > 0o7777:
        raise ValueError(f"mode out of range: {value!r}")
    return mode


def format_mode(mode: int) -> str:
    """Format permission and special bits as four octal digits."""
    return f"{stat_module.S_IMODE(mode):04o}"


@dataclass(frozen=True)
class RootFS:
    """A read-only, chroot-like view of a filesystem rooted at ``root``."""

    root: Path

    def __init__(self, root: str | os.PathLike[str]) -> None:
        candidate = Path(root).expanduser()
        if not candidate.exists():
            raise FileNotFoundError(f"audit root does not exist: {candidate}")
        if not candidate.is_dir():
            raise NotADirectoryError(f"audit root is not a directory: {candidate}")
        object.__setattr__(self, "root", candidate.absolute())

    @property
    def root_str(self) -> str:
        return str(self.root)

    def _resolve(self, relative: str | os.PathLike[str], *, follow_final: bool = True) -> Path:
        """Resolve ``relative`` inside the root with chroot-style symlinks."""
        raw = os.fspath(relative)
        if not isinstance(raw, str):
            raise TypeError("path must be a string")
        if "\x00" in raw:
            raise RootEscapeError("path contains a NUL byte")
        cleaned = raw.replace("\\", "/").lstrip("/")
        pending: deque[str] = deque(part for part in cleaned.split("/") if part not in ("", "."))
        current = self.root
        followed = 0
        while pending:
            part = pending.popleft()
            if part == "..":
                if current == self.root:
                    raise RootEscapeError(f"path escapes audit root: {raw!r}")
                current = current.parent
                continue
            candidate = current / part
            is_last = not pending
            if (not is_last or follow_final) and candidate.is_symlink():
                if followed >= MAX_SYMLINK_DEPTH:
                    raise RootEscapeError(f"too many symlinks while resolving {raw!r}")
                followed += 1
                try:
                    target = os.readlink(candidate)
                except OSError as exc:  # pragma: no cover - racing or permission
                    raise RootEscapeError(f"cannot read symlink {candidate}: {exc}") from exc
                if target.startswith("/"):
                    current = self.root
                target_parts = [
                    item for item in target.replace("\\", "/").split("/") if item not in ("", ".")
                ]
                pending.extendleft(reversed(target_parts))
                continue
            current = candidate
        return current

    def resolve(self, relative: str | os.PathLike[str]) -> Path:
        """Map a root-relative path to a host path, refusing escapes."""
        return self._resolve(relative, follow_final=True)

    def display(self, relative: str | os.PathLike[str]) -> str:
        return display_path(relative)

    def exists(self, relative: str | os.PathLike[str]) -> bool:
        return self.resolve(relative).exists()

    def is_file(self, relative: str | os.PathLike[str]) -> bool:
        return self.resolve(relative).is_file()

    def is_dir(self, relative: str | os.PathLike[str]) -> bool:
        return self.resolve(relative).is_dir()

    def is_symlink(self, relative: str | os.PathLike[str]) -> bool:
        return self._resolve(relative, follow_final=False).is_symlink()

    def readlink(self, relative: str | os.PathLike[str]) -> str:
        return os.readlink(self._resolve(relative, follow_final=False))

    def lstat(self, relative: str | os.PathLike[str]) -> os.stat_result:
        return self._resolve(relative, follow_final=False).lstat()

    def stat(self, relative: str | os.PathLike[str]) -> os.stat_result:
        return self.resolve(relative).stat()

    def read_text(
        self,
        relative: str | os.PathLike[str],
        *,
        max_bytes: int = MAX_READ_BYTES,
        default: str | None = None,
    ) -> str | None:
        """Read a UTF-8-ish text file; return ``default`` when absent."""
        path = self.resolve(relative)
        try:
            if not path.is_file():
                return default
            size = path.stat().st_size
            if size > max_bytes:
                raise FileTooLargeError(
                    f"{display_path(relative)} is {size} bytes; limit is {max_bytes}"
                )
            return path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return default
        except OSError as exc:
            raise OSError(f"cannot read {display_path(relative)}: {exc}") from exc

    def read_text_strict(self, relative: str | os.PathLike[str]) -> str:
        value = self.read_text(relative)
        if value is None:
            raise FileNotFoundError(f"{display_path(relative)} does not exist")
        return value

    def read_bytes(self, relative: str | os.PathLike[str]) -> bytes | None:
        path = self.resolve(relative)
        if not path.is_file():
            return None
        return path.read_bytes()

    def listdir(self, relative: str | os.PathLike[str]) -> list[str]:
        path = self.resolve(relative)
        try:
            return sorted(os.listdir(path))
        except (FileNotFoundError, NotADirectoryError):
            return []

    def glob(self, pattern: str) -> list[Path]:
        """Glob inside the root, resolving symlinked parents safely."""
        cleaned = pattern.replace("\\", "/").lstrip("/")
        parts = [part for part in cleaned.split("/") if part not in ("", ".")]
        if any(part == ".." for part in parts):
            raise RootEscapeError(f"glob escapes audit root: {pattern!r}")
        # Path.glob() skips dangling symlinks on Python 3.10, which silently
        # hides systemd enablement links that legitimately point outside an
        # offline root.  glob.glob() reports them and matches the live-host
        # behaviour we want here.
        matches = glob_module.glob(str(self.root / cleaned), recursive=True)
        results = sorted(Path(match) for match in matches)
        contained: list[Path] = []
        for item in results:
            try:
                relative = item.relative_to(self.root).as_posix()
                safe = self._resolve(relative, follow_final=False)
            except (OSError, ValueError, RootEscapeError):
                continue
            contained.append(safe)
        return contained

    def walk(
        self,
        relative: str = "/",
        *,
        max_depth: int = 8,
        max_entries: int = 50_000,
        exclude_dirs: frozenset[str] = frozenset(),
        followlinks: bool = False,
    ) -> Iterator[tuple[str, os.stat_result]]:
        """Yield ``(root-relative display path, lstat)`` with hard bounds.

        Directory symlinks are not followed by default.  Excluded directory
        names are pruned at any depth.
        """
        start = self.resolve(relative)
        if not start.is_dir():
            return
        base_depth = len(start.parts)
        seen = 0
        for current, dirnames, filenames in os.walk(start, followlinks=followlinks):
            current_path = Path(current)
            depth = len(current_path.parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = sorted(d for d in dirnames if d not in exclude_dirs)
            for name in sorted(filenames):
                full = current_path / name
                seen += 1
                if seen > max_entries:
                    return
                relative_name = full.relative_to(self.root).as_posix()
                try:
                    info = full.lstat()
                except OSError:  # pragma: no cover - races on live systems
                    continue
                yield display_path(relative_name), info

    def file_mode(self, relative: str | os.PathLike[str]) -> int | None:
        try:
            info = self.stat(relative)
        except (FileNotFoundError, RootEscapeError, OSError):
            return None
        return stat_module.S_IMODE(info.st_mode)
