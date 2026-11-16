"""Small, dependency-free parsers for the configuration formats audited."""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable, Iterator

_TRUE = {"1", "yes", "true", "on", "enabled", "enable", "y", "t"}
_FALSE = {"0", "no", "false", "off", "disabled", "disable", "n", "f"}


def unquote(value: str) -> str:
    """Remove one layer of matching single or double quotes."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_bool(value: str | bool | None) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = unquote(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return None


def parse_int(value: str | int | None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = unquote(value).strip()
    try:
        return int(text, 10)
    except ValueError:
        return None


def split_assignment(line: str) -> tuple[str, str] | None:
    """Split ``key=value`` / ``key value`` / ``key: value`` preserving spaces."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = re.match(r"^([A-Za-z0-9_.\-/]+)\s*(?:=|:|\s)\s*(.*)$", stripped)
    if not match:
        return None
    key = match.group(1)
    value = match.group(2).strip()
    if not value and "=" not in stripped:
        return None
    return key, value


def parse_assignments(
    text: str,
    *,
    key_lower: bool = True,
    last_wins: bool = True,
) -> dict[str, str]:
    """Parse a simple assignment-style configuration file.

    Inline comments are stripped only when preceded by whitespace, so values
    such as ``PermitRootLogin no # comment`` work while passwords containing
    ``#`` remain intact in the common case.
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        item = split_assignment(stripped)
        if item is None:
            continue
        key, value = item
        value = _strip_inline_comment(value)
        if key_lower:
            key = key.lower()
        if last_wins or key not in result:
            result[key] = _normalize_assignment_value(value)
    return result


def parse_assignment_list(
    text: str,
    *,
    key_lower: bool = True,
) -> list[tuple[str, str]]:
    """Parse assignments preserving order and duplicates (first-wins consumers)."""
    items: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        item = split_assignment(stripped)
        if item is None:
            continue
        key, value = item
        if key_lower:
            key = key.lower()
        items.append((key, _normalize_assignment_value(_strip_inline_comment(value))))
    return items


def _normalize_assignment_value(value: str) -> str:
    value = value.strip()
    if value.endswith(";") and not value.endswith('";'):
        value = value[:-1].rstrip()
    return unquote(value)


def _strip_inline_comment(value: str) -> str:
    """Strip `` # comment`` while respecting simple quotes."""
    quote: str | None = None
    for index, char in enumerate(value):
        if quote:
            if char == quote:
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.strip()


def parse_sshd_directives(text: str) -> list[tuple[str, str]]:
    """Return ``(keyword, value)`` pairs in file order.

    Content after the first ``Match`` block is excluded.  ``Include`` is
    returned as a directive so the caller can expand it at the right position.
    """
    items: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("match ") or line.lower() == "match":
            break
        keyword, value = _split_sshd_line(line)
        if keyword:
            items.append((keyword.lower(), value))
    return items


def _split_sshd_line(line: str) -> tuple[str, str]:
    if "=" in line:
        key, _, value = line.partition("=")
        if " " not in key.strip():
            return key.strip(), value.strip()
    parts = line.split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1].strip()


def is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def shell_words(value: str) -> list[str]:
    """Split a shell-like value without executing anything."""
    try:
        return shlex.split(value, comments=False, posix=True)
    except ValueError:
        return value.split()


def first_token(value: str) -> str:
    words = shell_words(value)
    return words[0] if words else ""


def iter_non_comment_lines(text: str, *, comment_prefixes: Iterable[str] = ("#",)) -> Iterator[str]:
    prefixes = tuple(comment_prefixes)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(prefixes):
            continue
        yield stripped


def human_join(items: Iterable[str], *, limit: int = 5) -> str:
    """Join values for a finding message, truncating long lists."""
    values = [str(item) for item in items]
    if not values:
        return "none"
    if len(values) <= limit:
        return ", ".join(values)
    remaining = len(values) - limit
    return f"{', '.join(values[:limit])} (+{remaining} more)"


def normalise_whitespace(value: str) -> str:
    """Collapse runs of whitespace and trim."""
    return " ".join(value.split())
